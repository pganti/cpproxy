#include "nst_http_req_helpers.h"

#include "nst_http_request.h"
#include "nst_http_upstream.h"

#include <nst_cpproxy_cfg_local_proc.h>
#include <nst_cpproxy_cfg.h>

#include <nst_cfg_domain.h>

#include <nst_connection.h>
#include <nst_event.h>

#include <nst_iobuf.h>
#include <nst_types.h>

static inline void
apply_timeout(nst_http_request_t *r,
              nst_http_upstream_t *u,
              nst_connection_t *downstream, bool any_read,
              nst_connection_t *upstream, bool any_write)
{
    if (nst_handle_write_event(upstream->write, 0) != NST_OK) {
        nst_http_upstream_error(u, errno, 0);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        if(any_write) {
            nst_event_add_timer(upstream->write,
                         nst_cfg_domain_get_write_timeout(r->domain_cfg));
        } else {
            /* we honor the last timeout if we didn't write anything
             * this time.
             */
            nst_event_add_timer_if_not_set(upstream->write,
                         nst_cfg_domain_get_write_timeout(r->domain_cfg));
        }
    } else {
        nst_event_del_timer(upstream->write);
    }

    if (nst_handle_read_event(downstream->read, 0) != NST_OK) {
        nst_http_downstream_error(r, errno, 0);
        return;
    }

    if (downstream->read->active
        && !downstream->read->ready
        && !nst_http_req_filter_is_done(r)) {
        if(any_read) {
            nst_event_add_timer(downstream->read,
                         nst_http_downstream_get_read_timeout(r));
        } else {
            /* we honor the last timeout if we didn't read anything this
             * time
             */
            nst_event_add_timer_if_not_set(downstream->read,
                         nst_http_downstream_get_read_timeout(r));
        }
    } else {
        nst_event_del_timer(downstream->read);
    }

    if(nst_http_request_is_tunnel(r) 
       && (any_read || any_write)) {
        /* It is our best guest for tunneling:
         * We got request flowing...we should cancel the response timeout
         */

        nst_event_del_timer(upstream->read);
    }
}

void
nst_http_req_relay(nst_http_request_t *r, bool is_write_event)
{
    ssize_t                    n;
    nst_iobuf_t               *iobuf = NULL;
    nst_int_t                  rc;
    nst_connection_t          *downstream, *upstream;
    bool                       any_read = FALSE, any_write = FALSE;
    nst_http_upstream_t       *u;
    bool                       got_eof = FALSE;
    bool                       hit_process_limit = FALSE;
    nst_uint_t                 nprocessed_bytes = 0;
    nst_uint_t                 max_nbytes_per_loop;

    u = r->upstream;
    nst_assert(u);
    downstream = r->htran->cli_connection;
    upstream = u->connection;
    max_nbytes_per_loop 
        = ((cpproxy_cfg.my_proc)->event).max_nbytes_per_loop;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s",
                     is_write_event ?
                     nst_connection_get_dbg_str(upstream) :
                     nst_connection_get_dbg_str(downstream));

    for ( ;; ) {

        if(nprocessed_bytes > max_nbytes_per_loop && !got_eof) {
            hit_process_limit = TRUE;
            break;
        }

        if(nst_iochain_get_nbufs(&u->req_iochain_out)
           || 
           (nst_iochain_get_nbufs(&r->req_body_iochain_in)
            && !nst_http_req_filter_is_done(r)
            )
           ) {
            /* flush out the r->req_body_iochain_in to u->req_iochain_out */
            rc = nst_http_req_output_filter(r, &r->req_body_iochain_in);

            if(rc >= 0) {
                any_write = TRUE;
                nprocessed_bytes += rc;

                if(nst_iochain_get_nbufs(&u->req_iochain_out) > 0) {
                    nst_assert(!nst_event_is_ready(upstream->write));
                } else if(nst_http_req_filter_is_error(r)) {
                    nst_http_downstream_error(r, 0, NST_HTTP_ERROR_RESP_FILTER);
                    return;
                } else if(nst_http_req_filter_is_done(r)) {
                    break;
                }
                /* Fall through:
                 *
                 * if everything is flushed to upstram,
                 *   => read from downstream again
                 * else
                 *   => at least have a chance to dectect
                 *      downstream close
                 */
            } else if(rc == NST_AGAIN) {
                /* fall through to have a chance to detect downstream
                 * close.
                 */
            } else {
                /* rc < 0 */

                /* upstream connection write error, request is freed */
                return;
            }

        }

        if(!downstream->read->ready)
            break;

        if(nst_http_req_filter_is_done(r)) {
            nst_assert(nst_iochain_is_empty(&r->req_body_iochain_in));
            nst_iochain_free(&r->recycle_req_body_iochain_in);
            break;
        }

        if(nst_iochain_is_empty(&r->recycle_req_body_iochain_in)) {
            iobuf = nst_iobuf_new(r->pool, NST_HTTP_REQ_READ_BUF_SIZE);
            if(!iobuf) {
                nst_http_downstream_error(r, 0, NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        } else if((iobuf = nst_iochain_remove_first_if_avail(&r->recycle_req_body_iochain_in))){
            /* we have a free buffer allocated before, use it */
        } else {
            /* we still have something pending to be flushed to upstream */
            nst_assert(nst_iochain_get_nbufs(&u->req_iochain_out) > 0);
            break;
        }

        nst_assert(iobuf->start == iobuf->pos);
        nst_assert(iobuf->start == iobuf->last);
        nst_iochain_append(&r->recycle_req_body_iochain_in, iobuf);
        
        n = downstream->io_ops->recv(downstream, iobuf->start,
                                     nst_iobuf_buf_size(iobuf));

        if (n > 0) {
            any_read = TRUE;
            nst_iobuf_add(iobuf, n);
            NST_REFC_GET(iobuf);
            nst_iochain_append(&r->req_body_iochain_in, iobuf);
            /* fall through to flush r->req_body_iochain_in */
        } else if (n == NST_AGAIN) {
            break;
        } else if (n < 0) {
            /* n < 0 && n != NST_AGAIN => other downstream read error */
            /* io_ops.recv have marked the downstream->io_errno */
            nst_http_downstream_error(r, 0, 0);
            return;
        } else {
            /* n == 0 */
            r->downstream_flags.io_eof = 1;
            iobuf = nst_iobuf_create_eof(u->pool);
            nst_iochain_append(&r->req_body_iochain_in, iobuf);
            got_eof = TRUE;
            nst_http_request_finalize(r);
            return;
        }

        /* iterate and then write to upstream */

    } /* for ( ;; ) */

    apply_timeout(r, u,
                  downstream, any_read,
                  upstream, any_write);

    if(hit_process_limit) {
        NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "hit process hit %ud bytes (%s event) "
                         "when relaying request",
                         max_nbytes_per_loop,
                         is_write_event ? "write" : "read");
        if(is_write_event) {
            if(upstream->write->active && upstream->write->ready) {
                nst_event_postpone(upstream->write);
            }
        } else {
            if(downstream->read->active && downstream->read->ready) {
                nst_event_postpone(downstream->read);
            }
        }
    }

    return;
}

ssize_t
nst_http_req_output_filter(nst_http_request_t *r, nst_iochain_t *in)
{
    nst_http_upstream_t *u;
    nst_iobuf_t      *iobuf;
    nst_connection_t *upstream;
    ssize_t           n;

    u = r->upstream;
    upstream = u->connection;
    nst_assert(upstream);

    iobuf = nst_iochain_get_last(in);
    if(iobuf && iobuf->flags.io_eof) {
        r->req_filter_flags.done = 1;
        nst_iochain_remove_last(in);
        nst_iobuf_free(iobuf);
    }

    nst_iochain_concat(&u->req_iochain_out, in);
    if(nst_iochain_get_nbufs(&u->req_iochain_out) == 0) {
        return 0;
    }

    n = upstream->io_ops->send_chain(upstream, &u->req_iochain_out);

    if(n > 0) {
        nst_http_upstream_set_last_byte_sent_at(u);
    } else if(n == 0 || n == NST_AGAIN) {
        /* OK */
    } else {
        /* send_chain should have marked the upstream->io_errno,
         * so we don't have to pass it here
         */
        nst_http_upstream_error(u, 0, NST_HTTP_BAD_GATEWAY);
    }

    return n;
}
