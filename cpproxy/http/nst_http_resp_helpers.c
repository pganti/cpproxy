#include "nst_http_resp_helpers.h"

#include "nst_http_request.h"
#include "nst_http_upstream.h"

#include <nst_cpproxy_cfg_local_proc.h>
#include <nst_cpproxy_cfg.h>

#include <nst_connection.h>
#include <nst_event.h>

#include <nst_cfg_domain.h>

#include <nst_iobuf.h>
#include <nst_types.h>

static inline void
apply_timeout(nst_http_request_t *r,
              nst_http_upstream_t *u,
              nst_connection_t *downstream, bool any_write,
              nst_connection_t *upstream, bool any_read)
{
    if (nst_handle_write_event(downstream->write, 0) != NST_OK) {
        nst_http_downstream_error(r, errno, 0);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        if(any_write) {
            nst_event_add_timer(downstream->write,
                            nst_cfg_domain_get_write_timeout(r->domain_cfg));
        } else {
            /* we honor the last timeout if we didn't write anything
             * this time.
             */
            nst_event_add_timer_if_not_set(downstream->write,
                            nst_cfg_domain_get_write_timeout(r->domain_cfg));
        }
    } else {
        nst_event_del_timer(downstream->write);
    }

    if (nst_handle_read_event(upstream->read, 0) != NST_OK) {
        nst_http_upstream_error(u, errno, 0);
        return;
    }

    if (upstream->read->active
        && !upstream->read->ready
        && !nst_http_resp_filter_is_done(r)) {
        /* we are expecting more data from upstream */
        if(any_read) {
            /* overwrite any old timer */
            nst_event_add_timer(upstream->read,
                                nst_http_upstream_get_read_timeout(u));
        } else {
            /* we honor the last timeout if we didn't read anything this
             * time
             */
            nst_event_add_timer_if_not_set(upstream->read,
                                 nst_http_upstream_get_read_timeout(u));
        }
    } else {
        nst_event_del_timer(upstream->read);
    }

    if(nst_http_request_is_tunnel(r) 
       && (any_read || any_write)) {
        /* It is our best guest for tunneling:
         * We got response flowing...we should cancel the request timeout
         */
        nst_event_del_timer(downstream->read);
    }
}

void
nst_http_resp_relay(nst_http_request_t *r, bool is_write_event)
{
    ssize_t                    n;
    nst_iobuf_t               *iobuf;
    nst_int_t                  rc;
    nst_connection_t          *downstream, *upstream;
    bool                       any_write = FALSE, any_read = FALSE;
    nst_http_upstream_t       *u;
    bool                       got_eof = FALSE;
    bool                       hit_process_limit = FALSE;
    nst_uint_t                 nprocessed_bytes = 0;
    nst_uint_t                 max_nbytes_per_loop;

    u = r->upstream;
    downstream = r->htran->cli_connection;
    upstream = u->connection;
    max_nbytes_per_loop 
        = ((cpproxy_cfg.my_proc)->event).max_nbytes_per_loop;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s",
                     is_write_event ?
                     nst_connection_get_dbg_str(downstream) :
                     nst_connection_get_dbg_str(upstream));
                  

    for ( ;; ) {

        if(nprocessed_bytes > max_nbytes_per_loop && !got_eof) {
            hit_process_limit = TRUE;
            break;
        }

        if(nst_iochain_get_nbufs(&r->resp_iochain_out)
           || 
           (nst_iochain_get_nbufs(&u->resp_body_iochain_in)
            && !nst_http_resp_filter_is_done(r)
            )
           ) {
            /* flush out the u->resp_iochain_in to r->resp_iochain_out */
            rc = nst_http_resp_output_filter(r, &u->resp_body_iochain_in);

            if(rc == NST_AGAIN) {
                break;
            } else if(rc < 0) {
                /* downstream connection error, request is freed */
                return;
            }

            /* rc >= 0 */
            any_write = TRUE;

            /* the u->resp_iochain_in must be flushed out */
            /* it may not be true for broken server which sent
             *       body > Content-Length
             */
            nst_assert(nst_iochain_get_data_len(&u->resp_body_iochain_in) == 0
                       || nst_http_resp_filter_is_done(r));

            if(nst_iochain_get_nbufs(&r->resp_iochain_out) > 0) {
                nst_assert(!nst_event_is_ready(downstream->write));
                break;
            } else if(nst_http_resp_filter_is_error(r)) {
                nst_http_upstream_error(u, 0, NST_HTTP_ERROR_RESP_FILTER);
                return;
            } else if(nst_http_resp_filter_is_done(r)) {
                nst_http_request_finalizing(r, TRUE);
                return;
            }

            /* we have flushed out the resp to downstream and the
             * resp filter is not done
             * => we expect more data from upstream
             * => fall through to read from upstream
             */

            nprocessed_bytes += rc;
        }

        if(!upstream->read->ready)
            break;

        if(nst_iochain_is_empty(&u->recycle_resp_iochain_in)) {
            iobuf = nst_iobuf_new(u->pool, NST_HTTP_RESP_READ_BUF_SIZE);
            if(!iobuf) {
                nst_http_upstream_error(u, 0, NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        } else {
            iobuf = nst_iochain_remove_first_if_avail(&u->recycle_resp_iochain_in);
            /* we must have flushed out the r->resp_iochain_in before
             * reading from upstream again
             */
            nst_assert(iobuf);
        }
        nst_assert(iobuf->start == iobuf->pos);
        nst_assert(iobuf->start == iobuf->last);
        nst_iochain_append(&u->recycle_resp_iochain_in, iobuf);

        n = upstream->io_ops->recv(upstream, iobuf->start,
                                   nst_iobuf_buf_size(iobuf));

        if (n == NST_AGAIN) {
            break;
        } else if (n < 0) {
            nst_http_upstream_error(u, 0, 0);
            return;
        } else if (n > 0) {
            /* u->state->response_length += n; */
            any_read = TRUE;
            nst_iobuf_add(iobuf, n);
            NST_REFC_GET(iobuf);
            nst_iochain_append(&u->resp_body_iochain_in, iobuf);
            nst_http_upstream_set_first_byte_received_at(u);
            nst_http_upstream_set_last_byte_received_at(u);
            /* fall through to flush u->resp_body_iochain_in */
        } else {
            /* n == 0 */
            nst_http_upstream_set_last_byte_received_at(u);
            nst_http_upstream_close(u, NST_IO_CLOSE_REASON_OK);
            u->flags.io_eof = 1;
            iobuf = nst_iobuf_create_eof(u->pool);
            nst_iochain_append(&u->resp_body_iochain_in, iobuf);
            got_eof = TRUE;
            /* fall through to flush the io_eof out */
        }

        /* iterate and then write to downstream */

    } /* for ( ;; ) */

    apply_timeout(r, u,
                  downstream, any_write,
                  upstream, any_read);

    if(hit_process_limit) {
        NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "hit process hit %ud bytes (%s event) "
                         "when relaying response",
                         max_nbytes_per_loop,
                         is_write_event ? "write" : "read");
        if(is_write_event) {
            if(downstream->write->active && downstream->write->ready) {
                nst_event_postpone(downstream->write);
            }
        } else {
            if(upstream->read->active && upstream->read->ready) {
                nst_event_postpone(upstream->read);
            }
        }
    }

    return;
}

ssize_t
nst_http_resp_output_filter(nst_http_request_t *r, nst_iochain_t *in)
{
    nst_iobuf_t      *iobuf;
    nst_connection_t *cli_c;
    ssize_t           n;

    iobuf = nst_iochain_get_last(in);
    if(iobuf && iobuf->flags.io_eof) {
        r->resp_filter_flags.done = 1;
        nst_iochain_remove_last(in);
        nst_iobuf_free(iobuf);
    }

    nst_iochain_concat(&r->resp_iochain_out, in);
    if(nst_iochain_get_nbufs(&r->resp_iochain_out) == 0) {
        return 0;
    }
    cli_c = r->htran->cli_connection;
    nst_assert(cli_c);

    n = cli_c->io_ops->send_chain(cli_c, &r->resp_iochain_out);

    if(n >= 0 || n == NST_AGAIN) {
        return n;
    } else {
        /* send_chain should have marked the cli_connection->io_errno,
         * so we don't have to pass it here
         */
        nst_http_downstream_error(r, 0, 0);
        return n;
    }
}
