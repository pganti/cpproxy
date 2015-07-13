/* always include myself first */
#include "nst_http_upstream.h"

/* local includes */
#include "nst_http_header.h"
#include "nst_http_req_helpers.h"
#include "nst_http_resp_helpers.h"
#include "nst_http_request.h"
#include "nst_http_transaction.h"
#include "nst_http_cpt_request.h"
#include "nst_http_cpt_filter.h"
#include "nst_http_cpt_score_ovr.h"
#include "nst_http_upstream_connect.h"
#include "nst_http_defaults.h"

#include <nst_cfg_domain.h>

/* libnst_cpt includes */
#include <nst_cpt_eval.h>
#include <nst_cpt_node.h>

/* libevent includes */
#include <nst_tp_connection.h>
#include <nst_event.h>

/* libnst_cfg includes */
#include <nst_cfg_domain.h>

/* libcore includes */
#include <nst_times.h>
#include <nst_errno.h>

/* std and 3rd party library */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>

static const nst_cpt_node_t * nst_http_upstream_find_nh(nst_http_request_t *r,
                                                        nst_http_upstream_t *u);
static const nst_cpt_node_t *
nst_http_upstream_find_osrv(nst_http_request_t *r, nst_http_upstream_t *u);

static nst_status_e
nst_http_upstream_create_mcon_request(nst_http_upstream_t *u);

static nst_status_e nst_http_upstream_create_request(nst_http_upstream_t *u);

static void nst_http_upstream_test_connect(nst_http_request_t *r,
                                           bool is_write_event);
static nst_status_e nst_http_upstream_after_connect(nst_http_upstream_t *u);

static void nst_http_setup_req_relay_handler(nst_http_request_t *r,
                                            nst_http_upstream_t *u);
static void nst_http_setup_resp_relay_handler(nst_http_request_t *r,
                                              nst_http_upstream_t *u);
static void nst_http_setup_connecting_handler(nst_http_request_t *r,
                                              nst_http_upstream_t *u);


static inline bool
nst_http_upstream_is_mp(const nst_http_upstream_t *u)
{
    nst_assert(u->cpt_node);

    return (u->cpt_node->type == NST_CPT_NODE_TYPE_SPC);
}

static nst_status_e
nst_http_upstream_after_connect(nst_http_upstream_t *u)
{
    nst_http_request_t *r;

    /* now, create the request */
    if(nst_http_upstream_create_request(u) != NST_OK) {
        nst_http_upstream_error(u, 0, NST_HTTP_INTERNAL_SERVER_ERROR);
        return NST_ERROR;
    }

    r = u->request;
    if(nst_http_request_is_tunnel(r)) {
        nst_http_setup_resp_relay_handler(r, u);
        nst_http_setup_req_relay_handler(r, u);
        r->state = NST_HTTP_REQ_STATE_TUNNEL_RELAY;
    } else {
        nst_assert(0 && "TODO: handle non tunnel request");
    }
    u->write_event_handler(r, TRUE);

    return NST_OK;
}

static void
nst_http_upstream_test_connect(nst_http_request_t *r,
                               bool is_write_event)
{
    int err;
    socklen_t len;
    nst_connection_t *upstream;
    nst_http_upstream_t *u;

#if 0
    if(!is_write_event)
        /* we will check it in the write event */
        return;
#endif

    u = r->upstream;
    upstream = u->connection;

    len = sizeof(err);
    if (getsockopt(upstream->fd, SOL_SOCKET, SO_ERROR,
                   (void *) &err, &len) == -1)
        err = errno;

    u->current_stats->connect_result_ms = nst_current_msec;

    if (err) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot connect to %s. %s(%d)",
                    nst_connection_get_brief_str(upstream),
                    nst_strerror(err), err);
        u->current_stats->connect_failed = 1;
        nst_connection_set_io_errno(upstream, err);
        /* TODO: see if we can retry one time */
        nst_http_upstream_error(u, 0, NST_HTTP_BAD_GATEWAY);
        return;
    }

    NST_NOC_LOG_OV(upstream->noc_log_lvl,
                   NST_LOG_LEVEL_DEBUG,
                   "connected to %s",
                   nst_connection_get_brief_str(upstream));
    nst_http_upstream_after_connect(u);
}

void
nst_http_upstream_handler(struct nst_event_s *ev)
{
    nst_connection_t     *upstream;
    nst_http_upstream_t  *u;
    nst_http_request_t   *r;

    upstream = ev->data;
    u = upstream->data;
    r = u->request;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s upstream got %s event timedout:%s",
                     r->id,
                     nst_connection_get_brief_str(upstream),
                     ev->write ? "write" : "read",
                     nst_event_is_timedout(ev) ? "true" : "false");

    if(nst_event_is_timedout(ev)) {
        nst_http_upstream_error(u,
                         ev->write ? NST_ECONN_WTIMEDOUT : NST_ECONN_RTIMEDOUT,
                         NST_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (ev->write) {
        u->write_event_handler(r, TRUE);
    } else {
        u->read_event_handler(r, FALSE);
    }
}

static void
nst_http_setup_resp_relay_handler(nst_http_request_t *r,
                                  nst_http_upstream_t *u)
{
    u->read_event_handler = nst_http_resp_relay;
    r->write_event_handler = nst_http_resp_relay;

}

static void
nst_http_setup_req_relay_handler(nst_http_request_t *r,
                                 nst_http_upstream_t *u)
{
    r->read_event_handler = nst_http_req_relay;
    u->write_event_handler = nst_http_req_relay;
}

static void
nst_http_setup_connecting_handler(nst_http_request_t *r,
                                  nst_http_upstream_t *u)
{
    r->state = NST_HTTP_REQ_STATE_CONNECT_UPSTREAM;
    u->read_event_handler = nst_http_upstream_test_connect;
    u->write_event_handler = nst_http_upstream_test_connect;
}

void
nst_http_upstream_init(nst_http_request_t *r)
{
    nst_connection_t           *downstream;
    nst_http_upstream_t        *u;
    const nst_cpt_node_t       *cpt_node;
    nst_status_e                ret;

    u = nst_pcalloc(r->pool, sizeof(nst_http_upstream_t));
    if (u == NULL) {
        /* cannot call nst_http_upstream_error() because
         * u->request is not initialized.
         */
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui cannot allocate memory for "
                    "nst_http_upstream_t object",
                    r->id);
        nst_http_request_error(r, NST_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->upstream = u;
    u->request = r;
    u->pool = r->pool;

    nst_iochain_init(&u->req_iochain_out);
    nst_iochain_init(&u->resp_hdr_iochain_in);
    nst_iochain_init(&u->resp_body_iochain_in);
    nst_iochain_init(&u->recycle_resp_iochain_in);

    cpt_node = nst_http_upstream_find_nh(r, u);
    if(!cpt_node) {
        /* force trying osrv */
        cpt_node = nst_http_upstream_find_osrv(r, u);
        if(!cpt_node) {
            nst_http_upstream_error(u, 0, NST_HTTP_ERROR_NH_NOT_FOUND);
            return;
        }
    }

    u->cpt_node = cpt_node;
    ret = nst_http_upstream_connect(cpt_node, u);
    
    if(ret == NST_ERROR) {
        if(errno == ENOSPC) {
            nst_http_upstream_error(u, errno, NST_HTTP_INTERNAL_SERVER_ERROR);
        } else {
            /* TODO: see if we can retry another cpt_node */
            nst_http_upstream_error(u, errno, NST_HTTP_BAD_GATEWAY);
        }
        return;
    }

    downstream = r->htran->cli_connection;
    downstream->read->handler
        = downstream->write->handler
        = nst_http_downstream_handler;
    r->read_event_handler = nst_http_downstream_check_broken_connection;
    r->write_event_handler = nst_http_downstream_check_broken_connection;

    if(u->connection->write->ready) {
        /* wow, it is connected immediately */
        nst_http_upstream_after_connect(u);
    } else {
        nst_http_setup_connecting_handler(r, u);
        nst_event_add_timer(u->connection->write,
                  nst_cfg_domain_get_upstream_connect_timeout(r->domain_cfg));
    }

    return;
}

/*! Find the next hop by evaluating the next hop tree in r->domain_cfg.
 *
 *  r will never be destroyed, so the calling function should handle erro
 *  case properly (e.g. by calling nst_http_upstream_error()).
 */
static const nst_cpt_node_t *
nst_http_upstream_find_nh(nst_http_request_t *r, nst_http_upstream_t *u)
{
    nst_cpt_request_t *cpt_request;

    /* domain_cfg must be found by now */
    nst_assert(r->domain_cfg);

    cpt_request = (nst_cpt_request_t *)&u->http_cpt_request;
    if(cpt_request->type == NST_CPT_REQ_TYPE_UNKNOWN) {
        /* init u->http_cpt_request */
        nst_http_cpt_request_init(&u->http_cpt_request, r);
    }

    return nst_cpt_find_nh(r->domain_cfg->cpt, cpt_request);
}

static const nst_cpt_node_t *
nst_http_upstream_find_osrv(nst_http_request_t *r, nst_http_upstream_t *u)
{
    nst_cpt_request_t *cpt_request;

    cpt_request = (nst_cpt_request_t *)&u->http_cpt_request;
    nst_assert(cpt_request->type != NST_CPT_REQ_TYPE_UNKNOWN);
    nst_assert(cpt_request->score_ovr == NULL);

    if(cpt_request->ntried > 0 
       && cpt_request->last_tried_nodes[cpt_request->ntried - 1]->type == NST_CPT_NODE_TYPE_OSRV) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "r#:%ui has already tried osrv. we will not force "
                      "trying osrv",
                      r->id);
        return NULL;
    }

    cpt_request->score_ovr = nst_http_cpt_score_ovr;

    return nst_cpt_find_nh(r->domain_cfg->cpt, cpt_request);
}
void
nst_http_upstream_close(nst_http_upstream_t *u,
                        nst_io_close_reason_e reason)
{
    nst_connection_t *upstream;
    nst_http_request_t *r = u->request;

    upstream = u->connection;
    if(!upstream)
        /* already closed or not yet connected */
        return;

    memcpy(&u->connection_backup.local_sockaddr,
           &upstream->local_sockaddr,
           sizeof(upstream->local_sockaddr));
    memcpy(&u->connection_backup.peer_sockaddr,
           &upstream->peer_sockaddr,
           sizeof(upstream->peer_sockaddr));
    u->connection_backup.io_errno = upstream->io_errno;
    u->connection_backup.nsent = upstream->nsent;
    u->connection_backup.nread = upstream->nread;
    if(r->domain_cfg->var_flags.upstream_tcp_info == 1) {
        socklen_t optlen = sizeof(struct tcp_info);
        
        if(!u->current_stats || u->current_stats->connect_failed == 1) {
            u->connection_backup.tcp_info = NULL;
        } else if(!u->connection_backup.tcp_info) {
            u->connection_backup.tcp_info
                = nst_pcalloc(u->pool, sizeof(struct tcp_info));
        }

        if(u->connection_backup.tcp_info
           &&
           getsockopt(upstream->fd, IPPROTO_TCP, TCP_INFO,
                      u->connection_backup.tcp_info, &optlen) == -1) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot get TCO_INFO for %s. %s(%d)",
                        nst_connection_get_brief_str(upstream),
                        nst_strerror(errno), errno);
            u->connection_backup.tcp_info = NULL;
        }
    }
            
    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s",
                     r->id, nst_connection_get_brief_str(upstream));

    u->flags.io_eof = upstream->flags.io_eof;
    upstream->pool = NULL;
    upstream->io_ops->close(upstream, reason);

    u->connection = NULL;
}

void
nst_http_upstream_error(nst_http_upstream_t *u,
                        int io_errno,
                        nst_int_t http_error)
{
    nst_http_request_t *r;
    nst_connection_t *upstream;
    nst_io_close_reason_e close_reason = NST_IO_CLOSE_REASON_OK;

    u->flags.error = 1;

    upstream = u->connection;
    r = u->request;

    /* upstream can be NULL if we ever successfully made a
     * upstream connection
     */
    if(upstream) {
        nst_connection_set_io_errno(upstream, io_errno);
        io_errno = upstream->io_errno;
        nst_http_request_add_connection_error_comment(r, upstream);
    }

    if(http_error) {
        nst_http_request_set_http_error(r, http_error);
    }
    http_error = r->http_error;

    NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                  "r#:%ui %s has conn-error: %s(%d) http-error: %d",
                  r->id,
                  upstream ? nst_connection_get_brief_str(upstream) : "",
                  io_errno ? nst_strerror(io_errno) : "no-error",
                  io_errno,
                  http_error);

    if(!io_errno) {
        io_errno = NST_ERRNO_UNKNOWN;
    }
    close_reason = nst_tp_errno_to_close_reason(io_errno, FALSE);
    nst_http_upstream_close(u, close_reason);

    nst_http_request_finalizing(u->request, TRUE);
}

nst_msec_t
nst_http_upstream_get_read_timeout(const nst_http_upstream_t *u)
{
    const nst_http_request_t *r = u->request;

    if(nst_http_request_is_tunnel(r))
        return nst_cfg_domain_get_tunnel_read_timeout(r->domain_cfg);
    else
        return nst_cfg_domain_get_read_timeout(r->domain_cfg);
}

void
nst_http_upstream_stats_init(nst_http_upstream_stats_t *stats,
                             const nst_http_request_t *r,
                             const struct nst_cpt_node_s *node)
{
    nst_memzero(stats, sizeof(*stats));
    stats->node = node;
}

    

static nst_status_e
nst_http_upstream_create_mcon_request(nst_http_upstream_t *u)
{
    size_t len;
    nst_iobuf_t *iobuf;
    const char *end_user_ip_str;
    const nst_sockaddr_t *end_user_ip;
    nst_http_request_t *r;
    nst_str_t domain;
    in_port_t portn;

    r = u->request;
    end_user_ip = nst_http_request_get_end_user_ip(r);
    end_user_ip_str = nst_sockaddr_get_ip_str(end_user_ip);
    if(!end_user_ip_str || !end_user_ip_str[0]) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui error setting \"%s:\" request header",
                    r->id,
                    NST_HTTP_HDR_X_NST_REAL_IP);
        return NST_ERROR;
    }

    domain = nst_http_request_get_upstream_host_domain(r);
    if(domain.len == 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui error setting \"%s:\" request header",
                    r->id,
                    NST_HTTP_HDR_HOST);
        return NST_ERROR;
    }
    portn = nst_http_request_get_upstream_host_port(r);

    len  = static_strlen("CONNEC / HTTP/1.1" CRLF);
    len += static_strlen("Connectoin: close" CRLF);
    len += static_hdr_name_strlen(NST_HTTP_HDR_HOST)
           + domain.len
           + 1 + NST_MAX_PORT_STR_BUF_SIZE /* :port */
           +  CRLF_LEN;

    len += static_hdr_name_strlen(NST_HTTP_HDR_X_NST_REAL_IP)
           + NST_MAX_IP_STR_BUF_SIZE - 1
           + CRLF_LEN;
    len += static_hdr_name_strlen(NST_HTTP_HDR_X_NST_RID)
           + NST_INT64_LEN
           + CRLF_LEN;

    len += CRLF_LEN;
    len += 1; /* for '\0' */

    iobuf = nst_iobuf_new_temp(u->pool, len);
    if(!iobuf) {
        return NST_ERROR;
    }

    iobuf->last = nst_copy(iobuf->last, "CONNEC / HTTP/1.1" CRLF,
                           sizeof("CONNEC / HTTP/1.1" CRLF) - 1);
    iobuf->last = nst_copy(iobuf->last, "Connection: close" CRLF,
                           sizeof("Connection: close" CRLF) - 1);
    if(portn) {
        iobuf->last = nst_sprintf(iobuf->last,
                                  "%s: %V:%ud" CRLF,
                                  NST_HTTP_HDR_HOST,
                                  &domain, htons(portn));
    } else {
        iobuf->last = nst_sprintf(iobuf->last,
                                  "%s: %V" CRLF,
                                  NST_HTTP_HDR_HOST,
                                  &domain);
    }
    iobuf->last = nst_sprintf(iobuf->last,
                              "%s: %s" CRLF,
                              NST_HTTP_HDR_X_NST_REAL_IP,
                              end_user_ip_str);
    iobuf->last = nst_sprintf(iobuf->last,
                              "%s: %ui" CRLF,
                              NST_HTTP_HDR_X_NST_RID,
                              r->id);
    iobuf->last = nst_copy(iobuf->last, CRLF, CRLF_LEN);
    *(iobuf->last) = '\0'; /* never increment the last here
                            * since we are not sending the '\0'.
                            * it is mainly for debug logging.
                            */

    nst_iochain_append(&u->req_iochain_out, iobuf);

    return NST_OK;
}

static nst_status_e
nst_http_upstream_create_request(nst_http_upstream_t *u)
{
    nst_http_request_t *r = u->request;

    nst_assert(u->cpt_node);
    if(nst_http_request_is_tunnel(r)) {
        if(nst_http_upstream_is_mp(u)) {
            if(nst_http_upstream_create_mcon_request(u) == NST_ERROR){
                return NST_ERROR;
            }
        }
   } else {
     nst_assert(0 && "To Come Soon: create request header for non-tunnel request");
    }
    return NST_OK;
}
