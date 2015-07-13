/* always include myself first */
#include "nst_http_request.h"

/* local includes */
#include "nst_http_variables.h"
#include "nst_http_access_log.h"
#include "nst_http_upstream.h"
#include "nst_http_transaction.h"
#include "nst_http_parse.h"
#include "nst_http_header.h"
#include "nst_http_defaults.h"

/* cpproxy/cfg/ includes */
#include <nst_cpproxy_cfg_domain.h>
#include <nst_cpproxy_cfg.h>

/* libevent includes */
#include <nst_tp_connection.h>
#include <nst_cfg_svc.h>
#include <nst_event.h>
#include <nst_connection.h>

/* libnst_cfg includes */
#include <nst_cfg_domain.h>

/* libcore includes */
#include <nst_iobuf.h>
#include <nst_string.h>
#include <nst_palloc.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_types.h>

#define NST_HTTP_REQUEST_LOG_COMMENT_BUF_SIZE 16

static nst_uint_t nst_http_next_request_id = 1;

/* process the request after reading the complete header */
static void nst_http_request_process(nst_http_request_t *r);

static nst_status_e nst_http_alloc_large_header_buffer(nst_http_request_t *r,
                                                       bool is_is_request_line);
 

/* It frees the request and thens call nst_http_close_connection().
 * closing cli_connection should free htran automatically also
 
static void nst_http_close_request(nst_http_request_t *r, nst_int_t error);
 */

/* read the request header from cli_connection to iobuf.
 * iobuf must have free space available.
 */
static ssize_t nst_http_read_request_header(nst_http_request_t *r,
                                            nst_iobuf_t *iobuf);

/* read the request line (i.e GET / HTTP/1.1\r\n) 
 * from cli_connection and then parse it
 */
static void nst_http_request_process_line(nst_http_request_t *rev,
                                          bool do_write);


/* read the request header (i.e. the lines following 'GET / HTTP/1.1\r\n')
 * from cli_connection and then parse it
 */
static void nst_http_request_process_headers(nst_http_request_t *r,
                                             bool do_write);

static void
nst_http_request_line_init(nst_http_request_line_t *req_ln)
{
    req_ln->method = NST_HTTP_UNKNOWN;
}


static void
nst_http_downstream_empty_handler(nst_http_request_t *r, bool do_write)
{
    nst_connection_t *cli_c = r->htran->cli_connection;

    NST_DEBUG_LOG_OV(cli_c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui, c#:%ui", r->id, cli_c->number);

    return;
}

void
nst_http_request_init(nst_event_t *rev)
{
    nst_http_transaction_t *htran;
    nst_http_request_t *r;
    nst_connection_t *cli_c;
    nst_iobuf_t *iobuf;

    cli_c = rev->data;
    htran = cli_c->data;
    r = htran->request;

    if(r) {
        /* keepalive connection */
        nst_assert(!r->pool);
        nst_memzero(r, sizeof(nst_http_request_t));
    } else {
        r = htran->request 
            = nst_pcalloc(cli_c->pool, sizeof(nst_http_request_t));
        if(!r) {
            nst_http_downstream_close(cli_c,
                                      NST_IO_CLOSE_REASON_ERROR);
            return;
        }
    }

    r->pool = nst_create_pool(NST_HTTP_REQ_POOL_SIZE, &nst_dl_logger);
    if(!r->pool) {
        nst_http_downstream_close(cli_c, NST_IO_CLOSE_REASON_ERROR);
        return;
    }

    r->id = nst_http_next_request_id++;
    if(!cli_c->tid)
        cli_c->tid = r->id;

    r->htran = htran;
    r->noc_log_lvl = cli_c->noc_log_lvl;
    r->dbg_log_lvl = cli_c->dbg_log_lvl;

    nst_timeval_ms(r->downstream_stats.start);
    r->downstream_stats.start_ms = r->downstream_stats.start.sec * 1000
        + r->downstream_stats.start.msec;

    nst_iochain_init(&r->req_hdr_iochain_in);
    nst_iochain_init(&r->req_body_iochain_in);
    nst_iochain_init(&r->recycle_req_body_iochain_in);
    nst_iochain_init(&r->resp_iochain_out);

    /* init request line */
    nst_http_request_line_init(&r->req_ln);

    /* init req_flags */
    r->req_flags.uri_changes = NST_HTTP_MAX_URI_CHANGES + 1;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "accepted new http r#:%ui %s",
                     r->id,
                     nst_connection_get_dbg_str(cli_c));

    if(nst_http_request_is_tunnel(r)) {
        nst_http_request_process(r);
        return;
    } else {
        r->state = NST_HTTP_REQ_STATE_READING_REQ;
    }

    /* prepare the iochain for reading request header */
    if( (iobuf = htran->small_req_hdr_iobuf) ) {
        nst_assert(nst_iochain_get_nbufs(&htran->recycle_req_hdr_iochain_in)
                   == 0);
        NST_REFC_GET(iobuf);
    } else if(htran->flags.keepalive) {
        /* it is keepalive and the last request is using large req hdr
         * we will keep using large req hdr also
         */
        iobuf = nst_iochain_remove_first(&htran->recycle_req_hdr_iochain_in);
        if(!iobuf) {
            iobuf = nst_iobuf_new(cli_c->pool, NST_HTTP_LARGE_REQ_HDR_BUF_SIZE);
         
            if(!iobuf) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "r#:%ui c#:%ui cannot allocate large "
                            "req read buffer",
                            r->id, cli_c->number);
                nst_http_request_error(r, NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
        nst_iochain_append(&htran->recycle_req_hdr_iochain_in, iobuf);
        NST_REFC_GET(iobuf); /* for appending to r->req_hdr_iochain_in */
    } else {
        /* For the very first request on this connection,
         * try small req hdr first.
         */
        iobuf = htran->small_req_hdr_iobuf
            = nst_iobuf_new(cli_c->pool, NST_HTTP_SMALL_REQ_HDR_BUF_SIZE);
        if(!iobuf) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ui c#:%ui cannot allocate small req read buffer",
                        r->id, cli_c->number);
            nst_http_request_error(r, NST_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        NST_REFC_GET(iobuf);
    }
    
    nst_iochain_append(&r->req_hdr_iochain_in, iobuf);

    r->state = NST_HTTP_REQ_STATE_READING_REQ;
    rev->handler = nst_http_downstream_handler;
    cli_c->write->handler = nst_http_downstream_handler;

    r->read_event_handler = nst_http_request_process_line;
    r->write_event_handler = nst_http_downstream_empty_handler;

    r->read_event_handler(r, FALSE);
}

/* It reads the request line and request header 
 *  the iobuf->pos will be updated accordingly
 */
static ssize_t
nst_http_read_request_header(nst_http_request_t *r, nst_iobuf_t *iobuf)
{
    ssize_t                    n;
    nst_event_t               *rev;
    nst_connection_t          *cli_c;
    nst_http_transaction_t    *htran;

    htran = r->htran;
    cli_c = htran->cli_connection;
    rev = cli_c->read;

    iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);
    nst_assert(iobuf);
    nst_assert(iobuf->last < iobuf->end);
    
    n = iobuf->last - iobuf->pos;
    
    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = cli_c->io_ops->recv(cli_c, iobuf->last,
                                iobuf->end - iobuf->last);
    } else {
        n = NST_AGAIN;
    }

    if (n == NST_AGAIN) {
        if (!nst_timer_is_set(&rev->timer)) {
            nst_event_add_timer(rev, cli_c->svc->post_accept_timeout_ms);
        }

        if (nst_handle_read_event(rev, 0) != NST_OK) {
            nst_http_downstream_error(r, 0,
                                      NST_HTTP_INTERNAL_SERVER_ERROR);
            return NST_ERROR;
        }

        return NST_AGAIN;
    }

    if (n > 0) {
        iobuf->last += n;
        
        return n;
    } else {
        if (n == 0) {
            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s client closed connection prematurely",
                           r->id,
                           nst_connection_get_brief_str(cli_c));
        } else {
            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s error reading client connection. "
                           "%s(%d)",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           nst_strerror(cli_c->io_errno),
                           cli_c->io_errno);
        }

        nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);

        return NST_ERROR;
    }
}

/* process the request line */
static void
nst_http_request_process_line(nst_http_request_t *r, bool do_write)
{
    ssize_t                    n;
    nst_status_e               rc;
    nst_connection_t          *cli_c;
    nst_iobuf_t               *iobuf;

    cli_c = r->htran->cli_connection;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s",
                     r->id,
                     nst_connection_get_brief_str(cli_c));

    rc = NST_AGAIN;

    iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);

    for ( ;; ) {

        /* reqest line is the very first thing we are reading, so 
         * the reading_iobuf must have space
         */
        nst_assert(iobuf->pos < iobuf->end);

        if (rc == NST_AGAIN) {
            n = nst_http_read_request_header(r, iobuf);

            if (n == NST_AGAIN || n == NST_ERROR) {
                return;
            }
        }

        rc = nst_http_parse_request_line(r, iobuf);

        if (rc == NST_OK) {

            r->last_req_ln_iobuf = iobuf;

            /* the request line has been parsed successfully */

            r->req_ln.request_line.len =
                r->req_ln.request_end - r->req_ln.request_start;
            r->req_ln.request_line.data = r->req_ln.request_start;
            *(r->req_ln.request_end) = '\0';


            if (r->req_ln.args_start) {
                r->req_ln.uri.len = r->req_ln.args_start - 1 - r->req_ln.uri_start;
            } else {
                r->req_ln.uri.len = r->req_ln.uri_end - r->req_ln.uri_start;
            }


            if (r->req_flags.complex_uri || r->req_flags.quoted_uri) {

                r->req_ln.uri.data = nst_pnalloc(r->pool, r->req_ln.uri.len + 1);
                if (r->req_ln.uri.data == NULL) {
                    nst_http_downstream_error(r, 0,
                                              NST_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                rc = nst_http_parse_complex_uri(r, TRUE);

                if (rc == NST_HTTP_PARSE_INVALID_REQUEST) {
                    nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
                    return;
                }

            } else {
                r->req_ln.uri.data = r->req_ln.uri_start;
            }


            r->req_ln.unparsed_uri.len = r->req_ln.uri_end - r->req_ln.uri_start;
            r->req_ln.unparsed_uri.data = r->req_ln.uri_start;


            r->req_ln.method_name.len = r->req_ln.method_end - r->req_ln.request_start + 1;
            r->req_ln.method_name.data = r->req_ln.request_line.data;


            if (r->req_ln.http_protocol.data) {
                r->req_ln.http_protocol.len = r->req_ln.request_end - r->req_ln.http_protocol.data;
            }


            if (r->req_ln.uri_ext) {
                if (r->req_ln.args_start) {
                    r->req_ln.exten.len = r->req_ln.args_start - 1 - r->req_ln.uri_ext;
                } else {
                    r->req_ln.exten.len = r->req_ln.uri_end - r->req_ln.uri_ext;
                }

                r->req_ln.exten.data = r->req_ln.uri_ext;
            }


            if (r->req_ln.args_start && r->req_ln.uri_end > r->req_ln.args_start) {
                r->req_ln.args.len = r->req_ln.uri_end - r->req_ln.args_start;
                r->req_ln.args.data = r->req_ln.args_start;
            }


            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s http request line: \"%V\"",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           &r->req_ln.request_line);
            
            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s http uri: \"%V\"",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           &r->req_ln.uri);

            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s http args: \"%V\"",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           &r->req_ln.args);

            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s http exten: \"%V\"",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           &r->req_ln.exten);


            NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "r#:%ui %s finished reading http request line",
                             r->id,
                             nst_connection_get_brief_str(cli_c));

            /* init the parsed_req_hdr here because the following
             * host_start and port_start may use the fields of parsed_req_hdr
             */
            nst_http_req_header_init(&r->parsed_req_hdr, r->pool);

            if (r->req_ln.host_start && r->req_ln.host_end) {
                n = nst_http_validate_host(r->req_ln.host_start,
                                 r->req_ln.host_end - r->req_ln.host_start);

                if (n <= 0) {
                    NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                                "r#:%ui %s invalid host in request line",
                                r->id, 
                                nst_connection_get_brief_str(cli_c));
                    nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
                    return;
                }

                r->parsed_req_hdr.server.len = n;
                r->parsed_req_hdr.server.data = r->req_ln.host_start;
            }
            
            if (r->req_ln.port_start && r->req_ln.port_end) {
                off_t tmp_porth;
                tmp_porth = nst_atoof(r->req_ln.port_start,
                                     r->req_ln.port_end - r->req_ln.port_start);
                if(tmp_porth > 0 && tmp_porth < 65536) {
                    r->parsed_req_hdr.portn = htons((in_port_t)tmp_porth);
                } else {
                    NST_NOC_LOG_OV(r->noc_log_lvl,
                                   NST_LOG_LEVEL_ERROR,
                                   "r#:%ui %s invalid port in request line",
                                   r->id,
                                   nst_connection_get_brief_str(cli_c),
                                   cli_c->number);
                    nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
                    return;
                }
            }

            if (r->req_ln.http_version >= NST_HTTP_VERSION_11) {
                /* if it is HTTP 1.1 assume it is keep-alive unless
                 * overrided by 'Connection:' header
                 */
                r->parsed_req_hdr.connection_type = NST_HTTP_CONNECTION_KEEP_ALIVE;
            } else if (r->req_ln.http_version < NST_HTTP_VERSION_10) {

#if 0 /* TODO */
                if (nst_http_find_virtual_server(r, r->headers_in.server.data,
                                                 r->headers_in.server.len)
                    == NST_ERROR)
                {
                    nst_http_close_request(r, NST_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                nst_http_request_process(r);
#endif
                nst_http_downstream_error(r, 0, NST_HTTP_VERSION_NOT_SUPPORTED);
                return;
            }

            r->read_event_handler = nst_http_request_process_headers;
            r->read_event_handler(r, FALSE);

            return;
        }

        if (rc != NST_AGAIN) {

            /* there was error while a request line parsing */
            NST_NOC_LOG(r->dbg_log_lvl,
                        "r#:%ui %s error when reading request line "
                        "from client connection",
                        r->id, 
                        nst_connection_get_brief_str(cli_c));
            nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
            return;
        }

        /* NST_AGAIN: a request line parsing is still incomplete */
        if (iobuf->pos == iobuf->end) {
            /* the request line longer than reading_iobuf */
            nst_status_e rv;

            rv = nst_http_alloc_large_header_buffer(r, TRUE);

            if (rv == NST_ERROR) {
                nst_http_downstream_error(r, 0,
                                          NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rv == NST_DECLINED) {
                /* the request line is longer than
                 * NST_HTTP_LARGE_REQ_HDR_SIZE
                 */
                r->req_ln.request_line.len = iobuf->end - r->req_ln.request_start;
                r->req_ln.request_line.data = r->req_ln.request_start;

                NST_NOC_LOG_OV(r->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "r#:%ui %s client request line is "
                               "too long",
                               r->id,
                               nst_connection_get_brief_str(cli_c));
                nst_http_downstream_error(r, 0, NST_HTTP_REQUEST_URI_TOO_LARGE);
                return;
            }

            iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);
            nst_assert(iobuf);
        }

    }
}

/* process the request headers (after the request line) */
static void
nst_http_request_process_headers(nst_http_request_t *r, bool do_write)
{
    ssize_t                     n;
    nst_int_t                   rc;

    nst_str_t                   header;
    nst_table_elt_t            *h;
    nst_http_header_handler_t  *hh;

    nst_connection_t           *cli_c;
    nst_iobuf_t                *iobuf;

    cli_c = r->htran->cli_connection;

    NST_DEBUG_LOG(r->dbg_log_lvl,
                  "r#:%ui %s",
                  r->id, nst_connection_get_brief_str(cli_c));

    rc = NST_AGAIN;

    iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);

    for ( ;; ) {

        if (rc == NST_AGAIN) {

            if(iobuf->pos == iobuf->end) {
                nst_status_e rv;
                
                rv = nst_http_alloc_large_header_buffer(r, FALSE);
                
                if (rv == NST_ERROR) {
                    nst_http_request_set_http_error(r,
                                                NST_HTTP_INTERNAL_SERVER_ERROR);
                    nst_http_request_finalize(r);
                    return;
                }

                if (rv == NST_DECLINED) {
                    if(r->hdr_parsing.header_name_start
                       && r->hdr_parsing.header_name_start < iobuf->end
                       && r->hdr_parsing.header_name_end >= iobuf->start) {
                        header.len = iobuf->end 
                            - r->hdr_parsing.header_name_start;
                        header.data = r->hdr_parsing.header_name_start;

                        NST_NOC_LOG_OV(r->noc_log_lvl,
                                       NST_LOG_LEVEL_ERROR,
                                       "r#:%ui %s client sent too long "
                                       "header line: \"%V\"",
                                       r->id,
                                       nst_connection_get_brief_str(cli_c),
                                       &header);
                    } else {
                        NST_NOC_LOG_OV(r->noc_log_lvl,
                                       NST_LOG_LEVEL_ERROR,
                                       "r#:%ui %s client sent too long "
                                       "header",
                                       r->id,
                                       nst_connection_get_brief_str(cli_c));
                    }

                    nst_http_downstream_error(r, 0,
                                            NST_HTTP_REQUEST_ENTITY_TOO_LARGE);
                    return;
                }

                iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);
                nst_assert(iobuf);
            }

            n = nst_http_read_request_header(r, iobuf);

            if (n == NST_AGAIN || n == NST_ERROR) {
                return;
            }
        }

        rc = nst_http_parse_header_line(r, iobuf, FALSE);

        if (rc == NST_OK) {

            /* TODO: temp remark */
            /* we will just forward if it is invalid */
#if 0
            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                header.len = r->header_end - r->header_name_start;
                header.data = r->header_name_start;

                nst_log_error(NST_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%V\"",
                              &header);
                continue;
            }
#endif

            /* a header line has been parsed successfully */

            h = nst_list_push(&r->parsed_req_hdr.headers);
            if (h == NULL) {
                nst_http_request_set_http_error(r,
                                                NST_HTTP_INTERNAL_SERVER_ERROR);
                nst_http_request_finalize(r);
                return;
            }

            h->hash = r->hdr_parsing.header_hash;

            h->key.len = r->hdr_parsing.header_name_end - r->hdr_parsing.header_name_start;
            h->key.data = r->hdr_parsing.header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->hdr_parsing.header_end - r->hdr_parsing.header_start;
            h->value.data = r->hdr_parsing.header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = nst_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                nst_http_request_error(r, NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (h->key.len == r->hdr_parsing.lowcase_index) {
                nst_memcpy(h->lowcase_key, r->hdr_parsing.lowcase_header,
                           h->key.len);

            } else {
                nst_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = nst_hash_find(&nst_http_req_header_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NST_OK) {
                nst_http_request_error(r, NST_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            NST_NOC_LOG_OV(r->noc_log_lvl,
                           NST_LOG_LEVEL_DEBUG,
                           "r#:%ui %s parsed http header: \"%V: %V\"",
                           r->id,
                           nst_connection_get_brief_str(cli_c),
                           &h->key, &h->value);
            continue;
        }

        if (rc == NST_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "r#:%ui %s finished reading http header",
                             r->id,
                             nst_connection_get_brief_str(cli_c));

            r->last_req_hdr_iobuf = iobuf;

            r->request_length += iobuf->pos - iobuf->start;

            r->state = NST_HTTP_REQ_STATE_PROCESS_REQ;

            nst_http_request_process(r);

            return;
        }

        if (rc == NST_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NST_HTTP_PARSE_INVALID_HEADER: "\r" is not followed by "\n" */

        header.len = r->hdr_parsing.header_end - r->hdr_parsing.header_name_start;
        header.data = r->hdr_parsing.header_name_start;
        NST_NOC_LOG_OV(r->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "r#:%ui %s received invalid header line: "
                       "\"%V\\r...\"",
                       r->id, 
                       nst_connection_get_brief_str(cli_c),
                       &header);
        r->http_error = NST_HTTP_BAD_REQUEST;
        nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);

        return;
    } /* for ( ;; ) */
}

/* close the downstream and free the request (if created) */
void
nst_http_downstream_close(nst_connection_t *c,
                          nst_io_close_reason_e reason)
{
    nst_pool_t  *pool;
    nst_http_transaction_t *htran;
    nst_http_request_t *r;

    htran = c->data;
    if(htran)
        r = htran->request;
    else
        r = NULL;


    if(nst_debug_log_level_test_ml(c->dbg_log_lvl, 
                                   NST_LOG_LEVEL_DEBUG)) {
        if(r) {
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "r#:%ui closing %s",
                             r->id,
                             nst_connection_get_brief_str(c));
        } else {
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "closing %s",
                             nst_connection_get_brief_str(c));
        }
    }

     pool = c->pool;
     c->pool = NULL;

     c->io_ops->close(c, reason);

     nst_destroy_pool(pool);
}

static nst_status_e
nst_http_alloc_large_header_buffer(nst_http_request_t *r,
                                   bool is_request_line)
{
    u_char                    *old_ln_start, *new_ln_start;
    nst_iobuf_t               *old_iobuf;
    nst_iobuf_t               *new_iobuf;
    nst_uint_t                 state;
    nst_uint_t                 unfinished_hdr_len;
    nst_http_transaction_t    *htran;
    nst_connection_t          *cli_c;

    htran = r->htran;
    cli_c = htran->cli_connection;
    
    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s",
                     r->id,
                     nst_connection_get_brief_str(cli_c));

    if (is_request_line)
        state = r->req_ln.state;
    else
        state = r->hdr_parsing.state;

    old_iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);
    nst_assert(old_iobuf->pos == old_iobuf->end);

    if (is_request_line && state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->request_length += old_iobuf->end - old_iobuf->start;

        old_iobuf->last = old_iobuf->pos = old_iobuf->start;

        return NST_OK;
    }

    old_ln_start = is_request_line ? r->req_ln.request_start : r->hdr_parsing.header_name_start;

    if (state != 0
        && (size_t) (old_iobuf->pos - old_ln_start)
        >= NST_HTTP_LARGE_REQ_HDR_BUF_SIZE)
    {
        /* even the large buf size cannot accomodate one header/request line */
        return NST_DECLINED;
    }

    if (nst_iochain_get_buf_size(&r->req_hdr_iochain_in)
        >= NST_HTTP_MAX_REQ_HDR_BUF_SIZE) {
        NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "r#:%ui %s request header > %d bytes",
                         r->id,
                         nst_connection_get_brief_str(cli_c),
                         NST_HTTP_MAX_REQ_HDR_BUF_SIZE);
        return NST_DECLINED;
    }

    new_iobuf = nst_iochain_remove_first(&htran->recycle_req_hdr_iochain_in);
    if (new_iobuf) {
        nst_assert(new_iobuf->pos == new_iobuf->last
                   && new_iobuf->last == new_iobuf->start);
        NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "r#:%ui %s reuse large req iobuf %p %uz",
                         r->id,
                         nst_connection_get_brief_str(cli_c),
                         new_iobuf->start, new_iobuf->end - new_iobuf->start);

    } else  {
        /* req in iobuf is always created from cli_c->pool */
        new_iobuf = nst_iobuf_new(cli_c->pool,
                                  NST_HTTP_LARGE_REQ_HDR_BUF_SIZE);

        if (new_iobuf == NULL) {
            return NST_ERROR;
        }

        NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "r#:%ui %s allocated large req iobuf %p %uz",
                         r->id,
                         nst_connection_get_brief_str(cli_c),
                         new_iobuf->start, new_iobuf->end - new_iobuf->last);

    }

    /* r->req_hdr_iochain_in took the ownership of the new_iobuf; */
    nst_iochain_append(&r->req_hdr_iochain_in, new_iobuf);

    if (state == 0) {
        /*
         * state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->request_length += old_iobuf->end - old_iobuf->start;

        return NST_OK;
    }

    unfinished_hdr_len = old_iobuf->pos - old_ln_start;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s copy %d bytes to new large header",
                     r->id,
                     nst_connection_get_brief_str(cli_c),
                     unfinished_hdr_len);


    r->request_length += old_ln_start - old_iobuf->start;

    new_ln_start = new_iobuf->start;

    /*      old_iobuf->pos == old_iobuf->end (MUST) 
     *     there is an assert checking this at the very beginning
     */
    nst_memcpy(new_ln_start, old_ln_start, unfinished_hdr_len);
    new_iobuf->last = new_iobuf->pos = new_ln_start + unfinished_hdr_len;

    if (is_request_line) {
        r->req_ln.request_start = new_ln_start;

        if (r->req_ln.request_end) {
            r->req_ln.request_end =
                new_ln_start + (r->req_ln.request_end - old_ln_start);
        }

        r->req_ln.method_end =
            new_ln_start + (r->req_ln.method_end - old_ln_start);

        r->req_ln.uri_start =
            new_ln_start + (r->req_ln.uri_start - old_ln_start);
        r->req_ln.uri_end =
            new_ln_start + (r->req_ln.uri_end - old_ln_start);

        if (r->req_ln.schema_start) {
            r->req_ln.schema_start =
                new_ln_start + (r->req_ln.schema_start - old_ln_start);
            r->req_ln.schema_end =
                new_ln_start + (r->req_ln.schema_end - old_ln_start);
        }

        if (r->req_ln.host_start) {
            r->req_ln.host_start =
                new_ln_start + (r->req_ln.host_start - old_ln_start);
            if (r->req_ln.host_end) {
                r->req_ln.host_end =
                    new_ln_start + (r->req_ln.host_end - old_ln_start);
            }
        }

        if (r->req_ln.port_start) {
            r->req_ln.port_start =
                new_ln_start + (r->req_ln.port_start - old_ln_start);
            r->req_ln.port_end =
                new_ln_start + (r->req_ln.port_end - old_ln_start);
        }

        if (r->req_ln.uri_ext) {
            r->req_ln.uri_ext =
                new_ln_start + (r->req_ln.uri_ext - old_ln_start);
        }

        if (r->req_ln.args_start) {
            r->req_ln.args_start =
                new_ln_start + (r->req_ln.args_start - old_ln_start);
        }

        if (r->req_ln.http_protocol.data) {
            r->req_ln.http_protocol.data =
                new_ln_start + (r->req_ln.http_protocol.data - old_ln_start);
        }

    } else {
        r->hdr_parsing.header_name_start = new_ln_start;
        r->hdr_parsing.header_name_end =
            new_ln_start + (r->hdr_parsing.header_name_end - old_ln_start);
        r->hdr_parsing.header_start =
            new_ln_start + (r->hdr_parsing.header_start - old_ln_start);
        r->hdr_parsing.header_end =
            new_ln_start + (r->hdr_parsing.header_end - old_ln_start);
    }

    return NST_OK;
}

static nst_status_e
nst_http_find_domain_cfg(nst_http_request_t *r)
{
    nst_connection_t *cli_c;

    cli_c = r->htran->cli_connection;
    if(cli_c->svc && cli_c->svc->edomain_name_len) {
        nst_str_t edomain;

        edomain.data = (u_char *)cli_c->svc->edomain_name;
        edomain.len = cli_c->svc->edomain_name_len;

        r->domain_cfg = nst_cpproxy_cfg_domain_get_by_mstr(&cpproxy_cfg,
                                                           &edomain);
        if(!r->domain_cfg) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ui %s effective domain \"%s\" "
                        "config not found",
                        r->id,
                        nst_connection_get_brief_str(cli_c),
                        edomain.data);
            nst_http_downstream_error(r, 0, NST_HTTP_ERROR_DOMAIN_NOT_FOUND);
            return NST_ERROR;
        }
    } else {
        if(!r->parsed_req_hdr.server.len) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ui %s domain not found in request",
                        r->id,
                        nst_connection_get_brief_str(cli_c));
            nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
            return NST_ERROR;
        }

        r->domain_cfg = nst_cpproxy_cfg_domain_get_by_mstr(&cpproxy_cfg,
                                                   &r->parsed_req_hdr.server);
        if(!r->domain_cfg) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ui %s requested domain \"%V\" config "
                        "not found",
                        r->id,
                        nst_connection_get_brief_str(cli_c),
                        r->parsed_req_hdr.server);
            nst_http_downstream_error(r, 0, NST_HTTP_ERROR_DOMAIN_NOT_FOUND);
            return NST_ERROR;
        }
    }

    nst_cfg_domain_get(r->domain_cfg);

    return NST_OK;
}

static inline nst_status_e
nst_http_request_hdr_body_partition(nst_http_request_t *r)
{
    nst_iobuf_t *last_req_hdr_iobuf;

    last_req_hdr_iobuf = nst_iochain_get_last(&r->req_hdr_iochain_in);
    if(last_req_hdr_iobuf /* tunnel request may not have any req header */
       && last_req_hdr_iobuf->pos < last_req_hdr_iobuf->last) {
        nst_iobuf_t *body_iobuf;

        body_iobuf = nst_iobuf_shadow_clone(last_req_hdr_iobuf);
        if(!body_iobuf) {
            return NST_ERROR;
        } else {
            nst_iochain_append(&r->req_body_iochain_in, body_iobuf);
            return NST_OK;
        }

        /* Warning: if we ever free req_hdr_iochain_in earlier than
         *          we flush out req_body_iochain_in, theorically...we
         *          should free body_iobuf also...but...we will flush out
         *          the r->pool later anyway...
         */
#if 0
        nst_uint_t ncopy = last_req_hdr_iobuf->last - last_req_hdr_iobuf->pos;
        nst_iobuf_t *iobuf
            = nst_iochain_remove_first_if_avail(&r->recycle_req_body_iochain_in);
        nst_assert(iobuf);
        nst_assert(nst_iobuf_buf_size(iobuf) <= ncopy);
        nst_assert(iobuf->pos == iobuf->start);
        memcpy(iobuf->pos, last_req_hdr_iobuf->pos, ncopy);
        nst_iochain_append(&r->recycle_req_body_iochain_in, iobuf);
#endif
    } else {
        return NST_OK;
    }
}

static void
nst_http_request_process(nst_http_request_t *r)
{
    nst_connection_t  *cli_c;

    cli_c = r->htran->cli_connection;

    nst_event_del_timer(cli_c->read);

    if(nst_http_find_domain_cfg(r) != NST_OK)
        return;

    if(nst_http_request_hdr_body_partition(r) != NST_OK)
        return;

    nst_http_upstream_init(r);

#if 0
    c->read->handler = ngx_http_request_handler;
    c->write->handler = ngx_http_request_handler;
    r->read_event_handler = ngx_http_block_reading;

    ngx_http_handler(r);

    ngx_http_run_posted_requests(c);
#endif
}

void
nst_http_downstream_handler(struct nst_event_s *ev)
{
    nst_connection_t       *downstream;
    nst_http_request_t     *r;
    nst_http_transaction_t *htran;

    downstream = ev->data;
    htran = downstream->data;
    r = htran->request;

    NST_DEBUG_LOG_OV(r->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "r#:%ui %s got %s event timedout:%s",
                     r->id, 
                     nst_connection_get_brief_str(downstream),
                     ev->write ? "write" : "read",
                     nst_event_is_timedout(ev) ? "true" : "false");

    if(nst_event_is_timedout(ev)) {
        nst_http_downstream_error(r,
                        ev->write ? NST_ECONN_WTIMEDOUT : NST_ECONN_RTIMEDOUT,
                        NST_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (ev->write) {
        r->write_event_handler(r, TRUE);
    } else {
        r->read_event_handler(r, FALSE);
    }
}

void
nst_http_request_error(nst_http_request_t *r, nst_int_t http_error)
{
    nst_http_request_set_http_error(r, http_error);

    NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                "r#:%ui %s %s has http-error: %ud",
                r->id,
                nst_connection_get_brief_str(r->htran->cli_connection),
                r->upstream && r->upstream->connection ?
                nst_connection_get_brief_str(r->upstream->connection) : "",
                r->http_error);

    nst_http_request_finalizing(r, TRUE);
}

void
nst_http_downstream_error(nst_http_request_t *r,
                          int io_errno,
                          nst_int_t http_error)
{
    NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                  "r#:%ui %s has "
                  "conn-error: %s(%d) http-error: %ud",
                  r->id,
                  nst_connection_get_brief_str(r->htran->cli_connection),
                  io_errno ? nst_strerror(io_errno) : "no-error",
                  io_errno ? io_errno : 0,
                  r->http_error);

    r->downstream_flags.error = 1;

    if(io_errno)
        nst_connection_set_io_errno(r->htran->cli_connection, io_errno);

    if(http_error)
        nst_http_request_set_http_error(r, http_error);

    /* TODO: add access log comment for r->http_error and conn_error
     *       e.g. CE-TO for downstream TIMEOUT
     *            CE-INV for invalid request header
     */
    nst_http_request_add_connection_error_comment(r, r->htran->cli_connection);

    /* TODO: for beta, check if we need to send 4xx or 5xx error reponse to
     *       downstream
     */

    /* We don't need to push pending bytes in r->resp_iochain_out,
     * so call nst_http_request_finalize(r) instread of
     * nst_http_request_finalizing(r).
     */
    nst_http_request_finalize(r);
}

bool
nst_http_downstream_is_readable_again(nst_http_request_t *r)
{
    return !(r->htran->cli_connection->flags.io_eof 
             || r->htran->cli_connection->io_errno);
}

bool
nst_http_downstream_is_writeable_again(nst_http_request_t *r)
{
    return !(r->htran->cli_connection->flags.io_eof  /* alrite... io_eof Here
                                                * is not extremely correct
                                                */
             || r->htran->cli_connection->io_errno);
}

void
nst_http_request_finalizing(nst_http_request_t *r, bool do_write)
{
    ssize_t n;
    nst_uint_t old_data_len;
    nst_connection_t *cli_c;

    /* we only need to flush out resp buffer to downstream.
     * we are taking advantage to the characterists of HTTP protocol.
     */

    cli_c = r->htran->cli_connection;

    old_data_len = nst_iochain_get_data_len(&r->resp_iochain_out);

    if(!nst_http_downstream_is_writeable_again(r))
        nst_http_request_finalize(r);

    /* we still have data to flush to downstream */
    if(old_data_len) {
        n = cli_c->io_ops->send_chain(cli_c, &r->resp_iochain_out);
    } else {
        nst_http_request_finalize(r);
        return;
    }

    if(n == NST_AGAIN) {
        r->write_event_handler = nst_http_request_finalizing;
        /* TODO: it shold be replaced by a broken connection handler. however,
         *       we should consider keepalive connection later
         */
        r->read_event_handler = nst_http_downstream_empty_handler;
        if(cli_c->write->active && !cli_c->write->ready) {
            nst_event_add_timer(cli_c->write,
                                nst_cfg_domain_get_write_timeout(r->domain_cfg));
        }
        nst_handle_write_event(cli_c->write, 0);
    } else if(n < 0 ||(nst_uint_t)n == old_data_len) {
            /* we encounted error
             * or
             * we flushed everything! finalize the request now
             */
        nst_http_request_finalize(r);
    }

    return;
}

void
nst_http_request_finalize(nst_http_request_t *r)
{
    nst_connection_t *downstream = r->htran->cli_connection;
    nst_connection_t *upstream;
    nst_http_upstream_t *u;
    bool downstream_error = FALSE;
    int downstream_io_errno = 0;
    bool upstream_error = FALSE;
    int upstream_io_errno = 0;

    nst_io_close_reason_e close_reason;

    /* TODO: check for keepalive and then carryover the request instead
     *       of closing the downstream.
     */

    if((downstream_error = (r->downstream_flags.error == 1))) {
        if(!(downstream_io_errno = downstream->io_errno)) {
            downstream_io_errno = NST_ERRNO_UNKNOWN;
        }
    }

    if((u = r->upstream)) {
        if((upstream = u->connection)) {
            if(downstream_error) {
                close_reason
                    = nst_tp_errno_to_close_reason(downstream_io_errno, TRUE);
            } else {
                close_reason = NST_IO_CLOSE_REASON_OK;
            }
            nst_http_upstream_close(u, close_reason);
        }

        upstream_error = (u->flags.error == 1);
        if(upstream_error
           &&
           !(upstream_io_errno = u->connection_backup.io_errno)
           ) {
                upstream_io_errno = NST_ERRNO_UNKNOWN;
        }

    }

    nst_http_request_access_log(r);

    if(r->pool) {
        nst_destroy_pool(r->pool);
        r->pool = NULL;
    }

    nst_cfg_domain_free(r->domain_cfg);

    if(downstream_error) {
        close_reason = nst_tp_errno_to_close_reason(downstream_io_errno, FALSE);
    } else if(upstream_error) {
        close_reason = nst_tp_errno_to_close_reason(upstream_io_errno, TRUE);
    } else {
        close_reason = NST_IO_CLOSE_REASON_OK;
    }

    nst_http_downstream_close(r->htran->cli_connection, close_reason);
}

void
nst_http_request_append_comment(nst_http_request_t *r,
                                const char *comment,
                                ssize_t len)
{
    size_t existing_len;

    if(len < 0)
        len = nst_strlen(comment);

    existing_len = nst_strlen(r->log_comment);
    /* +1 for ';' and +1 for '\0' */
    if(existing_len + len + 2 > NST_HTTP_REQ_LOG_COMMENT_BUF_SIZE)
        return;

    if(existing_len)
        r->log_comment[existing_len++] = ';';
    nst_memcpy(r->log_comment + existing_len, comment, len);
    r->log_comment[existing_len+len] = '\0';
}

in_port_t
nst_http_request_get_os_dst_port(const nst_http_request_t *r)
{
    if(nst_http_downstream_is_tcp(r)) {
        return nst_sockaddr_get_port(&r->htran->cli_connection->local_sockaddr);
    } else if(nst_http_downstream_is_mp(r)) {
        if(r->parsed_req_hdr.portn) {
            return r->parsed_req_hdr.portn;
        } else if(nst_http_downstream_is_ssl(r)){
            return htons(NST_HTTPS_DF_PORT);
        } else {
            return htons(NST_HTTP_DF_PORT);
        }
    } else {
        nst_assert(0 && "unhandled downstream type");
    }
}

const nst_sockaddr_t *
nst_http_request_get_end_user_ip(const nst_http_request_t *r)
{
    if(r->parsed_req_hdr.end_user_ip)
        return r->parsed_req_hdr.end_user_ip;
    else
        return &r->htran->cli_connection->peer_sockaddr;
}

nst_str_t
nst_http_request_get_upstream_host_domain(const nst_http_request_t *r)
{
    nst_str_t domain;

    nst_connection_t *cli_c = r->htran->cli_connection;

    if(cli_c->svc && cli_c->svc->edomain_name_len) {
        domain.data = (u_char *)cli_c->svc->edomain_name;
        domain.len = cli_c->svc->edomain_name_len;
    } else {
        if(r->parsed_req_hdr.server.len) {
            domain = r->parsed_req_hdr.server;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ud %s domain not found in request",
                        r->id,
                        nst_connection_get_brief_str(r->htran->cli_connection));
            domain.len = 0;
        }
    }

    return domain;
}

in_port_t
nst_http_request_get_upstream_host_port(const nst_http_request_t *r)
{
    if(nst_http_downstream_is_end_user(r)) {
        return nst_sockaddr_get_port(&r->htran->cli_connection->local_sockaddr);
    } else {
        if(r->parsed_req_hdr.portn) {
            return r->parsed_req_hdr.portn;
        } else {
            return 0;
        }
    }
}

void
nst_http_request_add_connection_error_comment(nst_http_request_t *r,
                                              const nst_connection_t *c)
{
    int c_errno;
    u_char error_str[16];
    u_char *p;
    u_char *last;
    size_t len;

    nst_assert(c == r->htran->cli_connection || (r->upstream && r->upstream->connection && c == r->upstream->connection));

    if( !(c_errno = c->io_errno) )
        return;

    last = error_str + sizeof(error_str);

    if(c->is_upstream)
        p = nst_cpymem(error_str, "US-", static_strlen("US-"));
    else
        p = nst_cpymem(error_str, "DS-", static_strlen("DS-"));

    switch(c_errno) {
    case NST_ECONN_RTIMEDOUT:
        p = nst_cpymem(p, "TOR", static_strlen("TOR"));
        break;
    case NST_ECONN_WTIMEDOUT:
        p = nst_cpymem(p, "TOW", static_strlen("TOW"));
        break;
    case NST_ECONN_PEER_TIMEDOUT:
        p = nst_cpymem(p, "P-TO", static_strlen("P-TO"));
        break;
    case NST_ECONN_PEER_FWD_TIMEDOUT:
        p = nst_cpymem(p, "P-FWD-TO", static_strlen("P-FWD-TO"));
        break;
    case NST_ECONN_PEER_ERROR:
        p = nst_cpymem(p, "P-ERR", static_strlen("P-ERR"));
        break;
    case NST_ECONN_PEER_FWD_ERROR:
        p = nst_cpymem(p, "P-FWD-ERR", static_strlen("P-FWD-ERR"));
        break;
    case NST_ECONN_PEER_RST:
    case ECONNRESET:
    case EPIPE:
        p = nst_cpymem(p, "P-RST", static_strlen("P-RST"));
        break;
    case NST_ECONN_PEER_FWD_RST:
        p = nst_cpymem(p, "P-FWD-RST", static_strlen("P-FWD-RST"));
        break;
    case NST_ECONN_TP:
        p = nst_cpymem(p, "TP-INT", static_strlen("TP-INT"));
        break;
    case ETIMEDOUT:
        p = nst_cpymem(p, "TO", static_strlen("TO"));
        break;
    case ECONNREFUSED:
        p = nst_cpymem(p, "CONN-REF", static_strlen("CONN-REF"));
        break;
    default:
        p = nst_snprintf(p, last - p, "?%Xd", c_errno);
    }

    if(p < last) {
        *p = '\0';
        len = p - error_str;
    } else {
        *(last - 1) = '\0';
        len = sizeof(error_str) - 1;
    }

    nst_http_request_append_comment(r, (char *)error_str, len);
}

nst_msec_t
nst_http_downstream_get_read_timeout(const nst_http_request_t *r)
{
    if(nst_http_request_is_tunnel(r))
        return nst_cfg_domain_get_tunnel_read_timeout(r->domain_cfg);
    else
        return nst_cfg_domain_get_read_timeout(r->domain_cfg);
}

void
nst_http_downstream_check_broken_connection(nst_http_request_t *r,
                                            bool is_write_event)
{
    nst_connection_t *downstream;
    nst_iochain_t *recycle_iochain_in;
    nst_iochain_t *target_iochain_in;
    nst_iobuf_t *iobuf;
    nst_pool_t *pool;
    ssize_t n;

    downstream = r->htran->cli_connection;
    if(!downstream->read->ready)
        return;

    /* Now, we assume it is always for body since we only handle tunneling
     * for now
     *
     * TODO: later for pipeline request after GET. put it into some other
     *       chain (may be the body chain is also fine...)
     */
    recycle_iochain_in = &r->recycle_req_body_iochain_in;
    target_iochain_in = &r->req_body_iochain_in;
    pool = r->pool;

    if(nst_iochain_is_empty(recycle_iochain_in)) {
        iobuf = nst_iobuf_new(pool, NST_HTTP_REQ_READ_BUF_SIZE);
        if(!iobuf) {
            nst_http_downstream_error(r, 0, NST_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    } else if((iobuf =
               nst_iochain_remove_first_if_avail(recycle_iochain_in))) {

    } else {
        /* we have read something from the downstream already */
        return;
    }

    nst_assert(iobuf->start == iobuf->pos);
    nst_assert(iobuf->start == iobuf->last);
    nst_iochain_append(recycle_iochain_in, iobuf);
        
    n = downstream->io_ops->recv(downstream, iobuf->start,
                                 nst_iobuf_buf_size(iobuf));

    if(n == NST_AGAIN) {
        if(!nst_http_request_is_tunnel(r)
           && r->req_ln.method != NST_HTTP_POST
           && r->parsed_req_hdr.content_length_n == 0) {
            nst_iochain_remove_last(recycle_iochain_in);
            nst_iobuf_free(iobuf);
        }
    } else if(n > 0) {
        nst_iobuf_add(iobuf, n);
        NST_REFC_GET(iobuf);
        nst_iochain_append(target_iochain_in, iobuf);
    } else if (n == 0) {
        r->downstream_flags.io_eof = 1;
        nst_http_downstream_error(r, 0, NST_HTTP_CLIENT_CLOSED_REQUEST);
    } else {
        /* n < 0 */

        /* io_ops.recv have marked the downstream->io_errno */
        nst_http_downstream_error(r, 0, 0);
    }
}
