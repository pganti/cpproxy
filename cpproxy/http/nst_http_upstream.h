#ifndef _NST_HTTP_UPSTREAM_H_
#define _NST_HTTP_UPSTREAM_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

/* local includes */
#include "nst_http_cpt_request.h"

/* libevent includes */
#include <nst_connection.h>

/* libcore includes */
#include <nst_array.h>
#include <nst_iobuf.h>
#include <nst_time.h>
#include <nst_string.h>
#include <nst_types.h>

struct nst_http_request_s;
struct nst_cpt_node_s;
struct nst_pool_s;
struct nst_iochain_s;

typedef struct nst_http_upstream_s nst_http_upstream_t;
typedef struct nst_http_upstream_stats_s nst_http_upstream_stats_t;
typedef void (*nst_http_upstream_event_handler_f)(struct nst_http_request_s *r, bool do_write);

/*! A struct to collect upstream statistics.
 *
 */
struct nst_http_upstream_stats_s {
    const struct nst_cpt_node_s   *node;

    unsigned                 connect_failed:1;
    nst_msec_t               connect_result_ms;
    nst_msec_t               last_byte_sent_ms;
    nst_msec_t               first_byte_received_ms;
    nst_msec_t               last_byte_received_ms;
};

/*! The main struct contains the upstream information such as
 *  the upstream statistics and upstream connection object.
 *
 */
struct nst_http_upstream_s {
    nst_http_upstream_event_handler_f     read_event_handler;
    nst_http_upstream_event_handler_f     write_event_handler;

    struct nst_http_request_s      *request;

    nst_http_cpt_request_t          http_cpt_request;

    nst_connection_t               *connection;

    struct nst_pool_s              *pool; /* it should be equal to the output
                                           * pool
                                           */

    nst_iochain_t req_iochain_out; /*!< Final iobuf(s) to be written to 
                                    *   the upstream connection
                                    */

    nst_iochain_t resp_hdr_iochain_in; /*!< The iobuf(s) contain the 
                                        *   un-mangled response header
                                        */

    nst_iochain_t resp_body_iochain_in; /*!< The iobuf(s) contain the
                                         *   un-mangled response body
                                         */

    nst_iochain_t recycle_resp_iochain_in; /*!< The free iobuf(s) used
                                            *   for reading response body.
                                            */


    /* nst_http_upstream_headers_in_t  headers_in;  *//* ML on NGX:
                                                       * response headers
                                                       */

    /* nst_http_upstream_resolved_t   *resolved; */

    size_t                          length; /*!< response body length */

    const struct nst_cpt_node_s    *cpt_node; /*!< current
                                               *   connecting/connected
                                               *   next hop node
                                               */

    nst_array_t                    *stats_array;
    nst_http_upstream_stats_t      *current_stats;

#if 0
    nst_int_t                (*reinit_request)(struct nst_http_request_s *r);
    nst_int_t                (*process_header)(struct nst_http_request_s *r);
    void                     (*abort_request)(struct nst_http_request_s *r);
    void                     (*finalize_request)(struct nst_http_request_s *r,
                                                 nst_int_t rc);
    nst_msec_t                      timeout;

#endif

/*
    nst_str_t                       method;
    nst_str_t                       schema;
    nst_str_t                       uri;
*/

    struct {
        unsigned                        request_sent:1;
        unsigned                        header_sent:1;
        unsigned                        io_eof:1;
        unsigned                        error:1;
    } flags;

    /*! mostly for access log.  the upstream connection
     *  may be closed (and hence lost the information) before
     *  access log is written.
     */
    struct {
        nst_sockaddr_t peer_sockaddr;
        nst_sockaddr_t local_sockaddr;
        int io_errno;
        size_t nsent;
        size_t nread;
        struct tcp_info *tcp_info;
    } connection_backup; 
};

void nst_http_upstream_init(struct nst_http_request_s *r);

ssize_t nst_http_resp_output_filter(struct nst_http_request_s *r,
                                    struct nst_iochain_s *in);

void nst_http_upstream_error(nst_http_upstream_t *u,
                             int io_errno,
                             nst_int_t http_error);

void nst_http_upstream_handler(struct nst_event_s *ev);

void nst_http_setup_relay_handler(struct nst_http_request_s *r,
                                  nst_http_upstream_t *u);

void nst_http_upstream_close(nst_http_upstream_t *u,
                             nst_io_close_reason_e reason);

nst_msec_t
nst_http_upstream_get_read_timeout(const nst_http_upstream_t *u);

static inline void
nst_http_upstream_set_first_byte_received_at(nst_http_upstream_t *u)
{
    nst_assert(u->current_stats);

    if(u->current_stats->first_byte_received_ms == 0)
        u->current_stats->first_byte_received_ms = nst_current_msec;
}

static inline void
nst_http_upstream_set_last_byte_received_at(nst_http_upstream_t *u)
{
    nst_assert(u->current_stats);

    u->current_stats->last_byte_received_ms = nst_current_msec;
}

static inline void
nst_http_upstream_set_last_byte_sent_at(nst_http_upstream_t *u)
{
    nst_assert(u->current_stats);

    u->current_stats->last_byte_sent_ms = nst_current_msec;
}

void
nst_http_upstream_stats_init(nst_http_upstream_stats_t *stats,
                             const struct nst_http_request_s *r,
                             const struct nst_cpt_node_s *node);

#endif
