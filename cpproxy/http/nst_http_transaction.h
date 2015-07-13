#ifndef _NST_HTTP_TRANSACTION_H_
#define _NST_HTTP_TRANSACTION_H_

#include <nst_config.h>

#include <nst_iobuf.h>

struct nst_pool_s;
struct nst_http_request_s;
struct nst_connection_s;

typedef struct nst_http_transaction_s nst_http_transaction_t;

struct nst_http_transaction_s {

    struct nst_connection_s          *cli_connection;

    struct nst_http_request_s        *request;    /* it can be changed
                                                   * to a list in order to
                                                   * support pipeline
                                                   * later.
                                                   */

    nst_iobuf_t                     *small_req_hdr_iobuf;
    nst_iochain_t                    recycle_req_hdr_iochain_in;

#if 0
    /* nst_iochain_t                    resp_out_iochain; */

    /* nst_http_event_handler_pt         read_event_handler; */
    /* nst_http_event_handler_pt         write_event_handler; */

    nst_http_upstream_t              *upstream;   /* serverside connection */
    nst_array_t                      *upstream_states;
                                         /* of nst_http_upstream_state_t */

    nst_iobuf_chain_t                 iochain_cli_out; /* chain of buf to 
                                                        * be written to 
                                                        * clientside connection.
                                                        */

    nst_uint_t                        err_status;

    /* nst_http_cleanup_t               *cleanup; */
#endif

    struct {
        unsigned                          pipeline:1;
        unsigned                          keepalive:1;
    } flags;
};

void nst_http_transaction_init_connection(struct nst_connection_s *cli_c);
void nst_http_transaction_min_mem_usage(nst_http_transaction_t *htran);

#endif
