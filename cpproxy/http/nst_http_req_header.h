#ifndef _NST_HTTP_REQ_HEADER_H_
#define _NST_HTTP_REQ_HEADER_H_

#include <nst_config.h>

#include <nst_list.h>
#include <nst_hash.h>
#include <nst_array.h>
#include <nst_string.h>

struct nst_sockaddr_t;
struct nst_pool_s;
typedef struct nst_http_req_header_s nst_http_req_header_t;

struct nst_http_req_header_s {
    nst_list_t                        headers;

    nst_table_elt_t                  *host;

    nst_table_elt_t                  *connection;

    unsigned                          connection_type:2;

    nst_table_elt_t                  *content_length;
    off_t                             content_length_n;

    nst_table_elt_t                  *content_type;

    nst_table_elt_t                  *transfer_encoding;

    nst_table_elt_t                  *expect;

    nst_table_elt_t                  *user_agent;

    nst_table_elt_t                  *accept_encoding;

    nst_table_elt_t                  *x_forwarded_for;
    struct nst_sockaddr_s            *end_user_ip; /* the real end-user IP */

    /* server and port found in request line or Host header.
     * request line will take the precedence over Host header.
     */
    nst_str_t                         server;
    in_port_t                         portn;     /* port in network order */

    nst_uint_t                        rid;

    struct {
        unsigned                          msie:1;
        unsigned                          msie4:1;
        unsigned                          msie6:1;
        unsigned                          msie7:1;
        unsigned                          opera:1;
        unsigned                          gecko:1;
        unsigned                          konqueror:1;
    } browser_flags;
};

extern nst_hash_t nst_http_req_header_hash;

void nst_http_req_header_init(nst_http_req_header_t *req_hdr,
                              struct nst_pool_s *pool);

nst_status_e nst_http_req_header_hash_init(void);


#endif
