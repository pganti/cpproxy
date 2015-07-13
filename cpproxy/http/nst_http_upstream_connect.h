#ifndef _NST_HTTP_UPSTREAM_CONNECT_H_
#define _NST_HTTP_UPSTREAM_CONNECT_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

/* libcore includes */
#include <nst_types.h>

/* forward declaration */
struct nst_cpt_node_s;
struct nst_http_upstream_s;
struct nst_http_request_s;

nst_status_e nst_http_upstream_connect(const struct nst_cpt_node_s *node,
                                       struct nst_http_upstream_s *upstream);
                                  
#endif
