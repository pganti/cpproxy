#ifndef _NST_HTTP_REQ_HELPERS_H_
#define _NST_HTTP_REQ_HELPERS_H_

#include <nst_config.h>
#include <nst_types.h>

struct nst_http_request_s;
struct nst_iochain_s;

void nst_http_req_relay(struct nst_http_request_s *r, bool is_write_event);

ssize_t nst_http_req_output_filter(struct nst_http_request_s *r, 
                                   struct nst_iochain_s *in);

#endif
