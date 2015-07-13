#ifndef _NST_HTTP_RESP_HELPERS_H_
#define _NST_HTTP_RESP_HELPERS_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

/* libcore includes */
#include <nst_types.h>

/* std and sys includes */
#include <sys/types.h>

struct nst_http_request_s;
struct nst_iochain_s;

void nst_http_resp_relay(struct nst_http_request_s *r, bool is_write_helper);

ssize_t nst_http_resp_output_filter(struct nst_http_request_s *r,
                                    struct nst_iochain_s *in);

#endif
