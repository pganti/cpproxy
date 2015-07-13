#ifndef _NST_HTTP_ACCESS_LOG_H_
#define _NST_HTTP_ACCESS_LOG_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_http_request_s;
struct nst_cfg_domain_s;

nst_status_e
nst_http_access_log_compile(struct nst_cfg_domain_s *domain);

void nst_http_request_access_log(struct nst_http_request_s *r);

nst_status_e nst_http_access_log_init(void);

void nst_http_access_log_reset(void);

#endif
