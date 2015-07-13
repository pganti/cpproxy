#ifndef _NST_HTTP_DOWNSTREAM_VARS_H_
#define _NST_HTTP_DOWNSTREAM_VARS_H_

#include <nst_config.h>

#include <nst_types.h>

struct tcp_info;
struct nst_http_var_s;

u_char * nst_http_var_do_tcp_info(const struct tcp_info *info,
                                  u_char *buf,
                                  size_t buf_size,
                                  const struct nst_http_var_s *var);

nst_status_e nst_http_downstream_add_vars(void);

#endif
