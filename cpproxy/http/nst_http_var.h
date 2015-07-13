#ifndef _NST_HTTP_VAR_LOG_H_
#define _NST_HTTP_VAR_LOG_H_

#include <nst_config.h>

#include <nst_string.h>
#include <nst_types.h>

struct nst_http_request_s;
struct nst_http_var_s;
struct nst_cfg_domain_s;

typedef u_char *(*nst_http_var_write_f) (struct nst_http_request_s *r,
                                         u_char *buf,
                                         size_t buf_size,
                                         const struct nst_http_var_s *var);
typedef size_t (*nst_http_var_getlen_f) (struct nst_http_request_s *r,
                                         const struct nst_http_var_s *var);
typedef void (*nst_http_var_domain_cfg_f) (struct nst_cfg_domain_s *domain);
typedef struct nst_http_var_s nst_http_var_t;

struct nst_http_var_s {
    nst_str_t             name;
    size_t                max_len;
    nst_http_var_getlen_f getlen;
    nst_http_var_write_f  write;
    nst_http_var_domain_cfg_f domain_cfg;
    uintptr_t             data;
};

const nst_http_var_t *nst_http_var_get(const nst_str_t *var_name);

nst_status_e nst_http_var_add(nst_http_var_t *src_vars, size_t n);


#endif
