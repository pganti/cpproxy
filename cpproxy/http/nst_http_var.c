#include "nst_http_var.h"

#include <nst_cpproxy_cfg.h>

#include <nst_array.h>

static nst_array_t nst_http_vars = { NULL, 0, 0, 0, NULL };

const nst_http_var_t *
nst_http_var_get(const nst_str_t *var_name)
{
    size_t i;
    nst_http_var_t *v;

    v = (nst_http_var_t *)nst_http_vars.elts;
    for(i = 0; i < nst_http_vars.nelts; i++) {
        if(var_name->len == v[i].name.len
           && nst_strncmp(var_name->data, v[i].name.data, v[i].name.len) == 0) {
            return &v[i];
        }
    }

    return NULL;
}


nst_status_e
nst_http_var_add(nst_http_var_t *src_vars, size_t n)
{
    size_t i;

    if(nst_http_vars.nalloc == 0) {
        if(nst_array_init(&nst_http_vars, cpproxy_cfg_sticky_pool,
                          128,
                          sizeof(nst_http_var_t)) == NST_ERROR) {
            return NST_ERROR;
        }
    }

    for(i = 0; i < n; i++) {
        nst_http_var_t *v;

        /* ensure there is no collision */
        if(nst_http_var_get(&src_vars[i].name)) {
            nst_assert(0 && "access log variable collision");
        }

        if( !(v = nst_array_push(&nst_http_vars)) )
            return NST_ERROR;

        memcpy(v, &src_vars[i], sizeof(*v));
    }

    return NST_OK;
}
