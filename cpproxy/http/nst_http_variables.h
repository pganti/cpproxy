#ifndef _NST_HTTP_VARIABLES_H_
#define _NST_HTTP_VARIABLES_H_


#include <nst_config.h>

#include <nst_string.h>
#include <nst_hash.h>
#include <nst_list.h>
#include <nst_types.h>

#include <stdint.h>

struct nst_http_request_s;

#define nst_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

#define NST_HTTP_VAR_CHANGEABLE   1
#define NST_HTTP_VAR_NOCACHEABLE  2
#define NST_HTTP_VAR_INDEXED      4
#define NST_HTTP_VAR_NOHASH       8

typedef struct nst_http_variables_s nst_http_variables_t;

typedef nst_variable_value_t  nst_http_variable_value_t;

typedef struct nst_http_variable_s  nst_http_variable_t;

typedef void (*nst_http_set_variable_pt) (struct nst_http_request_s *r,
                                          nst_http_variable_value_t *v,
                                          uintptr_t data);
typedef nst_int_t (*nst_http_get_variable_pt) (struct nst_http_request_s *r,
                                               nst_http_variable_value_t *v,
                                               uintptr_t data);

struct nst_http_variables_s {
    nst_hash_keys_arrays_t    *keys;
    nst_hash_t                 hash;
    nst_array_t                variables;       /* ngx_http_variable_t */
};

struct nst_http_variable_s {
    nst_str_t                     name;   /* must be first to build the hash */
    nst_http_set_variable_pt      set_handler;
    nst_http_get_variable_pt      get_handler;
    uintptr_t                     data;
    nst_uint_t                    flags;
    nst_int_t                     index;
};

extern nst_http_variables_t nst_http_variables;

static inline size_t
nst_http_variable_get_nstatic_vars(void)
{
    return nst_http_variables.variables.nelts;
}

nst_http_variable_t *nst_http_variables_add(const nst_http_variable_t *src_v);
nst_int_t nst_http_variables_get_index(const nst_str_t *name);
nst_http_variable_value_t *
nst_http_request_get_variable_by_index(struct nst_http_request_s *r,
                                       nst_int_t index);
nst_http_variable_value_t *
nst_http_request_get_variable_and_flush(struct nst_http_request_s *r,
                                        nst_int_t index);

#if 0
nst_http_variable_value_t *
nst_http_request_get_variable(struct nst_http_request_s *r,
                              nst_str_t *name,
                              nst_uint_t key,
                              nst_uint_t nowarn);
#endif

nst_int_t nst_http_variable_unknown_header(nst_http_variable_value_t *v,
                                           nst_str_t *var,
                                           nst_list_part_t *part,
                                           size_t prefix);

#define nst_http_clear_variable(r, index) r->variables[index].text.data = NULL;


nst_status_e nst_http_variables_add_core_vars(void);
nst_status_e nst_http_variables_init(void);


#if 0
typedef struct {
    nst_rbtree_node_t             node;
    size_t                        len;
    nst_http_variable_value_t    *value;
} nst_http_variable_value_node_t;


void nst_http_variable_value_rbtree_insert(nst_rbtree_node_t *temp,
    nst_rbtree_node_t *node, nst_rbtree_node_t *sentinel);
nst_http_variable_value_t *nst_http_variable_value_lookup(nst_rbtree_t *rbtree,
    nst_str_t *name, uint32_t hash);
#endif


extern nst_http_variable_value_t  nst_http_variable_null_value;
extern nst_http_variable_value_t  nst_http_variable_true_value;


#endif /* _NST_HTTP_VARIABLES_H_ */
