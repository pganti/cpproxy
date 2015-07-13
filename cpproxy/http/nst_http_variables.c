#include "nst_http_variables.h"

#include "nst_http_request.h"

#include <nst_cpproxy_cfg.h>

#include <nst_types.h>

#include <stdint.h>

#define DF_VARIABLES_HASH_MAX_SIZE 512
#define DF_VARIABLES_HASH_BUCKET_SIZE nst_cacheline_size

#define NST_HTTP_VAR_DOWNSTREAM_PREFIX "ds_"
#define NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX \
    NST_HTTP_VAR_DOWNSTREAM_PREFIX "req_"

nst_http_variables_t nst_http_variables;

static nst_int_t
nst_http_variable_unknown_downstream_request_header(nst_http_request_t *r,
                                            nst_http_variable_value_t *v,
                                            uintptr_t data);
static nst_int_t
nst_http_variable_downstream_request_host(nst_http_request_t *r,
                                          nst_http_variable_value_t *v,
                                          uintptr_t data);
static nst_int_t
nst_http_variable_downstream_remote_ip(nst_http_request_t *r,
                                       nst_http_variable_value_t *v,
                                       uintptr_t data);
static nst_int_t
nst_http_variable_downstream_remote_port(nst_http_request_t *r,
                                         nst_http_variable_value_t *v,
                                         uintptr_t data);
static nst_int_t
nst_http_variable_downstream_local_ip(nst_http_request_t *r,
                                      nst_http_variable_value_t *v,
                                      uintptr_t data);
static nst_int_t
nst_http_variable_downstream_local_port(nst_http_request_t *r,
                                        nst_http_variable_value_t *v,
                                        uintptr_t data);
static nst_int_t
nst_http_variable_downstream_request_method(nst_http_request_t *r,
                                            nst_http_variable_value_t *v,
                                            uintptr_t data);

/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

/*
 * the $http_host, $http_user_agent, $http_referer, $http_via,
 * and $http_x_forwarded_for variables may be handled by generic
 * nst_http_variable_unknown_header_in(), but for perfomance reasons
 * they are handled using dedicated entries
 */

static nst_http_variable_t nst_http_core_variables[] = {
    /* Host in request header or svc->edomain_name */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "host"), NULL,
      nst_http_variable_downstream_request_host,
      offsetof(nst_http_request_t, parsed_req_hdr.host), 0, 0 },

    /* HTTP request method in downstream request header */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "method"), NULL,
      nst_http_variable_downstream_request_method,
      0, 0, 0 },

    /* remote IP */
    { nst_string("ds_remote_ip"), NULL,
      nst_http_variable_downstream_remote_ip,
      0, 0, 0 },

    /* remote port */
    { nst_string("ds_remote_port"), NULL,
      nst_http_variable_downstream_remote_port,
      0, 0, 0 },

    /* local IP */
    { nst_string("ds_local_ip"), NULL,
      nst_http_variable_downstream_local_ip,
      0, 0, 0 },

    /* local Port */
    { nst_string("ds_local_port"), NULL,
      nst_http_variable_downstream_local_port,
      0, 0, 0 },

    { nst_null_string, NULL, NULL, 0, 0, 0 }
};

nst_http_variable_value_t  nst_http_variable_null_value =
    nst_http_variable("");
nst_http_variable_value_t  nst_http_variable_true_value =
    nst_http_variable("1");


nst_http_variable_t *
nst_http_variables_add(const nst_http_variable_t *src_v)
{
    nst_int_t                   rc;
    nst_uint_t                  i;
    nst_hash_key_t             *key;
    nst_http_variable_t        *hash_v;
    nst_http_variable_t        **index_v;

    key = nst_http_variables.keys->keys.elts;
    for (i = 0; i < nst_http_variables.keys->keys.nelts; i++) {
        if (src_v->name.len != key[i].key.len
            ||
            nst_strncasecmp(src_v->name.data, key[i].key.data,
                            src_v->name.len) != 0) {
            continue;
        }

        hash_v = key[i].value;

        nst_assert((hash_v->flags & NST_HTTP_VAR_CHANGEABLE));

#if 0
        if (!(hash_v->flags & NST_HTTP_VAR_CHANGEABLE)) {
            nst_conf_log_error(NST_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }
#endif

        return hash_v;
    }

    hash_v = nst_palloc(cpproxy_cfg_sticky_pool, sizeof(nst_http_variable_t));
    if (hash_v == NULL) {
        return NULL;
    }

    hash_v->name.len = src_v->name.len;
    hash_v->name.data = nst_pnalloc(cpproxy_cfg_sticky_pool, src_v->name.len);
    if (hash_v->name.data == NULL) {
        return NULL;
    }

    nst_strlow(hash_v->name.data, src_v->name.data, src_v->name.len);

    hash_v->set_handler = src_v->set_handler;
    hash_v->get_handler = src_v->get_handler;
    hash_v->data = src_v->data;
    hash_v->flags = src_v->flags;
    hash_v->index = -1;

    rc = nst_hash_add_key(nst_http_variables.keys, &hash_v->name, hash_v, 0);

    if (rc == NST_ERROR) {
        return NULL;
    }

    nst_assert(rc != NST_BUSY);

#if 0
    if (rc == NST_BUSY) {
        nst_conf_log_error(NST_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }
#endif

    /* indexing the variable...ok it is lamb and stupid
     * but it is adapted from nginx. I don't see we should spend time to
     * optimize it. It is pretty isolated => we can optimize it later without
     * changing the world.
     */

    index_v = nst_array_push(&nst_http_variables.variables);
    if (index_v == NULL) {
        return NULL;
    }

    *index_v = hash_v;
    hash_v->index = nst_http_variables.variables.nelts - 1;

    return hash_v;
}


nst_int_t
nst_http_variables_get_index(const nst_str_t *name)
{
    nst_http_variable_t        *v;

    v = nst_hash_find(&nst_http_variables.hash,
                      nst_hash_key(name->data, name->len),
                      name->data, name->len);

    if(v == NULL) {
        return -1;
    } else {
        nst_assert(v->index > -1);
        return v->index;
    }
}

nst_http_variable_value_t *
nst_http_request_get_variable_by_index(nst_http_request_t *r,
                                       nst_int_t index)
{
    nst_http_variable_t        **v;

    nst_assert(index > -1);
    nst_assert((nst_uint_t) index < nst_http_variables.variables.nelts);

#if 0
    if (nst_http_variables->variables.nelts <= index) {
        nst_log_error(NST_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }
#endif

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = nst_http_variables.variables.elts;

    if (v[index]->get_handler(r, &r->variables[index], v[index]->data)
        == NST_OK)
    {
        if (v[index]->flags & NST_HTTP_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;
        }

        return &r->variables[index];
    }

    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


nst_http_variable_value_t *
nst_http_request_get_variable_and_flush(nst_http_request_t *r,
                                        nst_int_t index)
{
    nst_http_variable_value_t  *v;

    nst_assert(index > -1);
    nst_assert((nst_uint_t) index < nst_http_variables.variables.nelts);

    v = &r->variables[index];

    if (v->valid) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return nst_http_request_get_variable_by_index(r, index);
}

#if 0
nst_http_variable_value_t *
nst_http_request_get_variable(nst_http_request_t *r,
                              nst_int_t index,
                              nst_str_t *name,
                              nst_uint_t key)
{
    nst_http_variable_t        *v;
    nst_http_variable_value_t  *vv;

    if(index > -1) {
        return nst_http_variable_indexed_get(r, index);
    }

    v = nst_hash_find(&nst_http_variables.hash, key, name->data, name->len);

    vv = nst_palloc(r->pool, sizeof(nst_http_variable_value_t));

    if(!vv)
        return NULL;

    if (v->get_handler(r, vv, v->data) == NST_OK) {
        return vv;
    } else {
        return NULL;
    }

    if (vv == NULL) {
        return NULL;
    }

    if (nst_strncmp(name->data,
                    NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX, 
                    sizeof(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX) - 1) == 0) {

        if (nst_http_variable_unknown_header_in(r, vv, (uintptr_t) name)
            == NST_OK)
        {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    NST_LOG_DEBUG(NST_LOG_LEVEL_DEBUG,
                  "r#:%ui unknown \"%V\" variable",
                  r->ui, name);

    return vv;
}
#endif

static nst_int_t
nst_http_variable_unknown_downstream_request_header(nst_http_request_t *r,
                                                   nst_http_variable_value_t *v,
                                                   uintptr_t data)
{
    return nst_http_variable_unknown_header(v, (nst_str_t *) data,
                          &r->parsed_req_hdr.headers.part,
                          sizeof(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX) - 1);
}

nst_int_t
nst_http_variable_unknown_header(nst_http_variable_value_t *v,
                                 nst_str_t *var,
                                 nst_list_part_t *part,
                                 size_t prefix)
{
    u_char            ch;
    nst_uint_t        i, n;
    nst_table_elt_t  *header;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        for (n = 0; n + prefix < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n + prefix == var->len && n == header[i].key.len) {
            v->len = header[i].value.len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = header[i].value.data;

            return NST_OK;
        }
    }

    v->not_found = 1;

    return NST_OK;
}

static nst_int_t
nst_http_variable_downstream_request_host(nst_http_request_t *r,
                                          nst_http_variable_value_t *v,
                                          uintptr_t data)
{
    nst_connection_t *cli_c = r->htran->cli_connection;
    v->valid = 1;
    v->no_cacheable = 0;

    if (r->parsed_req_hdr.server.len) {
        v->len = r->parsed_req_hdr.server.len;
        v->data = r->parsed_req_hdr.server.data;
        v->not_found = 0;
    } else if(cli_c->svc && cli_c->svc->edomain_name_len) {
        v->len = cli_c->svc->edomain_name_len;
        v->data = (const u_char *)cli_c->svc->edomain_name;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    return NST_OK;
}

static nst_int_t
nst_http_variable_downstream_remote_ip(nst_http_request_t *r,
                                       nst_http_variable_value_t *v,
                                       uintptr_t data)
{
    nst_sockaddr_t *peer_sockaddr = &r->htran->cli_connection->peer_sockaddr;

    v->len = nst_sockaddr_get_ip_strlen(peer_sockaddr);
    v->data = (const u_char *)nst_sockaddr_get_ip_str(peer_sockaddr);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NST_OK;
}


static nst_int_t
nst_http_variable_downstream_remote_port(nst_http_request_t *r,
                                         nst_http_variable_value_t *v,
                                         uintptr_t data)
{
    nst_sockaddr_t *peer_sockaddr = &r->htran->cli_connection->peer_sockaddr;

    v->len = nst_sockaddr_get_port_strlen(peer_sockaddr);
    v->data = (const u_char *)nst_sockaddr_get_port_str(peer_sockaddr);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NST_OK;
}


static nst_int_t
nst_http_variable_downstream_local_ip(nst_http_request_t *r,
                                      nst_http_variable_value_t *v,
                                      uintptr_t data)
{
    nst_sockaddr_t *local_sockaddr = &r->htran->cli_connection->local_sockaddr;

    v->len = nst_sockaddr_get_ip_strlen(local_sockaddr);
    v->data = (const u_char *)nst_sockaddr_get_ip_str(local_sockaddr);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NST_OK;
}


static nst_int_t
nst_http_variable_downstream_local_port(nst_http_request_t *r,
                                        nst_http_variable_value_t *v,
                                        uintptr_t data)
{
    nst_sockaddr_t *local_sockaddr = &r->htran->cli_connection->local_sockaddr;

    v->len = nst_sockaddr_get_port_strlen(local_sockaddr);
    v->data = (const u_char *)nst_sockaddr_get_port_str(local_sockaddr);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NST_OK;
}

static nst_int_t
nst_http_variable_downstream_request_method(nst_http_request_t *r,
                                            nst_http_variable_value_t *v,
                                            uintptr_t data)
{
    if (r->req_ln.method_name.data) {
        v->len = r->req_ln.method_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->req_ln.method_name.data;

    } else {
        v->not_found = 1;
    }

    return NST_OK;
}

nst_status_e
nst_http_variables_add_core_vars(void)
{
    nst_http_variable_t        *v;

    nst_http_variables.keys = nst_pcalloc(cpproxy_cfg_sticky_pool,
                                          sizeof(nst_hash_keys_arrays_t));
    if (nst_http_variables.keys == NULL) {
        return NST_ERROR;
    }

    nst_http_variables.keys->pool = cpproxy_cfg_sticky_pool;
    nst_http_variables.keys->temp_pool = cpproxy_cfg_sticky_pool;

    if (nst_hash_keys_array_init(nst_http_variables.keys, NST_HASH_SMALL)
        != NST_OK) {
        return NST_ERROR;
    }

    if (nst_array_init(&nst_http_variables.variables,
                       cpproxy_cfg_sticky_pool,
                       128,
                       sizeof(nst_http_variable_t *))
        != NST_OK) {
        return NST_ERROR;
    }


    for (v = nst_http_core_variables; v->name.len; v++) {
        if(nst_http_variables_add(v) == NULL) {
            return NST_ERROR;
        }
        
    }

    return NST_OK;
}


nst_status_e
nst_http_variables_init(void)
{
    nst_hash_init_t             hash;

    hash.hash = &nst_http_variables.hash;
    hash.key = nst_hash_key;
    hash.max_size = DF_VARIABLES_HASH_MAX_SIZE;
    hash.bucket_size = DF_VARIABLES_HASH_BUCKET_SIZE;
    hash.name = "variables_hash";
    hash.pool = cpproxy_cfg_sticky_pool;
    hash.temp_pool = NULL;

    if (nst_hash_init(&hash, nst_http_variables.keys->keys.elts,
                      nst_http_variables.keys->keys.nelts)
        != NST_OK)
    {
        return NST_ERROR;
    }

    nst_http_variables.keys = NULL;

    return NST_OK;
}

#if 0
void
nst_http_variable_value_rbtree_insert(nst_rbtree_node_t *temp,
                                      nst_rbtree_node_t *node,
                                      nst_rbtree_node_t *sentinel)
{
    nst_rbtree_node_t               **p;
    nst_http_variable_value_node_t   *vvn, *vvt;

    for ( ;; ) {

        vvn = (nst_http_variable_value_node_t *) node;
        vvt = (nst_http_variable_value_node_t *) temp;

        if (node->key != temp->key) {

            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else if (vvn->len != vvt->len) {

            p = (vvn->len < vvt->len) ? &temp->left : &temp->right;

        } else {
            p = (nst_memcmp(vvn->value->data, vvt->value->data, vvn->len) < 0)
                 ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    nst_rbt_red(node);
}

nst_http_variable_value_t *
nst_http_variable_value_lookup(nst_rbtree_t *rbtree,
                               nst_str_t *val,
                               uint32_t hash)
{
    nst_int_t                        rc;
    nst_rbtree_node_t               *node, *sentinel;
    nst_http_variable_value_node_t  *vvn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        vvn = (nst_http_variable_value_node_t *) node;

        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        if (val->len != vvn->len) {
            node = (val->len < vvn->len) ? node->left : node->right;
            continue;
        }

        rc = nst_memcmp(val->data, vvn->value->data, val->len);

        if (rc < 0) {
            node = node->left;
            continue;
        }

        if (rc > 0) {
            node = node->right;
            continue;
        }

        return vvn->value;
    }

    return NULL;
}
#endif
