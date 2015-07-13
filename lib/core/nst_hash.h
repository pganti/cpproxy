#ifndef _NST_HASH_H_
#define _NST_HASH_H_

#include "nst_config.h"

#include "nst_array.h"
#include "nst_string.h"
#include "nst_types.h"

#include <sys/types.h>


typedef struct {
    void             *value;
    u_char            len;
    u_char            name[1];
} nst_hash_elt_t;


typedef struct {
    nst_hash_elt_t  **buckets;
    nst_uint_t        size;
} nst_hash_t;


typedef struct {
    nst_hash_t        hash;
    void             *value;
} nst_hash_wildcard_t;


typedef struct {
    nst_str_t         key;
    nst_uint_t        key_hash;
    void             *value;
} nst_hash_key_t;


typedef nst_uint_t (*nst_hash_key_pt) (const u_char *data, size_t len);


typedef struct {
    nst_hash_t            hash;
    nst_hash_wildcard_t  *wc_head;
    nst_hash_wildcard_t  *wc_tail;
} nst_hash_combined_t;


typedef struct {
    nst_hash_t       *hash;
    nst_hash_key_pt   key;

    nst_uint_t        max_size;
    nst_uint_t        bucket_size;

    char             *name;
    nst_pool_t       *pool;
    nst_pool_t       *temp_pool;
} nst_hash_init_t;


#define NST_HASH_SMALL            1
#define NST_HASH_LARGE            2

#define NST_HASH_LARGE_ASIZE      16384
#define NST_HASH_LARGE_HSIZE      10007

#define NST_HASH_WILDCARD_KEY     1
#define NST_HASH_READONLY_KEY     2


typedef struct {
    nst_uint_t        hsize;

    nst_pool_t       *pool;
    nst_pool_t       *temp_pool;

    nst_array_t       keys;
    nst_array_t      *keys_hash;

    nst_array_t       dns_wc_head;
    nst_array_t      *dns_wc_head_hash;

    nst_array_t       dns_wc_tail;
    nst_array_t      *dns_wc_tail_hash;
} nst_hash_keys_arrays_t;

typedef struct nst_table_elt_s nst_table_elt_t;
struct nst_table_elt_s {
    nst_uint_t        hash;
    nst_str_t         key;
    nst_str_t         value;
    u_char           *lowcase_key;
};


void *nst_hash_find(nst_hash_t *hash, nst_uint_t key, const u_char *name, size_t len);
void *nst_hash_find_wc_head(nst_hash_wildcard_t *hwc, u_char *name, size_t len);
void *nst_hash_find_wc_tail(nst_hash_wildcard_t *hwc, u_char *name, size_t len);
void *nst_hash_find_combined(nst_hash_combined_t *hash, nst_uint_t key,
    u_char *name, size_t len);

nst_int_t nst_hash_init(nst_hash_init_t *hinit, nst_hash_key_t *names,
    nst_uint_t nelts);
nst_int_t nst_hash_wildcard_init(nst_hash_init_t *hinit, nst_hash_key_t *names,
    nst_uint_t nelts);

#define nst_hash(key, c)   ((nst_uint_t) key * 31 + c)
nst_uint_t nst_hash_key(const u_char *data, size_t len);
nst_uint_t nst_hash_key_lc(const u_char *data, size_t len);

nst_int_t nst_hash_keys_array_init(nst_hash_keys_arrays_t *ha, nst_uint_t type);
nst_int_t nst_hash_add_key(nst_hash_keys_arrays_t *ha, nst_str_t *key,
    void *value, nst_uint_t flags);


#endif /* _NST_HASH_H_INCLUDED_ */
