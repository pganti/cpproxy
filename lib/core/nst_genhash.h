#ifndef _NST_GENHASH_H_
#define _NST_GENHASH_H_

#include <nst_config.h>
#include <nst_types.h>

#include <stdint.h>
#include <unistd.h>

#define NST_GENHASH_MODE_NONE               (0)
#define NST_GENHASH_MODE_MULT_VALUES        (1)
#define NST_GENHASH_MODE_NO_SHRINK          (1<<1)
#define NST_GENHASH_MODE_NO_EXPAND          (1<<2)
#define NST_GENHASH_MODE_PROMOTE_TO_TOP     (1<<3)
#define NST_GENHASH_MODE_NO_RESIZE     (NST_GENHASH_MODE_NO_SHRINK | NST_GENHASH_MODE_NO_EXPAND)

typedef uint32_t nst_genhash_key_t;
typedef nst_genhash_key_t (*nst_genhash_f)(const void *);
typedef void * (*nst_genhash_kv_copy_f)(void *);
typedef int (*nst_compare_f)(const void *, const void *);
typedef void (*nst_destructor_f)(void *);

struct nst_allocator_s;

typedef struct nst_genhash_s nst_genhash_t;
typedef struct nst_genhash_iter_s nst_genhash_iter_t;

struct nst_genhash_iter_s {
    void *pos;                  /**< current position */
};

uint32_t hashlittle( const void *key, size_t length, uint32_t initval);
uint32_t hashbig( const void *key, size_t length, uint32_t initval);

nst_genhash_t *nst_genhash_new(uint32_t mode,
                               uint32_t min_size,
                               uint32_t fill_factor_min,
                               uint32_t fill_factor_max,
                               struct nst_allocator_s *allocator,
                               nst_genhash_f hash_fn,
                               nst_compare_f compare_fn,
                               nst_destructor_f free_key,
                               nst_destructor_f free_value,
                               nst_genhash_kv_copy_f key_copy,
                               nst_genhash_kv_copy_f value_copy);

void nst_genhash_free(nst_genhash_t *table);

void nst_genhash_flush(nst_genhash_t *ghash);

nst_status_e nst_genhash_add(nst_genhash_t *ghash, void *key, void *value);

void *nst_genhash_find(nst_genhash_t *table, const void *key);

nst_status_e nst_genhash_del(nst_genhash_t *ghash, const void *key);

uint32_t nst_genhash_get_nelts(const nst_genhash_t *ghash);

void nst_genhash_iter_init(const nst_genhash_t *ghash,
                           nst_genhash_iter_t *iterator);

bool nst_genhash_iter_next(nst_genhash_iter_t *iterator,
                           void **key, void **value);


/* some common hash functions for C Standard types */

/* uint32_t */
uint32_t nst_genhash_uint32(const void *k);
int nst_genhash_uint32_cmp(const void *k1, const void *k2);

/* (void *) */
uint32_t nst_genhash_void(const void *key);
int nst_genhash_void_cmp(const void *k1, const void *k2);

/* C string type */
uint32_t nst_genhash_cstr(const void *key);
int nst_genhash_cstr_cmp(const void *k1, const void *k2);

#endif
