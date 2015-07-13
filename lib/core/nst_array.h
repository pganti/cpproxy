
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_ARRAY_H_INCLUDED_
#define _NST_ARRAY_H_INCLUDED_


#include <nst_palloc.h>

typedef struct nst_array_s         nst_array_t;

struct nst_array_s {
    void        *elts;
    nst_uint_t   nelts;
    size_t       size;
    nst_uint_t   nalloc;
    nst_pool_t  *pool;
};


nst_array_t *nst_array_create(nst_pool_t *p, nst_uint_t n, size_t size);
void nst_array_destroy(nst_array_t *a);
void *nst_array_push(nst_array_t *a);
void *nst_array_push_n(nst_array_t *a, nst_uint_t n);


static nst_inline nst_int_t
nst_array_init(nst_array_t *array, nst_pool_t *pool, nst_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = nst_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NST_ERROR;
    }

    return NST_OK;
}


#endif /* _NST_ARRAY_H_INCLUDED_ */
