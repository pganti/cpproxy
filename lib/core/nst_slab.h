
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_SLAB_H_INCLUDED_
#define _NST_SLAB_H_INCLUDED_

#include <nst_core.h>

typedef struct nst_slab_page_s  nst_slab_page_t;

struct nst_slab_page_s {
    uintptr_t slab;
    nst_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    nst_atomic_t      lock;

    size_t            min_size;
    size_t            min_shift;

    nst_slab_page_t  *pages;
    nst_slab_page_t   free;

    u_char           *start;
    u_char           *end;

    nst_shmtx_t       mutex;
} nst_slab_pool_t;


void nst_slab_init(nst_slab_pool_t *pool);
void *nst_slab_alloc(nst_slab_pool_t *pool, size_t size);
void *nst_slab_alloc_locked(nst_slab_pool_t *pool, size_t size);
void nst_slab_free(nst_slab_pool_t *pool, void *p);
void nst_slab_free_locked(nst_slab_pool_t *pool, void *p);


#endif /* _NST_SLAB_H_INCLUDED_ */
