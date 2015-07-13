
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


nst_list_t *
nst_list_create(nst_pool_t *pool, nst_uint_t n, size_t size)
{
    nst_list_t  *list;

    list = nst_palloc(pool, sizeof(nst_list_t));
    if (list == NULL) {
        return NULL;
    }

    list->part.elts = nst_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NULL;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return list;
}


void *
nst_list_push(nst_list_t *l)
{
    void             *elt;
    nst_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = nst_palloc(l->pool, sizeof(nst_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = nst_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}
