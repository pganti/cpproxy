
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_LIST_H_INCLUDED_
#define _NST_LIST_H_INCLUDED_


#include "nst_config.h"

#include "nst_palloc.h"
#include "nst_types.h"

typedef struct nst_list_part_s  nst_list_part_t;

struct nst_list_part_s {
    void             *elts;
    nst_uint_t        nelts;
    nst_list_part_t  *next;
};


typedef struct {
    nst_list_part_t  *last;
    nst_list_part_t   part;
    size_t            size;
    nst_uint_t        nalloc;
    nst_pool_t       *pool;
} nst_list_t;


nst_list_t *nst_list_create(nst_pool_t *pool, nst_uint_t n, size_t size);

static nst_inline nst_int_t
nst_list_init(nst_list_t *list, nst_pool_t *pool, nst_uint_t n, size_t size)
{
    list->part.elts = nst_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NST_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NST_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *nst_list_push(nst_list_t *list);


#endif /* _NST_LIST_H_INCLUDED_ */
