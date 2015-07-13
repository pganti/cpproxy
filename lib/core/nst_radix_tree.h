
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_RADIX_TREE_H_INCLUDED_
#define _NST_RADIX_TREE_H_INCLUDED_


#include <nst_core.h>


#define NST_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct nst_radix_node_s  nst_radix_node_t;

struct nst_radix_node_s {
    nst_radix_node_t  *right;
    nst_radix_node_t  *left;
    nst_radix_node_t  *parent;
    uintptr_t          value;
};


typedef struct {
    nst_radix_node_t  *root;
    nst_pool_t        *pool;
    nst_radix_node_t  *free;
    char              *start;
    size_t             size;
} nst_radix_tree_t;


nst_radix_tree_t *nst_radix_tree_create(nst_pool_t *pool,
    nst_int_t preallocate);
nst_int_t nst_radix32tree_insert(nst_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
nst_int_t nst_radix32tree_delete(nst_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t nst_radix32tree_find(nst_radix_tree_t *tree, uint32_t key);


#endif /* _NST_RADIX_TREE_H_INCLUDED_ */
