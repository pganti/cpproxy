
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_RBTREE_H_INCLUDED_
#define _NST_RBTREE_H_INCLUDED_

#include <nst_config.h>
#include <nst_types.h>


typedef nst_uint_t  nst_rbtree_key_t;
typedef nst_int_t   nst_rbtree_key_int_t;


typedef struct nst_rbtree_node_s  nst_rbtree_node_t;

struct nst_rbtree_node_s {
    nst_rbtree_key_t       key;
    nst_rbtree_node_t     *left;
    nst_rbtree_node_t     *right;
    nst_rbtree_node_t     *parent;
    u_char                 color;
    u_char                 data;
};


typedef struct nst_rbtree_s  nst_rbtree_t;

typedef void (*nst_rbtree_insert_pt) (nst_rbtree_node_t *root,
    nst_rbtree_node_t *node, nst_rbtree_node_t *sentinel);

struct nst_rbtree_s {
    nst_rbtree_node_t     *root;
    nst_rbtree_node_t     *sentinel;
    nst_rbtree_insert_pt   insert;
};


#define nst_rbtree_init(tree, s, i)                                           \
    nst_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void nst_rbtree_insert(volatile nst_rbtree_t *tree,
    nst_rbtree_node_t *node);
void nst_rbtree_delete(volatile nst_rbtree_t *tree,
    nst_rbtree_node_t *node);
void nst_rbtree_insert_value(nst_rbtree_node_t *root, nst_rbtree_node_t *node,
    nst_rbtree_node_t *sentinel);
void nst_rbtree_insert_timer_value(nst_rbtree_node_t *root,
    nst_rbtree_node_t *node, nst_rbtree_node_t *sentinel);


#define nst_rbt_red(node)               ((node)->color = 1)
#define nst_rbt_black(node)             ((node)->color = 0)
#define nst_rbt_is_red(node)            ((node)->color)
#define nst_rbt_is_black(node)          (!nst_rbt_is_red(node))
#define nst_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define nst_rbtree_sentinel_init(node)  nst_rbt_black(node)


static inline nst_rbtree_node_t *
nst_rbtree_min(nst_rbtree_node_t *node, nst_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NST_RBTREE_H_INCLUDED_ */
