
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


static void *nst_radix_alloc(nst_radix_tree_t *tree);


nst_radix_tree_t *
nst_radix_tree_create(nst_pool_t *pool, nst_int_t preallocate)
{
    uint32_t           key, mask, inc;
    nst_radix_tree_t  *tree;

    tree = nst_palloc(pool, sizeof(nst_radix_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    tree->pool = pool;
    tree->free = NULL;
    tree->start = NULL;
    tree->size = 0;

    tree->root = nst_radix_alloc(tree);
    if (tree->root == NULL) {
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;
    tree->root->value = NST_RADIX_NO_VALUE;

    if (preallocate == 0) {
        return tree;
    }

    /*
     * The preallocation the first nodes: 0, 1, 00, 01, 10, 11, 000, 001, etc.
     * increases the TLB hits even if for the first lookup iterations.
     * On the 32-bit platforms the 7 preallocated bits takes continuous 4K,
     * 8 - 8K, 9 - 16K, etc.  On the 64-bit platforms the 6 preallocated bits
     * takes continuous 4K, 7 - 8K, 8 - 16K, etc.  There is no sense to
     * to preallocate more than one page, because further preallocation
     * distributes the only bit per page.  Instead, the random insertion
     * may distribute several bits per page.
     *
     * Thus, by default we preallocate maximum
     *     6 bits on amd64 (64-bit platform and 4K pages)
     *     7 bits on i386 (32-bit platform and 4K pages)
     *     7 bits on sparc64 in 64-bit mode (8K pages)
     *     8 bits on sparc64 in 32-bit mode (8K pages)
     */

    if (preallocate == -1) {
        switch (nst_pagesize / sizeof(nst_radix_tree_t)) {

        /* amd64 */
        case 128:
            preallocate = 6;
            break;

        /* i386, sparc64 */
        case 256:
            preallocate = 7;
            break;

        /* sparc64 in 32-bit mode */
        default:
            preallocate = 8;
        }
    }

    mask = 0;
    inc = 0x80000000;

    while (preallocate--) {

        key = 0;
        mask >>= 1;
        mask |= 0x80000000;

        do {
            if (nst_radix32tree_insert(tree, key, mask, NST_RADIX_NO_VALUE)
                != NST_OK)
            {
                return NULL;
            }

            key += inc;

        } while (key);

        inc >>= 1;
    }

    return tree;
}


nst_int_t
nst_radix32tree_insert(nst_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value)
{
    uint32_t           bit;
    nst_radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != NST_RADIX_NO_VALUE) {
            return NST_BUSY;
        }

        node->value = value;
        return NST_OK;
    }

    while (bit & mask) {
        next = nst_radix_alloc(tree);
        if (next == NULL) {
            return NST_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = NST_RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return NST_OK;
}


nst_int_t
nst_radix32tree_delete(nst_radix_tree_t *tree, uint32_t key, uint32_t mask)
{
    uint32_t           bit;
    nst_radix_node_t  *node;

    bit = 0x80000000;
    node = tree->root;

    while (node && (bit & mask)) {
        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    if (node == NULL) {
        return NST_ERROR;
    }

    if (node->right || node->left) {
        if (node->value != NST_RADIX_NO_VALUE) {
            node->value = NST_RADIX_NO_VALUE;
            return NST_OK;
        }

        return NST_ERROR;
    }

    for ( ;; ) {
        if (node->parent->right == node) {
            node->parent->right = NULL;

        } else {
            node->parent->left = NULL;
        }

        node->right = tree->free;
        tree->free = node;

        node = node->parent;

        if (node->right || node->left) {
            break;
        }

        if (node->value != NST_RADIX_NO_VALUE) {
            break;
        }

        if (node->parent == NULL) {
            break;
        }
    }

    return NST_OK;
}


uintptr_t
nst_radix32tree_find(nst_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit;
    uintptr_t          value;
    nst_radix_node_t  *node;

    bit = 0x80000000;
    value = NST_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != NST_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return value;
}


static void *
nst_radix_alloc(nst_radix_tree_t *tree)
{
    char  *p;

    if (tree->free) {
        p = (char *) tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->size < sizeof(nst_radix_node_t)) {
        tree->start = nst_palloc(tree->pool, nst_pagesize);
        if (tree->start == NULL) {
            return NULL;
        }

        tree->size = nst_pagesize;
    }

    p = tree->start;
    tree->start += sizeof(nst_radix_node_t);
    tree->size -= sizeof(nst_radix_node_t);

    return p;
}
