
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


static nst_inline void nst_rbtree_left_rotate(nst_rbtree_node_t **root,
    nst_rbtree_node_t *sentinel, nst_rbtree_node_t *node);
static nst_inline void nst_rbtree_right_rotate(nst_rbtree_node_t **root,
    nst_rbtree_node_t *sentinel, nst_rbtree_node_t *node);


void
nst_rbtree_insert(volatile nst_rbtree_t *tree, nst_rbtree_node_t *node)
{
    nst_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = (nst_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        nst_rbt_black(node);
        *root = node;

        return;
    }

    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    while (node != *root && nst_rbt_is_red(node->parent)) {

        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;

            if (nst_rbt_is_red(temp)) {
                nst_rbt_black(node->parent);
                nst_rbt_black(temp);
                nst_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    nst_rbtree_left_rotate(root, sentinel, node);
                }

                nst_rbt_black(node->parent);
                nst_rbt_red(node->parent->parent);
                nst_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            temp = node->parent->parent->left;

            if (nst_rbt_is_red(temp)) {
                nst_rbt_black(node->parent);
                nst_rbt_black(temp);
                nst_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    nst_rbtree_right_rotate(root, sentinel, node);
                }

                nst_rbt_black(node->parent);
                nst_rbt_red(node->parent->parent);
                nst_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    nst_rbt_black(*root);
}


void
nst_rbtree_insert_value(nst_rbtree_node_t *temp, nst_rbtree_node_t *node,
    nst_rbtree_node_t *sentinel)
{
    nst_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

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


void
nst_rbtree_insert_timer_value(nst_rbtree_node_t *temp, nst_rbtree_node_t *node,
    nst_rbtree_node_t *sentinel)
{
    nst_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((nst_rbtree_key_int_t) node->key - (nst_rbtree_key_int_t) temp->key
              < 0)
            ? &temp->left : &temp->right;

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


void
nst_rbtree_delete(volatile nst_rbtree_t *tree,
    nst_rbtree_node_t *node)
{
    nst_uint_t           red;
    nst_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = (nst_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        temp = node->left;
        subst = node;

    } else {
        subst = nst_rbtree_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    if (subst == *root) {
        *root = temp;
        nst_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = nst_rbt_is_red(subst);

    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst == node) {

        temp->parent = subst->parent;

    } else {

        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        nst_rbt_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    if (red) {
        return;
    }

    /* a delete fixup */

    while (temp != *root && nst_rbt_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (nst_rbt_is_red(w)) {
                nst_rbt_black(w);
                nst_rbt_red(temp->parent);
                nst_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (nst_rbt_is_black(w->left) && nst_rbt_is_black(w->right)) {
                nst_rbt_red(w);
                temp = temp->parent;

            } else {
                if (nst_rbt_is_black(w->right)) {
                    nst_rbt_black(w->left);
                    nst_rbt_red(w);
                    nst_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                nst_rbt_copy_color(w, temp->parent);
                nst_rbt_black(temp->parent);
                nst_rbt_black(w->right);
                nst_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (nst_rbt_is_red(w)) {
                nst_rbt_black(w);
                nst_rbt_red(temp->parent);
                nst_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (nst_rbt_is_black(w->left) && nst_rbt_is_black(w->right)) {
                nst_rbt_red(w);
                temp = temp->parent;

            } else {
                if (nst_rbt_is_black(w->left)) {
                    nst_rbt_black(w->right);
                    nst_rbt_red(w);
                    nst_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                nst_rbt_copy_color(w, temp->parent);
                nst_rbt_black(temp->parent);
                nst_rbt_black(w->left);
                nst_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    nst_rbt_black(temp);
}


static nst_inline void
nst_rbtree_left_rotate(nst_rbtree_node_t **root, nst_rbtree_node_t *sentinel,
    nst_rbtree_node_t *node)
{
    nst_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


static nst_inline void
nst_rbtree_right_rotate(nst_rbtree_node_t **root, nst_rbtree_node_t *sentinel,
    nst_rbtree_node_t *node)
{
    nst_rbtree_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}
