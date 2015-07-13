#ifndef __NST_EXPAT_TREE_TREE_H__
#define __NST_EXPAT_TREE_TREE_H__

#include <nst_core.h>

#define NST_EXPAT_TREE_VALUE_SSIZE (64)

typedef struct nst_expat_attr {
    char                     * name;
    char                     * value;
    struct nst_expat_attr    * next;
} nst_expat_attr_t;

typedef struct nst_expat_node {
    char                            * name;
    int                               vlen;
    int                               vsize;
    char                            * value;
    nst_expat_attr_t                * attr;
    int                               depth;
    int                               end;

    struct nst_expat_node           * children;
    struct nst_expat_node           * parent;
    struct nst_expat_node           * next;
    struct nst_expat_node           * prev;
} nst_expat_node_t;


typedef struct nst_expat_tree {
    nst_pool_t           * pool;
    nst_expat_node_t     * root;
    nst_expat_node_t     * current;
    nst_expat_node_t     * parent;
    int                    depth;
    void                 * parser;
    void                 * fp;
} nst_expat_tree_t;

nst_expat_tree_t * nst_expat_tree_from_file (nst_pool_t * pool, char * fname);
nst_expat_tree_t * nst_expat_tree_cleanup (nst_expat_tree_t * tree);
#endif  /*__NST_EXPAT_TREE_TREE_H__*/
