
#include "nst_expat_tree.h"

void
print_children (nst_expat_node_t    * root)
{
    nst_expat_node_t   * node;
    nst_expat_attr_t   * attr;

    for (node = root; node != NULL; node = node->next) {
        int i;
        for (i = 0; i  < node->depth * 2; i++) {
            printf (" ");
        }
        printf ("%s ", node->name);
        if (node->value) printf ("%s", node->value);
        attr = node->attr;
        if (attr) {
            printf ("<");
            while (attr) {
                printf ("%s: %s, ", attr->name, attr->value);
                attr = attr->next;
            }
            printf (">");
        }
        printf ("\n");
        if (node->children)
            print_children (node->children);
    }
}

int main (int argc, char * argv[])
{
    nst_log_t        * log;
    nst_pool_t       * pool;
    nst_expat_tree_t     * tree;

    if (argv[1] == NULL) {
        printf ("pass the file name\n");
        return -1;
    }

    log = nst_corelib_init ("nst_expat_test");
    pool = nst_create_pool (4096, log);
    tree = nst_expat_tree_from_file (pool, argv[1]);

    print_children (tree->root);

    return 0;
}


