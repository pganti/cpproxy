
#include <nst_cfg_dc.h>

void
print_config (struct data_center * dc)
{
    struct box       * box;
    printf ("%s: %s\n", dc->name, dc->type);

    for (box = dc->boxes; box != NULL; box = box->next) {
        struct process * p;
        printf ("  %s: %s\n", box->name, box->type);
        for (p = box->process; p != NULL; p = p->next) {
            struct monitor * m;
            struct log_facility * l;
            printf ("     %s/%s %s\n", p->path, p->cmd, p->args);
            for (l = p->log_facilities; l != NULL; l = l->next) {
                printf ("       log: %s(%s) -> %s\n", l->type, l->level, l->target);
            }
            for (m = p->monitors; m != NULL; m = m->next) {
                printf ("       mon: %s, restart=%s, interval=%s\n",
                        m->monname, m->maxrestarts, m->ri);
            }
        }
    }
}

    
int main (int argc, char * argv[])
{
    nst_log_t        * log;
    nst_pool_t       * pool;
    nst_expat_tree_t     * tree;
    struct data_center * dc, d;
    
    if (argv[1] == NULL) {
        printf ("pass the file name\n");
        return -1;
    }

    log = nst_corelib_init ("nst_xstruct_test");
    pool = nst_create_pool (1024, log);
    tree = nst_expat_tree_from_file (pool, argv[1]);

    dc = nst_xstruct_init_data_center (pool, &d);
    if (dc == NULL) {
        printf ("Init error");
        exit (-1);
    }

    dc = nst_xstruct_copy_struct_data_center (&d, pool, tree->root, "cluster");
    if (dc == NULL)
        printf ("Error");
    else
        print_config (dc);

    nst_expat_tree_cleanup (tree);

    nst_destroy_pool (pool);

    return 0;
}

           
