#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <nst_core.h>
#include <nst_genhash.h>


typedef struct test_nst_ghash_elem {
    nst_ghash_elem_t   e;
    int           value;
} test_nst_ghash_elem_t;

int            table_size = 1000;
int            nst_ghash_elems = 1000;

int test_key_compare (nst_ghash_key_t key, char * bigkey, nst_ghash_elem_t * e)
{
    int        l = *((int *)bigkey);
    test_nst_ghash_elem_t * te = (test_nst_ghash_elem_t *)e;

    if (te->value == l) {
        return 0;
    }
    return 1;
}

nst_ghash_key_t test_key_create (char * bigkey)
{
    nst_ghash_key_t k;
    int        l = *((int *)bigkey);

    return l;
}


int main (int argc, char * argv[])
{

    nst_ghash_table_t   ht, * htr;
    int            i;
    test_nst_ghash_elem_t  helms [nst_ghash_elems];
    test_nst_ghash_elem_t  * he;

    htr = nst_ghash_table_create (&ht,
                             table_size,
                             test_key_compare,
                             test_key_create);

    NST_ASSERT(htr != NULL);

    for (i=0; i < nst_ghash_elems; i++) {
        he = &helms[i];
        he->value = i;
        he->e.key = test_key_create ((char *)&i);
        nst_ghash_add_elem (he->e.key, &ht, (nst_ghash_elem_t *)he);
    }

    for (i=0; i < nst_ghash_elems; i++) {
        test_nst_ghash_elem_t * he;
        he = (test_nst_ghash_elem_t *)nst_ghash_lookup_elem (&ht, (char *)&i);
        if (he) {
            if (he->value != i) {
                printf ("Wrong element found i=%d, value=%d\n", i, he->value);
            }
            else {
                printf ("Found element i=%d, value=%d\n", i, he->value);
            }
        }
        else {
            printf ("Element not found\n", i);
        }

        nst_ghash_remove_elem (&ht, (nst_ghash_elem_t *)he);

        he = (test_nst_ghash_elem_t *)nst_ghash_lookup_elem (&ht, (char *)&i);
        if (he) {
            printf ("Deleted element found i=%d, value=%d\n", i, he->value);
        }
    }

    return 0;
}


