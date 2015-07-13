/*$Id: nst_mempool.h 554 2009-03-25 18:36:55Z pganti $*/
#ifndef _NST_METPOOL_H_
#define _NST_METPOOL_H_

#ifdef THREADS_ENABLED
#include  <pthread.h>
#endif

#include "nst_config.h"
#include "nst_types.h"

#define NST_METPOOL_NAME_MAX    (128)
#define NST_METPOOL_MAGIC       (0xbeef)
#define NST_METPOOL_ELEM_MAGIC  (0xeefb)
#define NST_METPOOL_METPOOL     (0xceaf)
#define NST_METPOOL_MALLOC      (0xfaec)

typedef struct nst_mempool_gstats {
    u64        pools;
    u64        alloc_failed;
    u64        buffer_alloc_failed;
    u64        elem_alloc_failed;
    u64        outstanding_elems;
    u64        destroyed;
    u64        malloc_failed;
} nst_mempool_gstats_t ;


typedef struct nst_mempool_stats {
    u64        alloc_failed;   /* Allocation failures */
    u64        size_exceeded;   /* Memory size exceeded */
    u64        malloc_failed;  /* Memory allocation failures */
    u64        alloced;   /* Allocated items */
    u64        freed;   /* Allocated items */
    u64        malloced;   /* MAllocated items */
    u64        mfreed;   /* MAllocated items */
    u64        outstanding_elems;
} nst_mempool_stats_t;

struct nst_mempool_elem {
    u16                    magic;
    u16                    source;
    struct nst_mempool_elem  * next;
};
typedef struct nst_mempool_elem nst_mempool_elem_t;

typedef struct mempool {
    char                  name[NST_METPOOL_NAME_MAX];    /* Name of the pool */
    int                   malloc;  /* Malloc if queue is empty */
    u32                   pool_size;  /* Pre-allocate these many items */
    u32                   poolmax_size;   /* Maximum number of items */
    u32                   malloc_size;  /* Allocated From Malloc */
    u32                   memsize;   /* Allocated items */
    u32                   meminuse;   /* Used memeory */
    nst_mempool_stats_t   stats;
    size_t                elem_size;   /* size of the each item */
    nst_mempool_elem_t  * mempool;
    char                * membase;
    int                   lock;     /* Lock the pool */

#ifdef THREADS_ENABLED
    pthread_mutex_t       mutex;
#endif
} nst_mempool_t;

extern nst_mempool_gstats_t    Mempoolgstats;

extern char * nst_mempool_string_alloc (size_t size);
extern void  nst_mempool_string_free (char * str);
extern nst_mempool_t * nst_mempool_create (char * name, int malloc,
        int pool_size, int poolmax_size, int elem_size, int lock);
extern void * nst_mempool_alloc (nst_mempool_t * pool);
extern void nst_mempool_free (nst_mempool_t * pool, void * m);
extern int nst_mempool_destroy (nst_mempool_t * pool);
extern int nst_mempool_init (void);
extern int nst_mempool_getoverhead (void);
extern void * nst_mempool_misc_malloc (size_t size);
extern void nst_mempool_misc_free (void * ptr);

#endif /*_NST_METPOOL_H_*/
