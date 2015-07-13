#ifndef _NST_PALLOC_H_
#define _NST_PALLOC_H_

#include "nst_config.h"

#include "nst_iobuf.h"
#include "nst_alloc.h"
#include "nst_types.h"
#include "nst_log_debug.h"

#include <sys/types.h>

/*
 * NST_MAX_ALLOC_FROM_POOL should be (nst_pagesize - 1), i.e. 4095 on x86.
 * On FreeBSD 5.x it allows to use the zero copy sending.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NST_MAX_ALLOC_FROM_POOL  (nst_pagesize - 1)

#define NST_DEFAULT_POOL_SIZE    (16 * 1024)
#define NST_MIN_POOL_SIZE                                                     \
    (sizeof(nst_pool_t) + 2 * sizeof(nst_pool_large_t))

struct nst_chain_s;
typedef void (*nst_pool_cleanup_pt)(void *data);
typedef struct nst_pool_cleanup_s  nst_pool_cleanup_t;
typedef struct nst_pool_large_s  nst_pool_large_t;
typedef struct nst_pool_s nst_pool_t;


struct nst_pool_cleanup_s {
    nst_pool_cleanup_pt   handler;
    void                 *data;
    nst_pool_cleanup_t   *next;
};


struct nst_pool_large_s {
    nst_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    nst_pool_t           *next;
} nst_pool_data_t;

struct nst_pool_s {
    nst_pool_data_t       d;
    size_t                max; /* the size of this pool (excluding nst_pool_t) */
    nst_pool_t           *current;
    struct nst_iobuf_queue_s  iobuf_queue;
    nst_pool_large_t     *large;
    nst_pool_cleanup_t   *cleanup;
    nst_log_t            *log;
};


typedef struct {
    nst_fd_t              fd;
    u_char               *name;
    nst_log_t            *log;
} nst_pool_cleanup_file_t;


void *nst_alloc(size_t size, nst_log_t *log);
void *nst_calloc(size_t size, nst_log_t *log);

nst_pool_t *nst_create_pool(size_t size, nst_log_t *log);
void nst_destroy_pool(nst_pool_t *pool);
void nst_reset_pool(nst_pool_t *pool);

/*  get memory from the pool.  if the existing space does not have
 *     enough memory, a new pool will be created. the returned memory will be
 *     aligned to machine work (i.e. unsigned long long).
 */
void *nst_palloc(nst_pool_t *pool, size_t size);

void *nst_palloc_large(nst_pool_t *pool, size_t size);

/* same as nst_palloc but the returned memory will not be aligned to
 *     machine word (i.e. not aligned to unsigned long long).
 */
void *nst_pnalloc(nst_pool_t *pool, size_t size);
void *nst_pcalloc(nst_pool_t *pool, size_t size);
void *nst_pmemalign(nst_pool_t *pool, size_t size, size_t alignment);
nst_int_t nst_pfree(nst_pool_t *pool, void *p);


nst_pool_cleanup_t *nst_pool_cleanup_add(nst_pool_t *p, size_t size);
void nst_pool_cleanup_file(void *data);
void nst_pool_delete_file(void *data);
char * nst_pool_strdup (nst_pool_t * pool, int len, char * str);

#endif /* _NST_PALLOC_H_INCLUDED_ */
