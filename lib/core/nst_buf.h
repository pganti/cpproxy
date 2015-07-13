
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_BUF_H_INCLUDED_
#define _NST_BUF_H_INCLUDED_


#include <nst_core.h>


typedef void *            nst_buf_tag_t;

typedef struct nst_chain_s         nst_chain_t;

typedef struct nst_buf_s  nst_buf_t;

struct nst_buf_s {
    u_char          *pos;
    u_char          *last;
    off_t            file_pos;
    off_t            file_last;

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    nst_buf_tag_t    tag;
    nst_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;

    unsigned         recycled:1;
    unsigned         in_file:1;
    unsigned         flush:1;
    unsigned         sync:1;
    unsigned         last_buf:1;
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    unsigned         zerocopy_busy:1;

    /* STUB */ int   num;
};

struct nst_chain_s {
    nst_buf_t    *buf;
    nst_chain_t  *next;
};


typedef struct {
    nst_int_t    num;
    size_t       size;
} nst_bufs_t;


typedef nst_int_t (*nst_output_chain_filter_pt)(void *ctx, nst_chain_t *in);

typedef struct {
    nst_buf_t                   *buf;
    nst_chain_t                 *in;
    nst_chain_t                 *free;
    nst_chain_t                 *busy;

    unsigned                     sendfile;
    unsigned                     need_in_memory;
    unsigned                     need_in_temp;

    nst_pool_t                  *pool;
    nst_int_t                    allocated;
    nst_bufs_t                   bufs;
    nst_buf_tag_t                tag;

    nst_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
} nst_output_chain_ctx_t;


typedef struct {
    nst_chain_t                 *out;
    nst_chain_t                **last;
    void                        *connection;
    nst_pool_t                  *pool;
    off_t                        limit;
} nst_chain_writer_ctx_t;


#define NST_CHAIN_ERROR     (nst_chain_t *) NST_ERROR


#define nst_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define nst_buf_in_memory_only(b)   (nst_buf_in_memory(b) && !b->in_file)

#define nst_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !nst_buf_in_memory(b) && !b->in_file)

#define nst_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !nst_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define nst_buf_size(b)                                                      \
    (nst_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

nst_buf_t *nst_create_temp_buf(nst_pool_t *pool, size_t size);
nst_chain_t *nst_create_chain_of_bufs(nst_pool_t *pool, nst_bufs_t *bufs);


#define nst_alloc_buf(pool)  nst_palloc(pool, sizeof(nst_buf_t))
#define nst_calloc_buf(pool) nst_pcalloc(pool, sizeof(nst_buf_t))

nst_chain_t *nst_alloc_chain_link(nst_pool_t *pool);
#define nst_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



nst_int_t nst_output_chain(nst_output_chain_ctx_t *ctx, nst_chain_t *in);
nst_int_t nst_chain_writer(void *ctx, nst_chain_t *in);

nst_int_t nst_chain_add_copy(nst_pool_t *pool, nst_chain_t **chain,
    nst_chain_t *in);
nst_chain_t *nst_chain_get_free_buf(nst_pool_t *p, nst_chain_t **free);
void nst_chain_update_chains(nst_chain_t **free, nst_chain_t **busy,
    nst_chain_t **out, nst_buf_tag_t tag);


#endif /* _NST_BUF_H_INCLUDED_ */
