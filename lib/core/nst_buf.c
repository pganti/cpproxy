
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


nst_buf_t *
nst_create_temp_buf(nst_pool_t *pool, size_t size)
{
    nst_buf_t *b;

    b = nst_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = nst_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by nst_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


nst_chain_t *
nst_alloc_chain_link(nst_pool_t *pool)
{
    nst_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = nst_palloc(pool, sizeof(nst_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


nst_chain_t *
nst_create_chain_of_bufs(nst_pool_t *pool, nst_bufs_t *bufs)
{
    u_char       *p;
    nst_int_t     i;
    nst_buf_t    *b;
    nst_chain_t  *chain, *cl, **ll;

    p = nst_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = nst_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by nst_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        cl = nst_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


nst_int_t
nst_chain_add_copy(nst_pool_t *pool, nst_chain_t **chain, nst_chain_t *in)
{
    nst_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = nst_alloc_chain_link(pool);
        if (cl == NULL) {
            return NST_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NST_OK;
}


nst_chain_t *
nst_chain_get_free_buf(nst_pool_t *p, nst_chain_t **free)
{
    nst_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = nst_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = nst_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
nst_chain_update_chains(nst_chain_t **free, nst_chain_t **busy,
    nst_chain_t **out, nst_buf_tag_t tag)
{
    nst_chain_t  *cl;

    if (*busy == NULL) {
        *busy = *out;

    } else {
        for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

        cl->next = *out;
    }

    *out = NULL;

    while (*busy) {
        if (nst_buf_size((*busy)->buf) != 0) {
            break;
        }

#if (NST_HAVE_WRITE_ZEROCOPY)
        if ((*busy)->buf->zerocopy_busy) {
            break;
        }
#endif

        if ((*busy)->buf->tag != tag) {
            *busy = (*busy)->next;
            continue;
        }

        (*busy)->buf->pos = (*busy)->buf->start;
        (*busy)->buf->last = (*busy)->buf->start;

        cl = *busy;
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}
