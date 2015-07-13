#include "nst_iobuf.h"

#include "nst_gen_func.h"
#include "nst_string.h"
#include "nst_palloc.h"
#include "nst_assert.h"

#define MAX_IOBUF_FROM_POOL 1024

static void
nst_iobuf_do_free_buf(nst_iobuf_t *iobuf)
{
    if(iobuf->start && !iobuf->flags.no_free && iobuf->flags.palloc_large)
        nst_pfree(iobuf->pool, iobuf->start);

    STAILQ_INSERT_HEAD(&iobuf->pool->iobuf_queue, iobuf, queue_entry);
}

static inline nst_iobuf_t *
get_or_create_iobuf(nst_pool_t *pool)
{
    nst_iobuf_t *new_iobuf;

    if( (new_iobuf = STAILQ_FIRST(&pool->iobuf_queue)) ) {
        /* get from pool and zero it out */
        STAILQ_REMOVE_HEAD(&pool->iobuf_queue, queue_entry);
        nst_assert(NST_REFC_VALUE(new_iobuf) == 0);
        nst_assert(new_iobuf->pool == pool);
        nst_memzero(new_iobuf, sizeof(nst_iobuf_t));
    } else {
        /* create a new one and then zero it out */
        new_iobuf = nst_pcalloc(pool, sizeof(nst_iobuf_t));
    }

    /* At this pool, new_iobuf is zero-ed out */

    new_iobuf->pool = pool;
    NST_REFC_INIT(new_iobuf, (nst_gen_destructor_f)nst_iobuf_do_free_buf);

    return new_iobuf;
}

nst_iobuf_t *
nst_iobuf_create_eof(nst_pool_t *pool)
{
    nst_iobuf_t *new_iobuf;

    new_iobuf = get_or_create_iobuf(pool);

    if(!new_iobuf) {
        return NULL;
    }

    new_iobuf->flags.no_free = 1;
    new_iobuf->flags.io_eof = 1;

    return new_iobuf;
}

static inline nst_iobuf_t *
nst_iobuf_do_new(nst_pool_t *pool, size_t size, bool temp)
{
    nst_iobuf_t *new_iobuf;

    new_iobuf = get_or_create_iobuf(pool);
    if(!new_iobuf) {
        return NULL;
    }

    if(!size) {
        return new_iobuf;
    }

    if(temp || size > MAX_IOBUF_FROM_POOL || size > pool->max ) {
        new_iobuf->start = new_iobuf->pos = new_iobuf->last
            = nst_palloc_large(pool, size);
        new_iobuf->flags.palloc_large = 1;
    } else {
        new_iobuf->start = new_iobuf->pos = new_iobuf->last
            = nst_palloc(pool, size);
    }

    if(new_iobuf->start) {
        new_iobuf->end = new_iobuf->start + size;
        return new_iobuf;
    } else {
        nst_iobuf_free(new_iobuf);
        return NULL;
    }
}

nst_iobuf_t *
nst_iobuf_new(nst_pool_t *pool, size_t size)
{
    return nst_iobuf_do_new(pool, size, FALSE);
}

nst_iobuf_t *
nst_iobuf_new_temp(nst_pool_t *pool, size_t size)
{
    return nst_iobuf_do_new(pool, size, TRUE);
}

nst_iobuf_t *
nst_iobuf_shadow_clone(nst_iobuf_t *src_iobuf)
{
    nst_iobuf_t *iobuf;

    iobuf = get_or_create_iobuf(src_iobuf->pool);
    if(!iobuf)
        return NULL;

    memcpy(iobuf, src_iobuf, sizeof(*iobuf));
    iobuf->flags.no_free = 1;/* the src_iobuf still takes the data ownership */
    NST_REFC_INIT(iobuf, (nst_gen_destructor_f)nst_iobuf_do_free_buf);

    return iobuf;
}

nst_iobuf_t *
nst_iochain_remove_first(nst_iochain_t *iochain)
{
    nst_iobuf_t *first_iobuf;

    if( !(first_iobuf = STAILQ_FIRST(&iochain->iobuf_queue)) )
        return NULL;

    STAILQ_REMOVE_HEAD(&iochain->iobuf_queue, queue_entry);

    nst_assert(iochain->nbufs > 0);
    iochain->nbufs--;
    iochain->buf_size -= nst_iobuf_buf_size(first_iobuf);

    return first_iobuf;
}

nst_iobuf_t *
nst_iochain_remove_first_if_avail(nst_iochain_t *iochain)
{
    nst_iobuf_t *first_iobuf;

    if( !(first_iobuf = STAILQ_FIRST(&iochain->iobuf_queue)) )
        return NULL;

    if(first_iobuf->pos == first_iobuf->last) {
        /* this iobuf has been written to the peer. it can be reused
         * for reading.
         */
        STAILQ_REMOVE_HEAD(&iochain->iobuf_queue, queue_entry);
        nst_assert(iochain->nbufs > 0);
        iochain->nbufs--;
        iochain->buf_size -= nst_iobuf_buf_size(first_iobuf);
        first_iobuf->pos = first_iobuf->last = first_iobuf->start;
        return first_iobuf;
    } else {
        nst_assert(first_iobuf->pos < first_iobuf->last);
        return NULL;
    }
}

void nst_iochain_free(nst_iochain_t *iochain)
{
    nst_iobuf_t *iobuf;

    while(!STAILQ_ETPTY(&iochain->iobuf_queue)) {
        iobuf = STAILQ_FIRST(&iochain->iobuf_queue);
        STAILQ_REMOVE_HEAD(&iochain->iobuf_queue, queue_entry);
        nst_iobuf_free(iobuf);
    }
}

void
nst_iobuf_free(nst_iobuf_t *iobuf)
{
    NST_REFC_PUT(iobuf);

    return;
}

int
nst_iobuf_vsnprintf (nst_pool_t * pool, nst_iochain_t * chain,
                     const char * fmt, ...)
{
    int                     len = 0;
    va_list                 args;
    char                    buf [4096];

    va_start(args, fmt);
    len = vsnprintf ((char *)buf, sizeof(buf), fmt, args);
    va_end (args);

    if (nst_iochain_data_append (pool, chain, len, buf) == NST_OK) {
        return NST_OK;
    }

    return NST_ERROR;
}


int
nst_iobuf_data_append (nst_iobuf_t * iobuf, int len, const char * src)
{
    u_char      * dst;

    NST_ASSERT(src != NULL);
    if ((int)nst_iobuf_write_buf_size(iobuf) < len) {
        return NST_ERROR;
    }

    dst = nst_iobuf_data_wptr(iobuf);
    memcpy ((void *)dst, (void *)src, len);
    nst_iobuf_add(iobuf, len);

    return NST_OK;
}

int
nst_iochain_data_append (nst_pool_t * pool, nst_iochain_t * chain,
                         int len, const char * src)
{
    nst_iobuf_t * b;
    int           lencopied = 0;

    b = nst_iochain_get_first (chain);
    while (src != NULL && lencopied < len) {
        int cp, a = 0, bs;
        if (b)
            a = nst_iobuf_write_buf_size (b);

        NST_ASSERT(a >= 0);
        if (a == 0) {
            bs = (len > NST_IOBUF_DEFAULT_SIZE) ? len : NST_IOBUF_DEFAULT_SIZE;
            b  = nst_iobuf_new (pool, bs);
            if (b == NULL) {
                return NST_ERROR;
            }
            nst_iochain_append (chain, b);
        }

        a = nst_iobuf_write_buf_size (b);
        NST_ASSERT(a > 0);

        cp = len < a ?  len : a;
        nst_iobuf_data_append (b, cp, src + lencopied);
        lencopied += cp;
        len -= cp;
    }

    return NST_OK;
}

int
nst_iobuf_coalesce (nst_pool_t * pool, nst_iochain_t * chain)
{
    nst_iobuf_t     * nb, * b;
    size_t            size = 0;

    STAILQ_FOREACH(b, &chain->iobuf_queue, queue_entry) {
        size += nst_iobuf_read_buf_size(b);
    }

    if (size > NST_IOBUF_COALESCE_MAX_SIZE) {
        return NST_ECOALESCE;
    }

    nb = nst_iobuf_new (pool, size);
    if (nb == NULL) {
        return NST_ERROR;
    }

    STAILQ_FOREACH(b, &chain->iobuf_queue, queue_entry) {
        nst_iobuf_data_append (nb, nst_iobuf_read_buf_size(b),
                          (char *)nst_iobuf_data_rptr(b));
    }
    nst_iochain_free (chain);
    nst_iochain_append (chain, nb);

    return NST_OK;
}

size_t
nst_iobuf_chain_data_len (nst_iochain_t * chain)
{
    nst_iobuf_t      * b;
    size_t            size = 0;

    STAILQ_FOREACH(b, &chain->iobuf_queue, queue_entry) {
        size += nst_iobuf_read_buf_size(b);
    }

    return size;
}

void
nst_iobuf_chain_merge (nst_iochain_t * src, nst_iochain_t * dest)
{
    nst_iobuf_t      * b;

    while (1) {
        b = nst_iochain_remove_first (src);
        if (b == NULL)
            break;
        nst_iochain_append (dest, b);
    }
}

void
nst_iochain_free_consumed (nst_iochain_t * chain)
{
    nst_iobuf_t     * b;

    while (1) {
        b = nst_iochain_get_first (chain);
        if (b && (nst_iobuf_read_buf_size (b) == 0)) {
            nst_iochain_remove_first (chain);
            nst_iobuf_free (b);
        }
        else {
            break;
        }
    }
}


int
nst_iobuf_coalesce_len (nst_pool_t * pool, int len, nst_iochain_t * chain)
{
    nst_iobuf_t     * nb, * b;
    int               bsize, tlen;
    char            * src, * dst;

    nb = nst_iobuf_new (pool, len);
    if (nb == NULL) {
        return NST_ENOMEM;
    }

    while (len > 0) {
        b = nst_iochain_get_first (chain);
        if (b == NULL)
            break;
        bsize = nst_iobuf_read_buf_size (b);
        tlen = (bsize > len) ? len : bsize;

        src = (char *)nst_iobuf_data_rptr(b);
        dst = (char *)nst_iobuf_data_wptr(nb);
        memcpy (dst, src, tlen);
        nst_iobuf_add (nb, tlen);
        if (len > bsize) {
            nst_iochain_remove_first (chain);
            nst_iobuf_free (b);
        }
        else {
            nst_iobuf_consumed (b, tlen);
        }
        len -= tlen;
    }

    if (nb != NULL)
        nst_iochain_insert_head (chain, nb);

    if (len == 0)
        return NST_OK;

    return NST_AGAIN;
}
