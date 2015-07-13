#include "nst_palloc.h"

#include "nst_string.h"
#include "nst_log_debug.h"
#include "nst_errno.h"

static void *nst_palloc_block(nst_pool_t *pool, size_t size);


nst_pool_t *
nst_create_pool(size_t size, nst_log_t *log)
{
    nst_pool_t  *p;

    p = nst_alloc(size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(nst_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;

    size = size - sizeof(nst_pool_t);
    p->max = (size < NST_MAX_ALLOC_FROM_POOL) ? size : NST_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    STAILQ_INIT(&p->iobuf_queue);

    return p;
}


void
nst_destroy_pool(nst_pool_t *pool)
{
    nst_pool_t          *p, *n;
    nst_pool_large_t    *l;
    nst_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            nst_log_debug1(NST_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

    for (l = pool->large; l; l = l->next) {

        nst_log_debug1(NST_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);

        if (l->alloc) {
            nst_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        nst_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void
nst_reset_pool(nst_pool_t *pool)
{
    nst_pool_t        *p;
    nst_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            nst_free(l->alloc);
        }
    }

    pool->large = NULL;

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(nst_pool_t);
    }
}


void *
nst_palloc(nst_pool_t *pool, size_t size)
{
    u_char      *m;
    nst_pool_t  *p;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = nst_align_ptr(p->d.last, NST_ALIGNMENT);

            if ((m < p->d.end) && ((size_t) (p->d.end - m) >= size)) {
                p->d.last = m + size;

                return m;
            }

            p = p->d.next;

        } while (p);

        return nst_palloc_block(pool, size);
    }

    return nst_palloc_large(pool, size);
}


void *
nst_pnalloc(nst_pool_t *pool, size_t size)
{
    u_char      *m;
    nst_pool_t  *p;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = p->d.last;

            if ((size_t) (p->d.end - m) >= size) {
                p->d.last = m + size;

                return m;
            }

            p = p->d.next;

        } while (p);

        return nst_palloc_block(pool, size);
    }

    return nst_palloc_large(pool, size);
}


static void *
nst_palloc_block(nst_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    nst_pool_t  *p, *new, *current;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = nst_alloc(psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new = (nst_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;

    m += sizeof(nst_pool_data_t);
    m = nst_align_ptr(m, NST_ALIGNMENT);
    new->d.last = m + size;

    current = pool->current;

    for (p = current; p->d.next; p = p->d.next) {
        if ((size_t) (p->d.end - p->d.last) < NST_ALIGNMENT) {
            current = p->d.next;
        }
    }

    p->d.next = new;

    pool->current = current ? current : new;

    return m;
}


void *
nst_palloc_large(nst_pool_t *pool, size_t size)
{
    void              *p;
    nst_pool_large_t  *large;

    p = nst_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = nst_palloc(pool, sizeof(nst_pool_large_t));
    if (large == NULL) {
        nst_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
nst_pmemalign(nst_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    nst_pool_large_t  *large;

    p = nst_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = nst_palloc(pool, sizeof(nst_pool_large_t));
    if (large == NULL) {
        nst_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


nst_int_t
nst_pfree(nst_pool_t *pool, void *p)
{
    nst_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            nst_log_debug1(NST_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            nst_free(l->alloc);
            l->alloc = NULL;

            return NST_OK;
        }
    }

    return NST_DECLINED;
}


void *
nst_pcalloc(nst_pool_t *pool, size_t size)
{
    void *p;

    p = nst_palloc(pool, size);
    if (p) {
        nst_memzero(p, size);
    }

    return p;
}


nst_pool_cleanup_t *
nst_pool_cleanup_add(nst_pool_t *p, size_t size)
{
    nst_pool_cleanup_t  *c;

    c = nst_palloc(p, sizeof(nst_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = nst_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    nst_log_debug1(NST_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}

char *
nst_pool_strdup (nst_pool_t * pool, int len, char * str)
{
    char  * dst;

    dst = nst_pnalloc (pool, len + 1);
    if (dst) {
        memcpy (dst, str, len);
        dst[len] = '\0';
    }

    return dst;
}

#if 0
void
nst_pool_cleanup_file(void *data)
{
    nst_pool_cleanup_file_t  *c = data;

    nst_log_debug1(NST_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (close(c->fd) == -1) {
        nst_log_error(NST_LOG_ALERT, c->log, nst_errno,
                      "close() \"%s\" failed", c->name);
    }
}


void
nst_pool_delete_file(void *data)
{
    nst_pool_cleanup_file_t  *c = data;

    nst_err_t  err;

    nst_log_debug2(NST_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (unlink((const char *)c->name) == -1) {
        err = nst_errno;

        if (err != NST_ENOENT) {
            nst_log_error(NST_LOG_CRIT, c->log, err,
                          "unlink() \"%s\" failed", c->name);
        }
    }

    if (close(c->fd) == -1) {
        nst_log_error(NST_LOG_ALERT, c->log, nst_errno,
                      "close() \"%s\" failed", c->name);
    }
}
#endif
