
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


nst_uint_t  nst_pagesize;
nst_uint_t  nst_pagesize_shift;
nst_uint_t  nst_cacheline_size;


void *
nst_xmalloc(size_t size)
{
    return malloc (size);
}

void*
nst_xcalloc (size_t size)
{
    void * p;

    p =  nst_xmalloc (size);
    if (p)
        bzero (p, size);

    return p;
}

void
nst_xfree (void * p)
{
    if (p) free (p);
}

void *
nst_alloc(size_t size, nst_log_t *log)
{
    void  *p;

    p = nst_xmalloc(size);
    if (p == NULL) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno,
                      "malloc() %uz bytes failed", size);
    }

    nst_log_debug2(NST_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}


void *
nst_calloc(size_t size, nst_log_t *log)
{
    void  *p;

    p = nst_alloc(size, log);

    if (p) {
        nst_memzero(p, size);
    }

    return p;
}


#if (NST_HAVE_POSIX_MEMALIGN)

void *
nst_memalign(size_t alignment, size_t size, nst_log_t *log)
{
    void  *p;

    if (posix_memalign(&p, alignment, size) == -1) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno,
                      "posix_memalign() %uz bytes aligned to %uz failed",
                      size, alignment);
    }

    nst_log_debug2(NST_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz", p, size);

    return p;
}

#elif (NST_HAVE_MEMALIGN)

void *
nst_memalign(size_t alignment, size_t size, nst_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno,
                      "memalign() %uz bytes aligned to %uz failed",
                      size, alignment);
    }

    nst_log_debug2(NST_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz", p, size);

    return p;
}

#endif
