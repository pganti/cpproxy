
/*
 * Copyright (C) Igor Sysoev
 */

#include <nst_core.h>

/*

                         12
    2048   2             11
    1024   4             10
    512    8             9
    256   16             8

    128   32   4   32    7

    64    64   8   63    6      1
    32   128  16  127    5      1
    16   256  32  254    4      2
    8    512  64  504    3      8

 */


#define NST_SLAB_PAGE_MASK   3
#define NST_SLAB_PAGE        0
#define NST_SLAB_BIG         1
#define NST_SLAB_EXACT       2
#define NST_SLAB_SMALL       3

#if (NST_PTR_SIZE == 4)

#define NST_SLAB_PAGE_FREE   0
#define NST_SLAB_PAGE_BUSY   0xffffffff
#define NST_SLAB_PAGE_START  0x80000000

#define NST_SLAB_SHIFT_MASK  0x0000000f
#define NST_SLAB_MAP_MASK    0xffff0000
#define NST_SLAB_MAP_SHIFT   16

#define NST_SLAB_BUSY        0xffffffff

#else /* (NST_PTR_SIZE == 8) */

#define NST_SLAB_PAGE_FREE   0
#define NST_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NST_SLAB_PAGE_START  0x8000000000000000

#define NST_SLAB_SHIFT_MASK  0x000000000000000f
#define NST_SLAB_MAP_MASK    0xffffffff00000000
#define NST_SLAB_MAP_SHIFT   32

#define NST_SLAB_BUSY        0xffffffffffffffff

#endif


#if (NST_DEBUG_MALLOC)

#define nst_slab_junk(p, size)     nst_memset(p, 0xD0, size)

#else

#if (NST_FREEBSD)

#define nst_slab_junk(p, size)                                                \
    if (nst_freebsd_debug_malloc)  nst_memset(p, 0xD0, size)

#else

#define nst_slab_junk(p, size)

#endif

#endif

static nst_slab_page_t *nst_slab_alloc_pages(nst_slab_pool_t *pool,
    nst_uint_t pages);
static void nst_slab_free_pages(nst_slab_pool_t *pool, nst_slab_page_t *page,
    nst_uint_t pages);


static nst_uint_t  nst_slab_max_size;
static nst_uint_t  nst_slab_exact_size;
static nst_uint_t  nst_slab_exact_shift;


void
nst_slab_init(nst_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    nst_int_t         m;
    nst_uint_t        i, n, pages;
    nst_slab_page_t  *slots;

    /* STUB */
    if (nst_slab_max_size == 0) {
        nst_slab_max_size = nst_pagesize / 2;
        nst_slab_exact_size = nst_pagesize / (8 * sizeof(uintptr_t));
        for (n = nst_slab_exact_size; n >>= 1; nst_slab_exact_shift++) {
            /* void */
        }
    }
    /**/

    pool->min_size = 1 << pool->min_shift;

    p = (u_char *) pool + sizeof(nst_slab_pool_t);
    size = pool->end - p;

    nst_slab_junk(p, size);

    slots = (nst_slab_page_t *) p;
    n = nst_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(nst_slab_page_t);

    pages = (nst_uint_t) (size / (nst_pagesize + sizeof(nst_slab_page_t)));

    nst_memzero(p, pages * sizeof(nst_slab_page_t));

    pool->pages = (nst_slab_page_t *) p;

    pool->free.prev = 0;
    pool->free.next = (nst_slab_page_t *) p;

    pool->pages->slab = pages;
    pool->pages->next = &pool->free;
    pool->pages->prev = (uintptr_t) &pool->free;

    pool->start = (u_char *)
                  nst_align_ptr((uintptr_t) p + pages * sizeof(nst_slab_page_t),
                                 nst_pagesize);

    m = pages - (pool->end - pool->start) / nst_pagesize;
    if (m > 0) {
        pages -= m;
        pool->pages->slab = pages;
    }

#if 0
    nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0, "slab: %p, %p, %ui, %d",
                  pool, pool->start, pages,
                  (pool->end - pool->start) / nst_pagesize - pages);
#endif
}


void *
nst_slab_alloc(nst_slab_pool_t *pool, size_t size)
{
    void  *p;

    nst_shmtx_lock(&pool->mutex);

    p = nst_slab_alloc_locked(pool, size);

    nst_shmtx_unlock(&pool->mutex);

    return p;
}


void *
nst_slab_alloc_locked(nst_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, n, m, mask, *bitmap;
    nst_uint_t        i, slot, shift, map;
    nst_slab_page_t  *page, *prev, *slots;

    if (size >= nst_slab_max_size) {

        nst_log_debug1(NST_LOG_DEBUG_ALLOC, nst_default_logger(), 0,
                       "slab alloc: %uz", size);

        page = nst_slab_alloc_pages(pool, (size + nst_pagesize - 1)
                                          >> nst_pagesize_shift);
        if (page) {
            p = (page - pool->pages) << nst_pagesize_shift;
            p += (uintptr_t) pool->start;

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        size = pool->min_size;
        shift = pool->min_shift;
        slot = 0;
    }

    nst_log_debug2(NST_LOG_DEBUG_ALLOC, nst_default_logger(), 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = (nst_slab_page_t *) ((u_char *) pool + sizeof(nst_slab_pool_t));
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < nst_slab_exact_shift) {

            do {
                p = (page - pool->pages) << nst_pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + p);

                map = (1 << (nst_pagesize_shift - shift))
                          / (sizeof(uintptr_t) * 8);

                for (n = 0; n < map; n++) {

                    if (bitmap[n] != NST_SLAB_BUSY) {

                        for (m = 1, i = 0; m; m <<= 1, i++) {
                            if ((bitmap[n] & m)) {
                                continue;
                            }

                            bitmap[n] |= m;

                            i = ((n * sizeof(uintptr_t) * 8) << shift)
                                + (i << shift);

                            if (bitmap[n] == NST_SLAB_BUSY) {
                                for (n = n + 1; n < map; n++) {
                                     if (bitmap[n] != NST_SLAB_BUSY) {
                                         p = (uintptr_t) bitmap + i;

                                         goto done;
                                     }
                                }

                                prev = (nst_slab_page_t *)
                                            (page->prev & ~NST_SLAB_PAGE_MASK);
                                prev->next = page->next;
                                page->next->prev = page->prev;

                                page->next = NULL;
                                page->prev = NST_SLAB_SMALL;
                            }

                            p = (uintptr_t) bitmap + i;

                            goto done;
                        }
                    }
                }

                page = page->next;

            } while (page);

        } else if (shift == nst_slab_exact_shift) {

            do {
                if (page->slab != NST_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if (page->slab == NST_SLAB_BUSY) {
                            prev = (nst_slab_page_t *)
                                            (page->prev & ~NST_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NST_SLAB_EXACT;
                        }

                        p = (page - pool->pages) << nst_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);

        } else { /* shift > nst_slab_exact_shift */

            n = nst_pagesize_shift - (page->slab & NST_SLAB_SHIFT_MASK);
            n = 1 << n;
            n = ((uintptr_t) 1 << n) - 1;
            mask = n << NST_SLAB_MAP_SHIFT;

            do {
                if ((page->slab & NST_SLAB_MAP_MASK) != mask) {

                    for (m = (uintptr_t) 1 << NST_SLAB_MAP_SHIFT, i = 0;
                         m & mask;
                         m <<= 1, i++)
                    {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if ((page->slab & NST_SLAB_MAP_MASK) == mask) {
                            prev = (nst_slab_page_t *)
                                            (page->prev & ~NST_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NST_SLAB_BIG;
                        }

                        p = (page - pool->pages) << nst_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);
        }
    }

    page = nst_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < nst_slab_exact_shift) {
            p = (page - pool->pages) << nst_pagesize_shift;
            bitmap = (uintptr_t *) (pool->start + p);

            s = 1 << shift;
            n = (1 << (nst_pagesize_shift - shift)) / 8 / s;

            if (n == 0) {
                n = 1;
            }

            bitmap[0] = (2 << n) - 1;

            map = (1 << (nst_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (i = 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NST_SLAB_SMALL;

            slots[slot].next = page;

            p = ((page - pool->pages) << nst_pagesize_shift) + s * n;
            p += (uintptr_t) pool->start;

            goto done;

        } else if (shift == nst_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NST_SLAB_EXACT;

            slots[slot].next = page;

            p = (page - pool->pages) << nst_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;

        } else { /* shift > nst_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NST_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NST_SLAB_BIG;

            slots[slot].next = page;

            p = (page - pool->pages) << nst_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;
        }
    }

    p = 0;

done:

    nst_log_debug1(NST_LOG_DEBUG_ALLOC, nst_default_logger(), 0, "slab alloc: %p", p);

    return (void *) p;
}


void
nst_slab_free(nst_slab_pool_t *pool, void *p)
{
    nst_shmtx_lock(&pool->mutex);

    nst_slab_free_locked(pool, p);

    nst_shmtx_unlock(&pool->mutex);
}


void
nst_slab_free_locked(nst_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    nst_uint_t        n, type, slot, shift, map;
    nst_slab_page_t  *slots, *page;

    nst_log_debug1(NST_LOG_DEBUG_ALLOC, nst_default_logger(), 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0,
                      "nst_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> nst_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = page->prev & NST_SLAB_PAGE_MASK;

    switch (type) {

    case NST_SLAB_SMALL:

        shift = slab & NST_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (nst_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n & (sizeof(uintptr_t) * 8 - 1));
        n /= (sizeof(uintptr_t) * 8);
        bitmap = (uintptr_t *) ((uintptr_t) p & ~(nst_pagesize - 1));

        if (bitmap[n] & m) {

            if (page->next == NULL) {
                slots = (nst_slab_page_t *)
                                   ((u_char *) pool + sizeof(nst_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NST_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NST_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (1 << (nst_pagesize_shift - shift)) / 8 / (1 << shift);

            if (n == 0) {
                n = 1;
            }

            if (bitmap[0] & ~(((uintptr_t) 1 << n) - 1)) {
                goto done;
            }

            map = (1 << (nst_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (n = 1; n < map; n++) {
                if (bitmap[n]) {
                    goto done;
                }
            }

            nst_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NST_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (nst_pagesize - 1)) >> nst_slab_exact_shift);
        size = nst_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            if (slab == NST_SLAB_BUSY) {
                slots = (nst_slab_page_t *)
                                   ((u_char *) pool + sizeof(nst_slab_pool_t));
                slot = nst_slab_exact_shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NST_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NST_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            nst_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NST_SLAB_BIG:

        shift = slab & NST_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (nst_pagesize - 1)) >> shift)
                              + NST_SLAB_MAP_SHIFT);

        if (slab & m) {

            if (page->next == NULL) {
                slots = (nst_slab_page_t *)
                                   ((u_char *) pool + sizeof(nst_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NST_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NST_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NST_SLAB_MAP_MASK) {
                goto done;
            }

            nst_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NST_SLAB_PAGE:

        if ((uintptr_t) p & (nst_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (slab == NST_SLAB_PAGE_FREE) {
            nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0,
                          "nst_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NST_SLAB_PAGE_BUSY) {
            nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0,
                          "nst_slab_free(): pointer to wrong page");
            goto fail;
        }

        n = ((u_char *) p - pool->start) >> nst_pagesize_shift;
        size = slab & ~NST_SLAB_PAGE_START;

        nst_slab_free_pages(pool, &pool->pages[n], size);

        size <<= nst_pagesize_shift;

        goto done;
    }

    /* not reached */

    return;

done:

    nst_slab_junk(p, size);

    return;

wrong_chunk:

    nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0,
                      "nst_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    nst_log_error(NST_LOG_ALERT, nst_default_logger(), 0,
                      "nst_slab_free(): chunk is already free");

fail:

    return;
}


static nst_slab_page_t *
nst_slab_alloc_pages(nst_slab_pool_t *pool, nst_uint_t pages)
{
    nst_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (nst_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (nst_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | NST_SLAB_PAGE_START;

#if (NST_DEBUG)
            page->next = NULL;
            page->prev = NST_SLAB_PAGE;
#endif

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NST_SLAB_PAGE_BUSY;
#if (NST_DEBUG)
                p->next = NULL;
                p->prev = NST_SLAB_PAGE;
#endif
                p++;
            }

            return page;
        }
    }

    nst_log_error(NST_LOG_ALERT, nst_default_logger(), NST_ENOMEM,
                      "nst_slab_alloc(): failed");

    return NULL;
}


static void
nst_slab_free_pages(nst_slab_pool_t *pool, nst_slab_page_t *page,
    nst_uint_t pages)
{
    nst_slab_page_t  *prev;

    page->slab = pages--;

    if (pages) {
        nst_memzero(&page[1], pages * sizeof(nst_slab_page_t));
    }

    if (page->next) {
        prev = (nst_slab_page_t *) (page->prev & ~NST_SLAB_PAGE_MASK);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}
