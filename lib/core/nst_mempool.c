/*$Id: nst_mempool.c 554 2009-03-25 18:36:55Z pganti $*/
#include <nst_core.h>

nst_mempool_gstats_t    Mempoolgstats;
static int              Mempool_inited = 0;

char * nst_mempool_string_alloc (size_t size)
{
    return ((char *)nst_xmalloc (size));
}

void  nst_mempool_string_free (char * str)
{
    if (str)
        nst_free (str);
}

void * nst_mempool_misc_malloc (size_t size)
{
	return nst_xmalloc (size);
}

void nst_mempool_misc_free (void * ptr)
{
	nst_free (ptr);
}

nst_mempool_t *
nst_mempool_create (char * name, int malloc, int pool_size,
        int poolmax_size, int elem_size, int lock)
{
    nst_mempool_t       * pool;
    u32               i;

    pool = nst_xmalloc (sizeof(nst_mempool_t));

    if (pool == NULL) {
        Mempoolgstats.alloc_failed++;
        return NULL;
    }

    bzero (pool, sizeof(nst_mempool_t));

    pool->malloc = malloc;
    pool->pool_size = pool_size;
    pool->poolmax_size = poolmax_size;
    pool->elem_size = elem_size + sizeof(nst_mempool_elem_t);

    snprintf (pool->name, NST_METPOOL_NAME_MAX, "%s", name);

    if (pool->pool_size) {
        pool->memsize = pool->elem_size * pool->pool_size;

        pool->membase = (char *) nst_xmalloc (pool->memsize);
        if (pool->membase == NULL) {
            Mempoolgstats.buffer_alloc_failed++;
            nst_free (pool);
            return NULL;
        }

        pool->mempool = NULL;
        for (i = 0; i < pool->pool_size; i++) {
            nst_mempool_elem_t   * elem = NULL;

            elem = (nst_mempool_elem_t *) (pool->membase + (i * pool->elem_size));
            elem->next = pool->mempool;
            elem->magic = 0;
            elem->source = 0;
            pool->mempool = elem;
        }
    }

    pool->lock = lock;

#ifdef THREADS_ENABLED
    if (pool->lock) {
        pthread_mutex_init (&pool->mutex, NULL);
    }
#endif

    Mempoolgstats.pools++;

    return pool;
}

static inline void * __nst_mempool_alloc (nst_mempool_t * pool)
{
    nst_mempool_elem_t  * elem = NULL;
    void           * m = NULL;
    int saved_errno = 0;

    if (pool->mempool) {
        elem = pool->mempool;
        pool->mempool = elem->next;
        elem->source = NST_METPOOL_METPOOL;
    }
    else {
        if (pool->meminuse >= pool->poolmax_size) {
            pool->stats.size_exceeded++;
        }
        else if (pool->malloc){
			elem = (nst_mempool_elem_t *)nst_xmalloc(pool->elem_size);
            saved_errno = errno;

			if (elem) {
				elem->source = NST_METPOOL_MALLOC;
				pool->malloc_size += pool->elem_size;
			}
			else {
				pool->stats.malloc_failed++;
				Mempoolgstats.malloc_failed++;
			}
		} else {
            saved_errno = ENOMEM;
        }
    }

    if (elem) {
        pool->stats.alloced++;
        pool->stats.outstanding_elems++;
        elem->magic = NST_METPOOL_ELEM_MAGIC;
        elem->next = NULL;
        m = (void *)(elem + 1);
        pool->meminuse += pool->elem_size;
    }
    else {
        Mempoolgstats.elem_alloc_failed++;
        pool->stats.malloc_failed++;
        errno = saved_errno;
    }

    return m;
}

static inline void __nst_mempool_free (nst_mempool_t * pool, void * m)
{
    nst_mempool_elem_t  * elem = NULL;

    elem = (nst_mempool_elem_t *)(((char *)m) - sizeof(nst_mempool_elem_t));

    NST_ASSERT(elem->magic == NST_METPOOL_ELEM_MAGIC);
    NST_ASSERT((elem->source == NST_METPOOL_METPOOL) ||
            (elem->source == NST_METPOOL_MALLOC));

    elem->magic = 0;
    if (elem->source == NST_METPOOL_METPOOL) {
        elem->next = pool->mempool;
        elem->source = 0;
        pool->mempool = elem;
        pool->stats.freed++;
    }
    else {
        pool->malloc_size -= pool->elem_size;
        pool->stats.mfreed--;
        nst_free (elem);
    }
    pool->meminuse -= pool->elem_size;

    pool->stats.outstanding_elems--;
}

void * nst_mempool_alloc (nst_mempool_t * pool)
{
    void * elem;

#ifdef THREADS_ENABLED
    if (pool->lock)
        pthread_mutex_lock(&pool->mutex);
#endif

    elem = __nst_mempool_alloc (pool);

#ifdef THREADS_ENABLED
    if (pool->lock)
        pthread_mutex_unlock (&pool->mutex);
#endif

    return elem;
}

void nst_mempool_free (nst_mempool_t * pool, void * m)
{
#ifdef THREADS_ENABLED
    if (pool->lock)
        pthread_mutex_lock (&pool->mutex);
#endif

    __nst_mempool_free (pool, m);

#ifdef THREADS_ENABLED
    if (pool->lock)
        pthread_mutex_unlock (&pool->mutex);
#endif
}

int nst_mempool_destroy (nst_mempool_t * pool)
{
#ifdef THREADS_ENABLED
    if (pool->lock)
        pthread_mutex_lock (&pool->mutex);
#endif

    if (pool->stats.outstanding_elems) {
        Mempoolgstats.outstanding_elems += pool->stats.outstanding_elems;

#ifdef THREADS_ENABLED
        if (pool->lock)
            pthread_mutex_unlock (&pool->mutex);
#endif

        return ERROR;
    }
    nst_xfree (pool->membase);
    pool->mempool = NULL;
    pool->malloc = 0;
    pool->pool_size = 0;

#ifdef THREADS_ENABLED
    if (pool->lock) {
        pthread_mutex_unlock (&pool->mutex);
        pthread_mutex_destroy (&pool->mutex);
    }
#endif

    bzero (pool, sizeof(nst_mempool_t));
    nst_free (pool);
    Mempoolgstats.destroyed++;

    return OK;
}

int nst_mempool_getoverhead ()
{
	return sizeof(nst_mempool_elem_t);
}

int nst_mempool_init ()
{
    if (Mempool_inited == 0) {
        bzero (&Mempoolgstats, sizeof(Mempoolgstats));
    }

    return OK;
}
