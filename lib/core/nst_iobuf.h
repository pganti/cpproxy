#ifndef _NST_IO_BUF_H_
#define _NST_IO_BUF_H_

#include "nst_config.h"

#include "queue.h"
#include "nst_refcount.h"
#include "nst_types.h"

#include <sys/types.h>
#include <stddef.h>

#define NST_IOBUF_DEFAULT_SIZE        (10 * 1024)
#define NST_IOBUF_COALESCE_MAX_SIZE   (1024 * 1024)

struct nst_pool_s;
typedef struct nst_iobuf_s        nst_iobuf_t;
typedef struct nst_iochain_s      nst_iochain_t;

struct nst_iobuf_s {
    u_char          *pos;           /* start of app data          */
    u_char          *last;          /* +1 after the app data      */

    u_char          *start;         /* start of buffer            */
    u_char          *end;           /* +1 after the end of buffer */

    struct nst_pool_s      *pool;   /* the pool that allocated this
                                     * nst_iobuf_s and the memory pointed
                                     * by 'start' pointer.
                                     */

    struct {
        unsigned     io_eof:1;
        unsigned     no_free:1;        /* do not free the memory pointed
                                        * by 'start' pointer
                                        */
        unsigned     palloc_large:1;    /* is it in pool->large? */
    } flags;

    STAILQ_ENTRY(nst_iobuf_s) queue_entry;
    NST_REFC_CTX_DEF;              /* ref counting the how many nst_iochain_t
                                    * has linked to this iobuf.
                                    * the last one is responsible to free
                                    * the iobuf and memory pointed by
                                    * iobuf->start.
                                    */
};

extern nst_iobuf_t nst_iobuf_eof;

STAILQ_HEAD(nst_iobuf_queue_s, nst_iobuf_s);
struct nst_iochain_s {
    size_t nbufs;
    size_t buf_size;
    struct nst_iobuf_queue_s iobuf_queue;
};

#define NST_IOCHAIN_ERROR     (nst_iochain_t *) NST_ERROR

static inline size_t
nst_iochain_get_nbufs(const nst_iochain_t *iochain)
{
    return iochain->nbufs;
}

static inline size_t
nst_iochain_get_buf_size(const nst_iochain_t *iochain)
{
    return iochain->buf_size;
}

static inline void
nst_iochain_init(nst_iochain_t *iochain)
{
    iochain->nbufs = 0;
    iochain->buf_size = 0;
    STAILQ_INIT(&iochain->iobuf_queue);
}

static inline nst_iobuf_t *
nst_iochain_get_last(nst_iochain_t *iochain)
{
    return STAILQ_LAST(&iochain->iobuf_queue, nst_iobuf_s, queue_entry);
}

static inline nst_iobuf_t *
nst_iochain_get_first(nst_iochain_t *iochain)
{
    return STAILQ_FIRST(&iochain->iobuf_queue);
}

static inline bool
nst_iochain_is_empty(const nst_iochain_t *iochain)
{
    return STAILQ_ETPTY(&iochain->iobuf_queue);
}

#define nst_iobuf_buf_size(b)       (size_t)((b)->end - (b)->start)
#define nst_iobuf_data_len(b)       (size_t)((b)->last - (b)->pos)
#define nst_iobuf_read_buf_size(b)  nst_iobuf_data_len(b)
#define nst_iobuf_write_buf_size(b) (size_t)((b)->end - (b)->last)

#define nst_iobuf_data_wptr(b) b->last
#define nst_iobuf_data_rptr(b) b->pos

#define nst_iobuf_consumed(b, len) do { b->pos += len; } while (0)
#define nst_iobuf_add(b, len) do { b->last += len; } while (0)


nst_iobuf_t *nst_iobuf_new(struct nst_pool_s *pool, size_t size);
nst_iobuf_t *nst_iobuf_new_temp(struct nst_pool_s *pool, size_t size);
void         nst_iobuf_free(nst_iobuf_t *iobuf);
nst_iobuf_t *nst_iobuf_create_eof(struct nst_pool_s *pool);
nst_iobuf_t *nst_iobuf_shadow_clone(nst_iobuf_t *src_iobuf);

nst_iobuf_t *nst_iochain_remove_first(nst_iochain_t *iochain);
nst_iobuf_t *nst_iochain_remove_first_if_avail(nst_iochain_t *iochain);
void nst_iochain_free(nst_iochain_t *iochain);
int nst_iobuf_coalesce (struct nst_pool_s * pool, nst_iochain_t * chain);
size_t nst_iobuf_chain_data_len (nst_iochain_t * chain);
int nst_iochain_data_append (struct nst_pool_s * pool, nst_iochain_t * chain, int len, const char * src);
int nst_iobuf_vsnprintf (struct nst_pool_s * pool, nst_iochain_t * chain, const char * fmt, ...);
void nst_iobuf_chain_merge (nst_iochain_t * src, nst_iochain_t * dest);
void nst_iochain_free_consumed (nst_iochain_t * chain);
int nst_iobuf_coalesce_len (struct nst_pool_s * pool, int len, nst_iochain_t * chain);

static inline void
nst_iochain_append(nst_iochain_t *iochain, nst_iobuf_t *iobuf)
{
    STAILQ_INSERT_TAIL(&iochain->iobuf_queue, iobuf, queue_entry);
    iochain->nbufs++;
    iochain->buf_size += nst_iobuf_buf_size(iobuf);
}


static inline void
nst_iochain_insert_head(nst_iochain_t *iochain, nst_iobuf_t *iobuf)
{
    STAILQ_INSERT_HEAD(&iochain->iobuf_queue, iobuf, queue_entry);
    iochain->nbufs++;
    iochain->buf_size += nst_iobuf_buf_size(iobuf);
}
static inline void
nst_iochain_concat(nst_iochain_t *dst, nst_iochain_t *src)
{
    STAILQ_CONCAT(&dst->iobuf_queue, &src->iobuf_queue);
    dst->nbufs += src->nbufs;
    dst->buf_size += src->buf_size;
    src->nbufs = src->buf_size = 0;
}

static inline size_t
nst_iochain_get_data_len(const nst_iochain_t *iochain)
{
    nst_iobuf_t *iobuf;
    size_t  data_len = 0;

    STAILQ_FOREACH(iobuf, &iochain->iobuf_queue, queue_entry) {
        data_len += nst_iobuf_data_len(iobuf);
    }

    return data_len;
}

static inline void
nst_iochain_remove_last(nst_iochain_t *iochain)
{
    nst_iobuf_t *last_iobuf;

    if( (last_iobuf = STAILQ_LAST(&iochain->iobuf_queue,
                                  nst_iobuf_s,
                                  queue_entry)) ) {
        STAILQ_REMOVE(&iochain->iobuf_queue, last_iobuf,
                      nst_iobuf_s, queue_entry);
        iochain->nbufs--;
        iochain->buf_size -= nst_iobuf_buf_size(last_iobuf);
    }
}

#endif /* _NST_IOBUF_H_ */
