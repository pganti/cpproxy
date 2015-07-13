#include <nst_config.h>

#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

#include <nst_buf.h>
#include <nst_array.h>
#include <nst_log.h>

#include <sys/uio.h>

#define NST_IOVS  16

ssize_t
nst_unix_readv_chain(nst_connection_t *c, nst_chain_t *chain)
{
    u_char        *prev;
    ssize_t        n, size;
    int            saved_errno;
    nst_array_t    vec;
    nst_event_t   *rev;
    struct iovec  *iov, iovs[NST_IOVS];

    prev = NULL;
    iov = NULL;
    size = 0;

    vec.elts = iovs;
    vec.nelts = 0;
    vec.size = sizeof(struct iovec);
    vec.nalloc = NST_IOVS;
    vec.pool = c->pool;

    /* coalesce the neighbouring bufs */

    while (chain) {
        if (prev == chain->buf->last) {
            iov->iov_len += chain->buf->end - chain->buf->last;

        } else {
            iov = nst_array_push(&vec);
            if (iov == NULL) {
                return NST_ERROR;
            }

            iov->iov_base = (void *) chain->buf->last;
            iov->iov_len = chain->buf->end - chain->buf->last;
        }

        size += chain->buf->end - chain->buf->last;
        prev = chain->buf->end;
        chain = chain->next;
    }

    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "readv: t#:%ui c#:%ui fd:%d "
                     "%d:%d",
                     c->tid, c->number, c->fd,
                     vec.nelts, iov->iov_len);

    rev = c->read;

    while(1) {
        n = readv(c->fd, (struct iovec *) vec.elts, vec.nelts);
        saved_errno = errno;
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "readv: t#:%ui c#:%ui fd:%d "
                         "returns n=%d",
                         c->tid, c->number, c->fd,
                         n);

        if (n > 0) {
            /* Positive case */
            if (n < size && !(nst_event_flags & NST_USE_GREEDY_EVENT)) {
                rev->ready = 0;
            }
            return n;

        } else if (n == 0) {
            /* Negative case */
            rev->ready = 0;
            c->flags.io_eof = 1;
            return n;

        } else {
            /* Negative case */
            /* n == -1 */
            nst_assert(saved_errno);
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "readv: t#:%ui c#:%ui fd:%d "
                             "%s(%d)",
                             c->tid, c->number, c->fd,
                             nst_strerror(saved_errno), saved_errno);
            if(saved_errno == EAGAIN) {
                rev->ready = 0;
                errno = saved_errno;
                return NST_AGAIN;
            } else if(saved_errno == EINTR) {
                continue;
            } else {
                NST_NOC_LOG_OV(c->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "readv: t#:%ui c#:%ui fd:%d "
                               "%s(%d)",
                               c->tid, c->number, c->fd,
                               nst_strerror(saved_errno), saved_errno);
                c->io_errno = saved_errno;
                rev->ready = 0;
                errno = saved_errno;
                return NST_ERROR;
            } /* if(saved_errno == EAGAIN) */
        } /* if(n > 0) */
    } /* while(1) */
}
