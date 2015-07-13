#include <nst_config.h>

#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

#include <nst_buf.h>
#include <nst_array.h>
#include <nst_log.h>

#include <sys/uio.h>
#include <limits.h>

#if (IOV_MAX > 64)
#define NST_IOVS  64
#else
#define NST_IOVS  IOV_MAX
#endif

ssize_t
nst_unix_writev_chain(nst_connection_t *c, nst_iochain_t *in)
{
    u_char        *prev;
    ssize_t        n, size, sending, sent, total_written, orig_data_len;
    int            saved_errno;
    nst_array_t    vec;
    nst_event_t   *wev;
    struct iovec  *iov, iovs[NST_IOVS];
    nst_iobuf_t   *iobuf;
    nst_iobuf_t   *tmp_iobuf;

    wev = c->write;

    if (!wev->ready) {
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s not ready",
                         nst_connection_get_brief_str(c));
        return NST_AGAIN;
    }
 
    orig_data_len = nst_iochain_get_data_len(in);
    if(!orig_data_len) {
        return 0;
    }

    total_written = 0;

    vec.elts = iovs;
    vec.size = sizeof(struct iovec);
    vec.nalloc = NST_IOVS;
    vec.pool = c->pool;

    for ( ;; ) {
        prev = NULL;
        iov = NULL;

        vec.nelts = 0;

        sending = 0;

        /* create the iovec and coalesce the neighbouring bufs */
        STAILQ_FOREACH(iobuf, &in->iobuf_queue, queue_entry) {
            if(vec.nelts >= NST_IOVS)
                break;

            nst_assert(!iobuf->flags.io_eof);
            size = nst_iobuf_data_len(iobuf);

            if(prev == iobuf->pos) {
                iov->iov_len += size;
            } else {
                iov = nst_array_push(&vec);
                if (iov == NULL) {
                    NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                                "cannot create iov %s(%d)",
                                nst_strerror(errno), errno);
                    return NST_ERROR;
                }

                iov->iov_base = iobuf->pos;
                iov->iov_len = size;
            }

            prev = iobuf->pos + size;
            sending += size;
        }

        do {
            n = writev(c->fd, vec.elts, vec.nelts);
            saved_errno = errno;
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                   (n == -1 && saved_errno != EAGAIN && saved_errno != EINTR ? 
                    NST_LOG_LEVEL_ERROR : NST_LOG_LEVEL_DEBUG),
                   "writev(%ud)=>%d: %s %s(%d)",
                   sending, n,
                   nst_connection_get_dbg_str(c),
                   n == -1 ? nst_strerror(saved_errno) : "no-errno",
                   n == -1 ? saved_errno : 0);
        } while(n == -1 && saved_errno == EINTR);

        if (n > 0) {
            c->nsent += n;
            total_written += n;
            sent = n;

        } else if (n == 0) {
            wev->ready = 0;
            return total_written ? total_written : NST_AGAIN;

        } else {
            nst_assert(saved_errno != EINTR);
            if(saved_errno == EAGAIN) {
                wev->ready = 0;
                return total_written ? total_written : NST_AGAIN;
            } else {
                nst_connection_set_io_errno(c, saved_errno);
                errno = saved_errno;
                return NST_ERROR;
            }

        }

        nst_assert(n > 0);

        STAILQ_FOREACH_SAFE(iobuf, &in->iobuf_queue, queue_entry, tmp_iobuf) {
            if (sent == 0) {
                break;
            }

            size = iobuf->last - iobuf->pos;

            if (sent >= size) {
                sent -= size;
                nst_assert(sent >= 0);
                nst_iochain_remove_first(in);
                iobuf->pos = iobuf->last;
                nst_iobuf_free(iobuf);
                continue;
            } else {
                iobuf->pos += sent;
                break;
            }
        } /* STAILQ_FOREACH_SAFE */

        /* Even tough sent < sending, we still have to write till 
         * EAGAIN because:
         *
         * man 7 signal:
         *   If  a blocked call to one of the following interfaces
         *   is interrupted by a signal handler, then the call will
         *   be automatically restarted after the signal handler returns
         *   if the SA_RESTART flag was used; otherwise the call will fail
         *   with the error EINTR:

           * read(2), readv(2), write(2), writev(2),  and  ioctl(2)  calls  on
             "slow"  devices.   A  "slow" device is one where the I/O call may
             block for an indefinite time, for example, a terminal,  pipe,  or
             socket.   (A  disk is not a slow device according to this defini-
             tion.)  If an I/O call on a slow device has  already  transferred
             some data by the time it is interrupted by a signal handler, then
             the call will return a success status (normally,  the  number  of
             bytes transferred).
        */
        if(total_written == orig_data_len) {
            return total_written;
        }
    } /* for ( ;; ) */
}
