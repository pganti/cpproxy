/* We don't have itself, so nst_config.h should always be first here */
#include <nst_config.h>

/* libevent includes */
#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

/* nst core includes */
#include <nst_errno.h>
#include <nst_assert.h>
#include <nst_log.h>

/* sys and std includes */
#include <sys/types.h>
#include <sys/socket.h>

ssize_t
nst_unix_recvmsg(nst_connection_t *c,
                 struct msghdr *msghdr,
                 size_t total_buf_size,
                 int flags)
{
    ssize_t       n;
    int     saved_errno;
    nst_event_t  *rev;

    rev = c->read;

    if(!rev->ready) {
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s not ready",
                         nst_connection_get_brief_str(c));
        return NST_AGAIN;
    }

    while(1) {
        n = recvmsg(c->fd, msghdr, flags);
        saved_errno = errno;

        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                   (n == -1 && saved_errno != EAGAIN && saved_errno != EINTR ? 
                    NST_LOG_LEVEL_ERROR : NST_LOG_LEVEL_DEBUG),
                   "recvmsg(%ud,%Xd)=>%d%s: %s %s(%d)",
                   total_buf_size, flags, n,
                   n > 0 && msghdr->msg_flags & MSG_OOB ? "(OOB)" : "",
                   nst_connection_get_dbg_str(c),
                   n == -1 ? nst_strerror(saved_errno) : "no-errno",
                   n == -1 ? saved_errno : 0);

        if (n == 0) {
            rev->ready = 0;
            c->flags.io_eof = 1;
            return n;

        } else if (n > 0) {
            if ((size_t) n < total_buf_size
                && !(nst_event_flags & NST_USE_GREEDY_EVENT)
                && !(flags & MSG_PEEK)) {
                rev->ready = 0;
            }
            c->nread += n;
            return n;

        } else {
            if (saved_errno == EAGAIN) {
                rev->ready = 0;
                errno = saved_errno;
                return NST_AGAIN;
            } else if(saved_errno == EINTR) {
                continue;
            } else {
                nst_assert(saved_errno);
                rev->ready = 0;
                c->io_errno = saved_errno;
                NST_NOC_LOG_OV(c->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "recvmsg: %s %s(%ud).",
                               nst_connection_get_dbg_str(c),
                               nst_strerror(saved_errno), saved_errno);
                errno = saved_errno;
                return NST_ERROR;
            } /* if (saved_errno == EAGAIN) */

        } /* if (n == 0) */
    } /* while(1) */
}
