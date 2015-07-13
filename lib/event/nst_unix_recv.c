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
nst_unix_recv(nst_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    nst_event_t  *rev;
    int saved_errno;

    nst_assert(size > 0);

    rev = c->read;

    if(!rev->ready) {
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s not ready",
                         nst_connection_get_brief_str(c));
        return NST_AGAIN;
    }

    while(1) {
        n = recv(c->fd, buf, size, 0);
        saved_errno = errno;

        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                   (n == -1 && saved_errno != EAGAIN && saved_errno != EINTR ? 
                    NST_LOG_LEVEL_ERROR : NST_LOG_LEVEL_DEBUG),
                   "recv(%ud)=>%d: %s %s(%d)",
                   size, n,
                   nst_connection_get_dbg_str(c),
                   n == -1 ? nst_strerror(saved_errno) : "no-errno",
                   n == -1 ? saved_errno : 0);

        if (n > 0) {
            /* positive case */

            if ((size_t) n < size
                && !(nst_event_flags & NST_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

            c->nread += n;

            return n;
        } else if (n == 0) {
            /* negative case */
            rev->ready = 0;
            c->flags.io_eof = 1;
            return n;

        } else {
            /* n == -1 */
            /* negative case */
            if (saved_errno == EAGAIN) {
                rev->ready = 0;
                return NST_AGAIN;
            } else if (saved_errno == EINTR) {
                continue;
            } else {
                nst_assert(saved_errno);
                rev->ready = 0;
                NST_NOC_LOG_OV(c->dbg_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "recv: %s %s(%d).",
                               nst_connection_get_dbg_str(c),
                               nst_strerror(saved_errno), saved_errno);
                nst_connection_set_io_errno(c, saved_errno);
                errno = saved_errno;
                return NST_ERROR;
            }

        }
    }
}
