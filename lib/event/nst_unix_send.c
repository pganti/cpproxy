/* We don't have itself, so nst_config.h should always be first here */
#include <nst_config.h>

/* libevent includes */
#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

/* nst core includes */
#include <nst_assert.h>
#include <nst_log.h>
#include <nst_errno.h>

/* sys and std includes */
#include <sys/types.h>
#include <sys/socket.h>

ssize_t
nst_unix_send(nst_connection_t *c,
              const u_char *buf,
              size_t size,
              int flags)
{
    ssize_t       n;
    ssize_t       total_written;
    int           saved_errno;
    nst_event_t  *wev;

    wev = c->write;
    if(!wev->ready) {
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s not ready",
                         nst_connection_get_brief_str(c));
        return NST_AGAIN;
    }

    nst_assert(size > 0);

    total_written = 0;
    for ( ;; ) {
        n = send(c->fd, buf + total_written, size - total_written, flags);
        saved_errno = errno;

        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                   (n == -1 && saved_errno != EAGAIN && saved_errno != EINTR ? 
                    NST_LOG_LEVEL_ERROR : NST_LOG_LEVEL_DEBUG),
                   "send(%d(%ud - %d), %Xd)=>%d: %s %s(%d)",
                   (ssize_t)size - total_written, size, total_written, flags, n,
                   nst_connection_get_dbg_str(c),
                   n == -1 ? nst_strerror(saved_errno) : "no-errno",
                   n == -1 ? saved_errno : 0);

        if (n > 0) {
        /* We have to write till EAGAIN because:
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

            total_written += n;
            c->nsent += n;
            if(total_written == (ssize_t)size)
                return size;
            else
                continue;

        } else if (n == 0) {
            wev->ready = 0;
            return total_written ? total_written : NST_AGAIN;

        } else {
            /* n == -1 */
            if(saved_errno == EINTR) {
                continue;
            } else if (saved_errno == EAGAIN) {
                wev->ready = 0;
                return total_written ? total_written : NST_AGAIN;

            } else {
                c->io_errno = saved_errno;
                errno = saved_errno;
                return NST_ERROR;
            }

        } /* else { n == -1 */

    }
}
