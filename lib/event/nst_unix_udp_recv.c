#include <nst_config.h>

#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

#include <nst_log.h>
#include <nst_errno.h>

ssize_t
nst_udp_unix_recv(nst_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    int           saved_errno;
    nst_event_t  *rev;

    rev = c->read;

    while(1) {
        n = recv(c->fd, buf, size, 0);
        saved_errno = errno;

        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "udp recv: t#:%ui c#:%ui fd:%d "
                         "read %d out of %d",
                         c->tid, c->number, c->fd,
                         n, size);

        if (n >= 0) {
            return n;

        } else {
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "udp recv: t#:%ui c#:%ui fd:%d "
                             "%s(%d)",
                             c->tid, c->number, c->fd,
                             nst_strerror(saved_errno), saved_errno);

            if(saved_errno == EAGAIN) {
                rev->ready = 0;
                return NST_AGAIN;
            } else if(saved_errno == EINTR) {
                continue;
            } else {
                NST_NOC_LOG_OV(c->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "udp recv: t#:%ui c#:%ui fd:%d "
                               "%s(%d)",
                               c->tid, c->number, c->fd,
                               nst_strerror(saved_errno), saved_errno);
                nst_connection_set_io_errno(c, saved_errno);
                rev->ready = 0;
                return NST_ERROR;
            }
        } 
    }
}
