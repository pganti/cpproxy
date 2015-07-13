#include <nst_config.h>

#include "nst_connection.h"

#include <nst_errno.h>
#include <nst_assert.h>

#include <sys/socket.h>

nst_status_e
nst_unix_shutdown(nst_connection_t *c)
{
    int n;
    int saved_errno;

    n = shutdown(c->fd, SHUT_WR);
    saved_errno = errno;

    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "shutdown: t#:%ui c#:%ui fd:%d n=%d",
                     c->tid, c->number, c->fd,
                     n);

    c->flags.shutdown = 1;
    
    if(n == 0) {
        return NST_OK;
    } else {
        nst_assert(saved_errno != EINTR);
        NST_NOC_LOG_OV(c->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "shutdown: t#:%ui c#:%ui fd:%d %s(%d)",
                       c->tid, c->number, c->fd,
                       nst_strerror(saved_errno), saved_errno);
        nst_connection_set_io_errno(c, saved_errno);
        return NST_ERROR;
    }
}
