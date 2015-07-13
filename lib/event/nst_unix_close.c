#include <nst_config.h>

#include "nst_io_ops.h"
#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"
#include "nst_event.h"

#include <nst_palloc.h>
#include <nst_types.h>
#include <nst_errno.h>
#include <nst_log.h>
#include <nst_timer.h>

#include <unistd.h>

nst_status_e
nst_unix_close(nst_connection_t *c, nst_io_close_reason_e reason)
{
    int n;
    int saved_errno;
    int fd;

    if(c->fd == -1) {
        NST_NOC_LOG_OV(c->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "t#:%ui c#:%ui has alread closed",
                       c->tid, c->number);
        return NST_OK;
    }

    nst_event_del_timer(c->read);
    nst_event_del_timer(c->write);
    nst_event_clear_timedout(c->read);
    nst_event_clear_timedout(c->write);

    if (nst_del_conn) {
        /* NGX: for epoll, we will always hit this case */
        nst_del_conn(c, NST_CLOSE_EVENT);

    } else {
        if (c->read->active || c->read->disabled) {
            nst_del_event(c->read, NST_READ_EVENT, NST_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            nst_del_event(c->write, NST_WRITE_EVENT, NST_CLOSE_EVENT);
        }
    }

    c->flags.closed = 1;

    if(c->is_upstream == 1) {
        nst_assert(!c->pool);
    } else {
        if(c->pool) {
            nst_destroy_pool(c->pool);
            c->pool =  NULL;
        }
    }
        
    nst_free_connection(c);

    fd = c->fd;
    c->fd = -1;

    while(TRUE) {
        n = close(fd);
        saved_errno = errno;

        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "close(t#:%ui c#:%ui fd:%d)=>%d",
                         c->tid, c->number, fd, n);

        if(n == 0) {
            return NST_OK;
        } else {
            NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "close: t#:%ui c#:%ui fd:%d %s(%d)",
                             c->tid, c->number, c->fd,
                             nst_strerror(saved_errno), saved_errno);
            if(saved_errno == EINTR) {
                continue;
            } else {
                NST_NOC_LOG_OV(c->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "close(t#:%ui c#:%ui fd:%d) failed. %s(%d)",
                               c->tid, c->number, c->fd,
                               nst_strerror(saved_errno), saved_errno);
                nst_connection_set_io_errno(c, saved_errno);
                return NST_ERROR;
            }
        } /* if(n == 0) */
    } /* while(1) */
}
