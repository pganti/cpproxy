#include <nst_config.h>

#include "nst_unix_io_ops.h"

#include "nst_unix_close.h"
#include "nst_init_sockfd.h"
#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_connection.h"

#include <nst_sockaddr.h>
#include <nst_assert.h>
#include <nst_errno.h>

//nst_status_e nst_unix_close(nst_connection_t *c);

nst_status_e
nst_unix_connect(nst_connection_t **new_c,
                 nst_sockaddr_t *peer_sockaddr,
                 nst_sockaddr_t *local_sockaddr,
                 int tcp_ext,
                 nst_uint_t tid,
                 nst_log_level_t noc_log_lvl,
                 nst_log_level_t dbg_log_lvl)
{
    struct sockaddr_storage sa;
    socklen_t          socklen;
    int                rc;
    int                saved_errno;
    int                s = -1;
    nst_event_t       *rev, *wev;
    nst_connection_t  *c = NULL;

    s = socket(nst_sockaddr_get_family(peer_sockaddr), SOCK_STREAM, 0);

    if (s == -1) {
        NST_NOC_LOG_OV(noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "connect to %s:%s t#:%ui failed %s(%d)",
                       nst_sockaddr_get_ip_str(peer_sockaddr),
                       nst_sockaddr_get_port_str(peer_sockaddr),
                       tid,
                       nst_strerror(errno), errno);
        return NST_ERROR;
    }

    if(nst_init_sockfd(s, tcp_ext) == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "nst_unix_connect() to %s:%s failed. setsockops failed.",
                    nst_sockaddr_get_ip_str(peer_sockaddr),
                    nst_sockaddr_get_port_str(peer_sockaddr));
        goto ERR;
    }

    rc = bind(s,
              nst_sockaddr_get_sys_sockaddr(local_sockaddr),
              nst_sockaddr_get_sys_socklen(local_sockaddr));
    if(rc == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "connect to %s:%s for t#:%ui failed: cannot bind to local "
                    "sockaddr %s:%s. %s(%d)",
                    nst_sockaddr_get_ip_str(peer_sockaddr),
                    nst_sockaddr_get_port_str(peer_sockaddr),
                    tid,
                    nst_sockaddr_get_ip_str(local_sockaddr),
                    nst_sockaddr_get_port_str(local_sockaddr),
                    nst_strerror(errno), errno);
        goto ERR;
    }

    c = nst_get_connection(s);

    if (c == NULL) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "connect to %s:%s for t#:%ui failed: "
                    "cannot get nst_connection_t object",
                    nst_sockaddr_get_ip_str(peer_sockaddr), 
                    nst_sockaddr_get_port_str(peer_sockaddr),
                    tid);

        goto ERR;
    }

    c->type = NST_CONN_TYPE_TCP;
    c->tid = tid;
    c->noc_log_lvl = noc_log_lvl;
    c->dbg_log_lvl = dbg_log_lvl;
    c->io_ops = &nst_unix_io_ops;
    c->is_upstream = 1;

    rev = c->read;
    wev = c->write;

    if (nst_add_conn) {
        if (nst_add_conn(c) == NST_ERROR) {
            nst_unix_close(c, NST_IO_CLOSE_REASON_EVADD_FAILED);
            return NST_ERROR;
        }
    }

    NST_DEBUG_LOG_OV(dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "connect to %s:%s for t#:%ui c#:%ui, fd:%d",
                     nst_sockaddr_get_ip_str(peer_sockaddr),
                     nst_sockaddr_get_port_str(peer_sockaddr),
                     c->tid, c->number, c->fd);

    do {
        rc = connect(s,
                     nst_sockaddr_get_sys_sockaddr(peer_sockaddr),
                     nst_sockaddr_get_sys_socklen(peer_sockaddr));
    } while(rc == -1 && errno == EINTR);

    if (rc == -1) {
        saved_errno = errno;

        NST_DEBUG_LOG_OV(dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "connect to %s:%s for t#:%ui c#:%ui fd:%d => -1 "
                         "%s(%d)",
                         nst_sockaddr_get_ip_str(peer_sockaddr),
                         nst_sockaddr_get_port_str(peer_sockaddr),
                         c->tid, c->number, c->fd,
                         nst_strerror(saved_errno), saved_errno);

        if (saved_errno != EINPROGRESS) {
            NST_NOC_LOG_OV(noc_log_lvl,
                           NST_LOG_LEVEL_ERROR,
                           "connect to %s:%s failed for t#:%ui c#:%ui fd:%d. "
                           "%s(%d)",
                           nst_sockaddr_get_ip_str(peer_sockaddr),
                           nst_sockaddr_get_port_str(peer_sockaddr),
                           c->tid, c->number, c->fd,
                           nst_strerror(saved_errno), saved_errno);
            goto ERR;
        }
    }

    socklen = sizeof(sa);
    if(getsockname(s, (struct sockaddr *)&sa, &socklen) == -1) {
        NST_NOC_LOG_OV(noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "connect to %s:%s for t#:%ui c#:%ui fd:%d failed. "
                       "cannot getsockname. %s(%d)",
                       nst_sockaddr_get_ip_str(peer_sockaddr),
                       nst_sockaddr_get_port_str(peer_sockaddr),
                       c->tid, c->number, c->fd,
                       nst_strerror(errno), errno);
        goto ERR;
    }

    memcpy(&c->peer_sockaddr, peer_sockaddr, sizeof(c->peer_sockaddr));
    nst_sockaddr_init_by_sa(&c->local_sockaddr,
                            (struct sockaddr *)&sa,
                            socklen);
    if (nst_add_conn) {
        if (rc == -1) {

            /* NST_EINPROGRESS */
            *new_c = c;
            return NST_AGAIN;
        }

        NST_DEBUG_LOG_OV(dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "connect to %s:%s for %s is connected immediately",
                         nst_sockaddr_get_ip_str(peer_sockaddr),
                         nst_sockaddr_get_port_str(peer_sockaddr),
                         nst_connection_get_dbg_str(c));

        wev->ready = 1;
        *new_c = c;
        return NST_OK;
    }

    /* epoll should have done here */
    nst_assert(0 && "epoll implementation should not reach here");

    return NST_OK;

 ERR:
    if(c) {
        nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
    } else if(s != -1) {
        do {
            rc = close(s);
        } while(rc == -1 && errno == EINTR);
        if(rc == -1) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                          "cannot close fd:%d when connecting to %s:%s",
                          s,
                          nst_sockaddr_get_ip_str(peer_sockaddr),
                          nst_sockaddr_get_port_str(peer_sockaddr));
        }
    }
    return NST_ERROR;
}
