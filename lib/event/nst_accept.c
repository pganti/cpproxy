#include "nst_accept.h"

#include "nst_event_int.h"
#include "nst_event.h"
#include "nst_cfg_svc.h"
#include "nst_connection.h"
#include "nst_tp_connection.h"
#include "nst_event.h"
#include "nst_init_sockfd.h"
#include "nst_unix_close.h"

#include <nst_mempool.h>
#include <nst_palloc.h>
#include <nst_assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

static inline nst_listener_t *
nst_listener_new(void)
{
    return nst_allocator_calloc(&event_ctx.allocator,
                                1,
                                sizeof(nst_listener_t));
}

static inline void
nst_listener_free(nst_listener_t *listener)
{
    nst_allocator_free(&event_ctx.allocator, listener);
}

static void nst_close_accepted_connection(nst_connection_t *c)
{
    int fd;
    int rc;

    fd = c->fd;
    c->fd = -1;
    do {
        rc = close(fd);
    } while(rc == -1 && errno == EINTR);

    if(rc == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot close newly accepted connection fd:%d. %s(%d)",
                    fd, nst_strerror(errno), errno);
    }

    if(c->svc)
        nst_cfg_svc_free(c->svc);

    if(c->pool)
        nst_destroy_pool(c->pool);

    nst_free_connection(c);
}

static void
nst_event_accept(nst_event_t *ev)
{
    struct sockaddr_storage sa;
    socklen_t          socklen;
    int                saved_errno;
    int                s;
    nst_cfg_svc_t     *svc;
    nst_event_t       *rev, *wev;
    nst_listener_t    *ls;
    nst_connection_t  *lc;
    nst_connection_t  *c;            /* newly accepted connection */
    nst_uint_t          naccepted;
    nst_uint_t          naccepts_per_loop;

    lc = (nst_connection_t *)ev->data;
    ls = (nst_listener_t *)lc->data;
    svc = ls->svc;

    NST_DEBUG_LOG_OV(svc->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "accept() on %s:%s for service %s",
                     nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                     nst_sockaddr_get_port_str(&lc->local_sockaddr),
                     svc->name);

    naccepts_per_loop = svc->naccepts_per_loop;

    for(naccepted = 0;
        naccepted < naccepts_per_loop;
        naccepted++) {

        socklen = sizeof(sa);

        sa.ss_family = AF_UNSPEC;
        s = accept(lc->fd, (struct sockaddr *) &sa, &socklen);
        saved_errno = errno;

        if (s == -1) {
            NST_DEBUG_LOG_OV(svc->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "accept(c#:%ui fd:%d %s:%s)=>-1 %s(%d)",
                             lc->number, lc->fd,
                             nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                             nst_sockaddr_get_port_str(&lc->local_sockaddr),
                             nst_strerror(saved_errno), saved_errno);
            if (saved_errno == EAGAIN) {
                ev->ready = 0;
                nst_handle_read_event(ev, 0);
                return;

            } else if(saved_errno == EINTR) {
                /* ...I know you are yelling about what if naccepted == 0.
                 * it is fine...naccepted++ will change it back
                 * to 0 safely
                 */
                naccepted--; /* don't count this iteration */
                continue;

            } else if(saved_errno == ECONNABORTED) { 
                NST_NOC_LOG_OV(svc->noc_log_lvl,
                               NST_LOG_LEVEL_DEBUG,
                               "accept(c#:%ui fd:%d %s:%s)=>-1. "
                               "peer aborted the connection. "
                               "%s(%d)",
                               lc->number, lc->fd,
                               nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                               nst_sockaddr_get_port_str(&lc->local_sockaddr),
                               nst_strerror(saved_errno), saved_errno);
                continue;
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "accept(c#:%ui fd:%d %s:%s) failed. "
                            "%s(%d)",
                            lc->number, lc->fd,
                            nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                            nst_sockaddr_get_port_str(&lc->local_sockaddr),
                            nst_strerror(saved_errno), saved_errno);

                nst_assert(saved_errno != EINVAL);
                nst_assert(saved_errno != EBADF);
                nst_assert(saved_errno != EFAULT);

                if(saved_errno == EMFILE || saved_errno == ENFILE
                   || saved_errno == ENOBUFS || saved_errno == ENOMEM) {
                    /* not accepting anymore now to see if we can 
                     * process other events first which may free up
                     * some resources
                     */
                    break;
                } else {
                    continue;
                }
            } /* if(saved_errno == EAGAIN) */
        } /* if(s == -1) */

        nst_assert(s != -1);
        nst_assert(sa.ss_family != AF_UNSPEC);

        if(nst_init_sockfd(s, svc->tcp_ext) == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "nst_accept(c#:%ui fd:%d %s:%s) failed. "
                        "setsockops failed.",
                        lc->number, lc->fd,
                        nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                        nst_sockaddr_get_port_str(&lc->local_sockaddr));
                break;
        }

        if(svc->type == NST_SVC_TYPE_TP
           && nst_init_tp_sockfd(s) == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "nst_accept(c#:%ui fd:%d %s:%s) failed. "
                        "mp setsockops failed.",
                        lc->number, lc->fd,
                        nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                        nst_sockaddr_get_port_str(&lc->local_sockaddr));
            break;
        }


        c = nst_get_connection(s);

        if (c == NULL) {
            int rc;
            do {
                rc = close(s);
            } while(rc == -1 && errno == EINTR);
            
            if(rc == -1) {
                NST_NOC_LOG_OV(svc->noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "error when closing accepted socket fd:%d. "
                               "%s(%d)",
                               s, nst_strerror(errno), errno);
            }
            continue;
        }

        /* -start- init c */
        /* ML on NGX:  the default pool_size is 256 */ 
        c->pool = nst_create_pool(event_ctx.cfg.connection_pool_size,
                                  &nst_dl_logger);
        if (c->pool == NULL) {
            NST_NOC_LOG_OV(svc->noc_log_lvl,
                           NST_LOG_LEVEL_ERROR,
                           "cannot allocate pool for new connection "
                           "accepted from %s:%s. %s(%d)",
                           nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                           nst_sockaddr_get_port_str(&lc->local_sockaddr),
                           nst_strerror(errno), errno);
            nst_close_accepted_connection(c);
            break;
        }

        nst_sockaddr_init_by_sa(&c->peer_sockaddr, (struct sockaddr *)&sa, socklen);
        memcpy(&c->local_sockaddr, &lc->local_sockaddr,
               sizeof(c->local_sockaddr));

        /* TODO: SSL ops */
        switch(svc->type) {
        case NST_SVC_TYPE_TP:
            c->io_ops = &nst_tp_io_ops;
            break;
        default:
            c->io_ops = &nst_unix_io_ops;
        };

        rev = c->read;
        wev = c->write;

        wev->ready = 1;

        if (nst_event_flags & (NST_USE_AIO_EVENT|NST_USE_RTSIG_EVENT)) {
            /* rtsig, aio, iocp */
            rev->ready = 1;
        }

        /* ML on NGX: deferred_accept should be always on on linux 2.6 */
        if (svc->deferred_accept) {

            rev->ready = 1;
#if (NST_HAVE_KQUEUE)
            rev->available = 1;
#endif
        }

        /* init connection cfg from svc */
        c->noc_log_lvl = svc->noc_log_lvl;
        c->dbg_log_lvl = svc->dbg_log_lvl;

        if(svc->type == NST_SVC_TYPE_TP) {
            c->type = NST_CONN_TYPE_TP;
        } else {
            c->type = NST_CONN_TYPE_TCP;
        }

        c->data = ls;

        c->svc = svc;
        NST_REFC_GET(svc);

        /* ML on NGX:
         * instead of having this kind of EPOLL and KQUEUE checks everywhere,
         * should they be abstracted???
         * so far...I don't have very good impression on NGX
         * code/data encapsulation
         */

        /* ML on NGX:
         * For epoll, the app is responsible to call
         * nst_handle_????_event to register for interested event.
         */

        if ((nst_event_flags & NST_USE_EPOLL_EVENT) == NST_USE_EPOLL_EVENT &&
            nst_add_conn) {
            if (nst_add_conn(c) == NST_ERROR) {
                nst_close_accepted_connection(c);
                return;
            }
        }
        /* -end- init c */

        NST_DEBUG_LOG_OV(svc->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "accept(c#:%ui fd:%d %s:%s)=>new TCP: %s",
                         lc->number, lc->fd,
                         nst_sockaddr_get_ip_str(&lc->local_sockaddr),
                         nst_sockaddr_get_port_str(&lc->local_sockaddr),
                         nst_connection_get_dbg_str(c));

        ls->svc->handler(c);

    } /*     for(naccepted = 0; */

    /* We have too many pending accept and it exceeds the
     * event_cfg.ctx.max_naccepts_per_loop OR
     * some error happened and need to retry later.
     * 
     * Put it to postponed_queue
     * for processing during next event loop.
     */
    if(lc->read->ready) {
        nst_event_postpone(lc->read);
    }
}

nst_status_e
nst_event_add_listener(nst_cfg_svc_t *svc)
{
    nst_event_t *rev;
    nst_connection_t *lc = NULL;
    nst_listener_t *ls = NULL;
    int fd = -1;
    int reuseaddr = 1;
    int ret = NST_OK;
    int tcp_accept_timeout;

    nst_assert(svc->listener == NULL);

    /* - start - setting up socket */
    fd = socket(nst_sockaddr_get_family(&svc->listen_sockaddr),
                SOCK_STREAM, 0);
    if(fd == -1) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "cannot create nst_listener_t socket %s:%s for service %s",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       svc->name);
        return NST_ERROR;
    }

    if(nst_init_sockfd(fd, svc->tcp_ext) == NST_ERROR) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "listening on %s:%s failed. setsockops failed.",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr));
        return NST_ERROR;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(reuseaddr)) == -1) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "listening on %s:%s failed. "
                       "setsockopt(SO_REUSEADDR) failed. %s(%ud)",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       nst_strerror(errno), errno);
        ret = NST_ERROR;
        goto DONE;
    }

    tcp_accept_timeout = svc->post_accept_timeout_ms / 1000;
    if (svc->deferred_accept) {
        if(setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                      &tcp_accept_timeout, sizeof(tcp_accept_timeout)) == -1) {
            NST_NOC_LOG_OV(svc->noc_log_lvl,
                           NST_LOG_LEVEL_ERROR,
                           "listening on %s:%s failed. "
                           "setsockopt(TCP_DEFER_ACCEPT) failed. %s(%d)",
                           nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                           nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                           nst_strerror(errno), errno);
            ret = NST_ERROR;
            goto DONE;
        }
    }

    if(bind(fd,
            nst_sockaddr_get_sys_sockaddr(&svc->listen_sockaddr),
            nst_sockaddr_get_sys_socklen(&svc->listen_sockaddr)) == -1) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "listening on %s:%s failed. bind() failed. %s(%d)",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       nst_strerror(errno), errno);
        ret = NST_ERROR;
        goto DONE;
    }

    if(listen(fd, svc->backlog) == -1) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "listen() on %s:%s failed. %s(%d)",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       nst_strerror(errno), errno);
        ret = NST_ERROR;
        goto DONE;
    }
    /* - end - setting up socket */

    /* create nst_listener_t */
    ls = nst_listener_new();
    if(!ls) {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "listening on %s:%s failed. "
                       "cannot create nst_listener_t %s(%d)",
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       nst_strerror(errno), errno);
        ret = NST_ERROR;
        goto DONE;
    }

    /* create nst_connection_t */
    lc = nst_get_connection(fd);
    if(!lc) {
        ret = NST_ERROR;
        goto DONE;
    }

    /* - start - init lc */
    lc->type = (svc->type == NST_SVC_TYPE_TP) ? NST_CONN_TYPE_TP : NST_CONN_TYPE_TCP;
    lc->fd = fd;
    fd = -1; /* lc took the ownership */
    memcpy(&lc->local_sockaddr, &svc->listen_sockaddr,
           sizeof(lc->local_sockaddr));
    lc->data = ls;
    rev = lc->read;
    rev->ready = 1;
    rev->accept = 1;
    rev->handler = nst_event_accept;
    TAILQ_INSERT_TAIL(&event_ctx.postponed_queue,
                      lc->read,
                      queue_entry);
    /* - end - init lc */

    /* - start - init ls */
    ls->svc = svc;
    ls->conn = lc;
    lc = NULL; /* ls->conn took the ownership */
    svc->listener = ls;
    /* - end - init ls */

 DONE:
    if(ret == NST_ERROR) {
        if(fd != -1) {
            while(close(fd) == -1 && errno == EINTR) {}
        }
        if(lc) {
            nst_unix_close(lc, NST_IO_CLOSE_REASON_OK);
        }
        if(ls) {
            nst_listener_free(ls);
        }
        svc->listener = NULL;
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_ERROR,
                       "service %s cannot listen on %s:%s",
                       svc->name,
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr));
        return NST_ERROR;
    } else {
        NST_NOC_LOG_OV(svc->noc_log_lvl,
                       NST_LOG_LEVEL_INFO,
                       "service \"%s\" is listening on %s:%s with c#:%ui",
                       svc->name,
                       nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                       nst_sockaddr_get_port_str(&svc->listen_sockaddr),
                       ls->conn->number);
        return NST_OK;
    }
}

void
nst_event_del_listener(nst_cfg_svc_t *svc)
{
    nst_listener_t *ls;
    nst_connection_t *lc;

    if(svc->listener == NULL)
        return;

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "removed service \"%s\" from listening socket. "
                "pending to-be-accepted connection may be affected.",
                svc->name);

    ls = svc->listener;
    lc = ls->conn;

    nst_unix_close(lc, NST_IO_CLOSE_REASON_OK);
    nst_listener_free(ls);

    svc->listener = NULL;
}
