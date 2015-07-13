#include <nst_mempool.h>
#include <nst_palloc.h>
#include <nst_assert.h>
#include "nst_event_int.h"
#include "nst_event.h"
#include "nst_cfg_svc.h"
#include "nst_connection.h"
#include "nst_tp_connection.h"
#include "nst_init_sockfd.h"
#include "nst_connect.h"
#include "nst_unix_close.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>


static void nst_connect_write_event (nst_event_t * wev);

static void
nst_connect_read_event (nst_event_t * rev)
{
    nst_connect_write_event (rev);
}

static void
nst_connect_write_event (nst_event_t * wev)
{
    int                       rc;
    nst_connection_t        * c;
    nst_connect_context_t   * ctx;

    c = wev->data;
    ctx = c->data;
    
    if (ctx == NULL) {
        return;
    }

    if (nst_event_is_timedout(wev) == TRUE) {
        c->data = NULL;
        nst_unix_close (c, NST_IO_CLOSE_REASON_TIMEDOUT);
        ctx->error = ETIMEDOUT;
        ctx->cbf (NST_CONNECT_STATUS_TIMEOUT, NULL, ctx);
        return;
    }

    rc = connect(c->fd, nst_sockaddr_get_sys_sockaddr(&ctx->peer_sockaddr),
                 nst_sockaddr_get_sys_socklen(&ctx->peer_sockaddr));
    
    if (rc < 0) {
        int saved_errno = errno;
        if (saved_errno == EINPROGRESS) {
            /* In progress */
            return;
        }
        else {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            ctx->error = saved_errno;
            ctx->cbf (NST_CONNECT_STATUS_EQADD_FAILED, NULL, ctx);
            return;
        }
    }
    else if (rc == 0) {
        return nst_connect_connected (c);
    }
    else {
        NST_ASSERT (0);
    }
}

void
nst_connect_connected (nst_connection_t * c)
{
    nst_connect_context_t   * ctx;
    struct sockaddr_storage   sa;
    socklen_t                 socklen = sizeof(struct sockaddr_storage);

    if (c->flags.connected == 1)
        return;
    
    ctx = c->data;
    if(getsockname(c->fd, (struct sockaddr *)&sa, &socklen) == -1) {
        ctx->error = errno;
        nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
        ctx->cbf (NST_CONNECT_STATUS_SOCKNAME_FAILED, NULL, ctx);
        return;
    }

    nst_sockaddr_init_by_sa(&c->local_sockaddr, (struct sockaddr *)&sa,
                            socklen);

    c->flags.connected = 1;
    c->data = NULL;
    ctx->cbf (NST_CONNECT_STATUS_CONNECTED, c, ctx);
}

void
nst_connect_cb (int dobind, nst_conn_type_e  type, nst_connect_context_t * ctx)
{
    int                rc;
    int                s=0;
    nst_connection_t  *c;
    int                proto = 0;
    nst_sockaddr_t    * peer;
        
    ctx->error = 0;
    c = nst_get_connection(s);
    if (c == NULL) {
        ctx->cbf (NST_CONNECT_STATUS_MALLOC_FAILED, NULL, ctx);
        return;
    }

    c->fd = -1;
    peer = &ctx->peer_sockaddr;
    c->peer_sockaddr = *peer;

    if (peer->addr.inet.sin_family == AF_UNIX)
        proto = PF_UNIX;
    s = socket(nst_sockaddr_get_family(peer), SOCK_STREAM, proto);

    if (s == -1) {
        nst_free_connection (c);
        ctx->cbf (NST_CONNECT_STATUS_FD_ALLOC_FAILED, NULL, ctx);
        return;
    }
    c->fd = s;

    if (dobind && proto != AF_UNIX) {
        rc = bind(s,
                  nst_sockaddr_get_sys_sockaddr(&ctx->local_sockaddr),
                  nst_sockaddr_get_sys_socklen(&ctx->local_sockaddr));
        if(rc == -1) {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            ctx->error = errno;
            ctx->cbf (NST_CONNECT_STATUS_BIND_FAILED, NULL, ctx);
            return;
        }
    }

    c->io_ops = &nst_unix_io_ops;
    c->data = ctx;
    c->type = type;

    if (nst_nonblocking(s) == -1) {
        nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
        ctx->cbf (NST_CONNECT_STATUS_NBSET_FAILED, NULL, ctx);
        return;
    }

    if (nst_add_conn) {
        /* We are in the event loop. Set the read/write cbs */
        c->data = ctx;
        c->read->handler = nst_connect_read_event;
        c->write->handler = nst_connect_write_event;

        if (nst_add_conn(c) == NST_ERROR) {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            ctx->cbf (NST_CONNECT_STATUS_EQADD_FAILED, NULL, ctx);
            return;
        }
        if (ctx->timeout > 0) {
            nst_event_add_timer (c->write, ctx->timeout);
            nst_event_add_timer (c->read, ctx->timeout);
        }
    }

    c->flags.connected = 0;
    rc = connect (s, nst_sockaddr_get_sys_sockaddr(&ctx->peer_sockaddr),
             nst_sockaddr_get_sys_socklen(&ctx->peer_sockaddr));
    if (rc < 0) {
        int saved_errno = errno;
        if (saved_errno != EINPROGRESS) {
            nst_event_add_timer (c->write, 1);
            nst_event_add_timer (c->read, 1);
        }
    }
    else {
        NST_ASSERT(rc <= 0);
    }
}

int
nst_connect (int dobind, nst_conn_type_e type, nst_event_handler_f rh,
             nst_event_handler_f  wh, nst_connect_context_t * ctx)
{
    int                rc;
    int                s=0;
    nst_connection_t  *c;
    int                proto = 0;
    nst_sockaddr_t    * peer;
        
    ctx->error = 0;
    c = nst_get_connection(s);
    if (c == NULL) {
        return NST_CONNECT_STATUS_MALLOC_FAILED;
    }

    c->fd = -1;
    peer = &ctx->peer_sockaddr;
    c->peer_sockaddr = *peer;

    if (peer->addr.inet.sin_family == AF_UNIX)
        proto = PF_UNIX;
    s = socket(nst_sockaddr_get_family(peer), SOCK_STREAM, proto);

    if (s == -1) {
        nst_free_connection (c);
        return NST_CONNECT_STATUS_FD_ALLOC_FAILED;
    }
    c->fd = s;

    if (dobind && proto != AF_UNIX) {
        rc = bind(s,
                  nst_sockaddr_get_sys_sockaddr(&ctx->local_sockaddr),
                  nst_sockaddr_get_sys_socklen(&ctx->local_sockaddr));
        if(rc == -1) {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            return NST_CONNECT_STATUS_BIND_FAILED;
        }
    }

    if (nst_nonblocking(s) == -1) {
        nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
        return NST_CONNECT_STATUS_NBSET_FAILED;
    }

    if (nst_add_conn) {
        if (nst_add_conn(c) == NST_ERROR) {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            return NST_CONNECT_STATUS_EQADD_FAILED;
        }
        c->io_ops  = &nst_unix_io_ops;
        c->data    = ctx->data;
        c->type    = type;
        c->read->handler = rh;
        c->write->handler = wh;
        ctx->data = NULL;

        if (ctx->timeout > 0) {
            nst_event_add_timer (c->write, ctx->timeout);
            nst_event_add_timer (c->read, ctx->timeout);
        }
    }

    c->flags.connected = 0;
    rc = connect(s, nst_sockaddr_get_sys_sockaddr(&ctx->peer_sockaddr),
                 nst_sockaddr_get_sys_socklen(&ctx->peer_sockaddr));
    
    if (rc < 0) {
        int saved_errno = errno;
        if (saved_errno == EINPROGRESS) {
            /* We are in the event loop. Set the read/write cbs */
            ctx->data = c;
            return NST_CONNECT_STATUS_INPROGRESS;
        }
        else {
            nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
            ctx->error = saved_errno;
            return NST_CONNECT_STATUS_EQADD_FAILED;
        }
    }
    else if (rc == 0) {
        ctx->data = c;
        return NST_CONNECT_STATUS_CONNECTED; 
    }
    else {
        NST_ASSERT(rc <= 0);
    }

    nst_unix_close(c, NST_IO_CLOSE_REASON_ERROR);
    return NST_CONNECT_STATUS_CONNECT_FAILED;
}
