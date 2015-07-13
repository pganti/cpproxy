#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/socket.h>
#include <netinet/tcp.h>

#include "nst_connection.h"
#include "nst_unix_io_ops.h"
#include "nst_tp_connection.h"

#include "nst_cfg_svc.h"
#include "nst_event_int.h"

#include <nst_log.h>
#include <nst_enum_type_helpers.h>

nst_io_ops_t *nst_io_opss[_NUM_NST_CONN_TYPE] = {
    [NST_CONN_TYPE_UNKNOWN] = NULL,
    [NST_CONN_TYPE_TCP]     = &nst_unix_io_ops,
    [NST_CONN_TYPE_TP]      = &nst_tp_io_ops,
    [NST_CONN_TYPE_UNIX]    = &nst_unix_io_ops,
    [NST_CONN_TYPE_PIPE]    = &nst_unix_io_ops,
    [NST_CONN_TYPE_RTNETLINK]    = &nst_unix_io_ops,
};
    
nst_int_io_ops_t *nst_int_io_opss[_NUM_NST_CONN_TYPE] = {
    [NST_CONN_TYPE_UNKNOWN] = NULL,
    [NST_CONN_TYPE_TCP]     = &nst_unix_int_io_ops,
    [NST_CONN_TYPE_TP]      = &nst_tp_int_io_ops,
    [NST_CONN_TYPE_UNIX]    = &nst_unix_int_io_ops,
    [NST_CONN_TYPE_PIPE]    = &nst_unix_int_io_ops,
    [NST_CONN_TYPE_RTNETLINK]    = &nst_unix_int_io_ops,
};

static char conn_log_str_buf[256];

static const char *nst_conn_type_str[] = {
    [NST_CONN_TYPE_UNKNOWN]      = "unknown",
    [NST_CONN_TYPE_TCP]          = "tcp",
    [NST_CONN_TYPE_TP]           = "mp",
    [NST_CONN_TYPE_UNIX]         = "unix",
    [NST_CONN_TYPE_PIPE]         = "pipe",
    [NST_CONN_TYPE_RTNETLINK]    = "rtnetlink",
};

static inline const char *
nst_conn_type_to_str(nst_conn_type_e type)
{
    return nst_enum_type_to_str(nst_conn_type_str,
                                NST_CONN_TYPE_UNKNOWN,
                                _NUM_NST_CONN_TYPE,
                                NST_CONN_TYPE_UNKNOWN,
                                type);
}

nst_connection_t *
nst_get_connection(int fd)
{
    nst_uint_t         instance;
    nst_event_t       *rev, *wev;
    nst_connection_t  *c;

    c = event_ctx.free_connections;

    if (c == NULL) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "%ui connections are not enough",
                    event_ctx.cfg.max_nconnections);
        errno = ENOSPC;
        return NULL;
    }

    event_ctx.free_connections = c->data;
    event_ctx.nfree_connections--;

    rev = c->read;
    wev = c->write;

    nst_memzero(c, sizeof(nst_connection_t));

    c->read = rev;
    c->write = wev;
    c->fd = fd;
    c->noc_log_lvl = NST_LOG_LEVEL_DEFAULT;
    c->dbg_log_lvl = NST_LOG_LEVEL_DEFAULT;

    instance = rev->instance;

    nst_memzero(rev, sizeof(nst_event_t));
    nst_memzero(wev, sizeof(nst_event_t));

    rev->instance = !instance;
    wev->instance = !instance;

    rev->data = c;
    wev->data = c;

    wev->write = 1;

    rev->timer.handler = nst_event_timer_handler;
    rev->timer.data = rev;
    wev->timer.handler = nst_event_timer_handler;
    wev->timer.data = wev;

    c->number = nst_connection_counter++;

    return c;
}

void
nst_do_free_connection(nst_connection_t *c) {
    if(event_ctx.pending_free_connections_tail) {
        c->data = event_ctx.pending_free_connections_head;
        event_ctx.pending_free_connections_head = c;
    } else {
        event_ctx.pending_free_connections_tail =
            event_ctx.pending_free_connections_head = c;
    }

    if(c->svc)
        nst_cfg_svc_free(c->svc);

    event_ctx.npending_free_connections++;

    return;
}

void
nst_free_connection(nst_connection_t *c)
{
    c->data = NULL;
    if(nst_event_is_postponed(c->read)
       || nst_event_is_postponed(c->write)) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "%s has postponed event (read:%d write:%d). "
                      "delaying connection free",
                      nst_connection_get_brief_str(c),
                      nst_event_is_postponed(c->read),
                      nst_event_is_postponed(c->write));

        c->postponed_free = 1;
    } else {
        nst_do_free_connection(c);
    }
}

int
nst_connection_add_toeventq (nst_connection_t * c)
{
    if (nst_add_conn) {
        if (nst_add_conn(c) == NST_ERROR) {
            return NST_ERROR;
        }
        return NST_OK;
    }
    return NST_ERROR;
}

const char *
nst_connection_get_brief_str(const nst_connection_t *c)
{
#if (NST_THREADS)
#error "TODO: implement a thread-safe version of nst_connection_get_brief_str()"
#endif

    char *end;

    end = (char *)nst_snprintf((u_char *)conn_log_str_buf,
                               sizeof(conn_log_str_buf),
                               "%s-%s-c#:%ui tid:%ui",
                               nst_conn_type_to_str(c->type),
                               c->is_upstream ? "up" : "down",
                               c->number,
                               c->tid);

    if(end < conn_log_str_buf + sizeof(conn_log_str_buf))
        *end = '\0';
    else
        conn_log_str_buf[sizeof(conn_log_str_buf)-1] = '\0';

    return conn_log_str_buf;
}

const char *
nst_connection_get_dbg_str(const nst_connection_t *c)
{
#if (NST_THREADS)
#error "TODO: implement a thread-safe version of nst_connection_get_dbg_str()"
#endif

    char *end;

    end = (char *) nst_snprintf((u_char *)conn_log_str_buf,
                                sizeof(conn_log_str_buf),
                                "%s-%s-c#:%ui tid:%ui fd:%d (%s:%s,%s:%s)",
                                nst_conn_type_to_str(c->type),
                                c->is_upstream ? "up" : "down",
                                c->number,
                                c->tid,
                                c->fd,
                                nst_sockaddr_get_ip_str(&c->local_sockaddr),
                                nst_sockaddr_get_port_str(&c->local_sockaddr),
                                nst_sockaddr_get_ip_str(&c->peer_sockaddr),
                                nst_sockaddr_get_port_str(&c->peer_sockaddr));

    if(end < conn_log_str_buf + sizeof(conn_log_str_buf))
        *end = '\0';
    else
        conn_log_str_buf[sizeof(conn_log_str_buf)-1] = '\0';

    return conn_log_str_buf;
}

int
nst_connection_rtt (const nst_connection_t * conn)
{
    struct tcp_info    tcpinfo;
    int                optlen, status;
    float              f;
    int                rtt = 0;
    
    optlen = sizeof(tcpinfo);
    status = getsockopt (conn->fd, SOL_TCP, TCP_INFO, (void *)&tcpinfo,
                         (socklen_t *)&optlen);
    if (status == 0) {
        f = (float)tcpinfo.tcpi_rtt;
        rtt = (int) (f / 1000);
    }

    if (rtt == 0)
        return 1;

    return rtt;
}
