#ifndef _NST_EVENT_COMMON_H_
#define _NST_EVENT_COMMON_H_

#include "nst_unix_io_ops.h"

#include <nst_config.h>
#include <nst_rbtree.h>
#include <nst_timer.h>

#include <unistd.h>
#include <fcntl.h>

typedef struct nst_event_s nst_event_t;

typedef void (*nst_event_handler_f)(struct nst_event_s *ev);

struct nst_event_s {
    /* It should be pointing back to nst_connection_t. */
    void            *data;

    /* is it a write event or read event */
    unsigned         write:1;

    unsigned         accept:1;

    /* used to detect the stale events in kqueue, rtsig, and epoll */
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    /*  action: is the application interested in this event? */
    unsigned         active:1;

    unsigned         disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    /*  
     * is the socket ready for this event? 
     * read: data is ready in kernel socket buffer.
     *       when read returns EAGAIN or return value < requested no of bytes
     *            ==> set to 0
     *       when epoll returns with EPOLLIN ==> set to 1
     *
     * write: kernel socket buffer has free space
     *        when write returns EAGAIN or returns value < requested no of byes
     *             ==> set to 0
     *        when epoll returns with EPOLLOUT ==> set to 1
     */
    unsigned         ready:1;
    unsigned         oneshot:1;           /* NGX: we have no use of it */

    /* aio operation is complete */
    unsigned         complete:1;

    unsigned         delayed:1;

    unsigned         read_discarded:1;

    unsigned         unexpected_eof:1;

    /* the pending eof reported by kqueue or in aio chain operation */
    unsigned         pending_eof:1;

    unsigned         posted_ready:1;

    unsigned         closed:1;

    /* to test on worker exit */
    unsigned         channel:1;
    unsigned         resolver:1;

    nst_event_handler_f  handler;

    nst_timer_t          timer;

    TAILQ_ENTRY(nst_event_s) queue_entry;
};

#define nst_recv             nst_unix_io_ops.recv
/* #define nst_recv_chain       nst_unix_io_ops.recv_chain */
#define nst_udp_recv         nst_unix_io_ops.udp_recv
#define nst_send             nst_unix_io_ops.send
#define nst_send_chain       nst_unix_io_ops.send_chain
#define nst_close            nst_unix_io_ops.close

#define nst_recvmsg     nst_unix_recvmsg
//#define nst_connect     nst_unix_connect

#endif
