#ifndef _NST_EVENT_INT_H_
#define _NST_EVENT_INT_H_

#include <nst_config.h>

/* local includes */
#include "nst_cfg_event.h"
#include "nst_connection.h"

/* nst core includes */
#include <queue.h>
#include <nst_time.h>
#include <nst_allocator.h>
#include <nst_types.h>

/* sys and std includes */
#include <netinet/in.h>

struct nst_connection_s;
struct nst_event_s;
struct nst_event_contxt_s;
struct nst_timer_s;

typedef struct nst_event_actions_s nst_event_actions_t;
typedef struct nst_event_context_s nst_event_context_t;

TAILQ_HEAD(nst_event_queue_s, nst_event_s);

struct nst_event_context_s {
    nst_cfg_event_t cfg;

    struct nst_timer_context_s *timer_ctx;

    struct nst_connection_s *connections;

    struct nst_connection_s *free_connections;
    nst_uint_t nfree_connections;

    struct nst_connection_s *pending_free_connections_head;
    struct nst_connection_s *pending_free_connections_tail;
    nst_uint_t npending_free_connections;


    struct nst_event_s *read_events;
    struct nst_event_s *write_events;

    struct nst_event_queue_s postponed_queue;

    nst_allocator_t         allocator;
};

struct nst_event_actions_s {
    nst_int_t  (*add)(nst_event_t *ev, nst_int_t event, nst_uint_t flags);
    nst_int_t  (*del)(nst_event_t *ev, nst_int_t event, nst_uint_t flags);

    nst_int_t  (*enable)(nst_event_t *ev, nst_int_t event, nst_uint_t flags);
    nst_int_t  (*disable)(nst_event_t *ev, nst_int_t event, nst_uint_t flags);

    nst_int_t  (*add_conn)(struct nst_connection_s *c);
    nst_int_t  (*del_conn)(struct nst_connection_s *c, nst_uint_t flags);

    nst_int_t  (*process_changes)(nst_uint_t nowait);
    nst_int_t  (*process_events)(nst_msec_t timer, nst_uint_t flags);

    void       (*done)(void);
};


/* ML on NGX: I don't know what it is. */
typedef struct {
    in_addr_t  mask;
    in_addr_t  addr;
} nst_event_debug_t;

struct nst_io_ops_s;
struct nst_int_io_ops_s;

struct nst_io_ops_s     *nst_io_opss[_NUM_NST_CONN_TYPE];
struct nst_int_io_ops_s *nst_int_io_opss[_NUM_NST_CONN_TYPE];
extern nst_event_context_t     event_ctx;             /* init in nst_event.c */
extern nst_event_actions_t     nst_event_actions;     /* init in nst_epoll.c */
extern nst_uint_t              nst_event_flags;       /* init in nst_epoll.c */
extern nst_uint_t              nst_connection_counter;/* init in nst_event.c */
extern nst_io_ops_t            nst_sock_io_ops;       /* init in nst_event.c */
extern nst_io_ops_t            nst_tp_io_ops;         /* init in nst_event.c */
/* extern nst_io_ops_t            nst_ssl_io_ops; */  /* init in nst_event.c */ 

/* ML on NGX:
 * We don't have accept mutex.
 */
#if 0
extern nst_atomic_t          *nst_accept_mutex_ptr;
extern nst_shmtx_t            nst_accept_mutex;
extern nst_uint_t             nst_use_accept_mutex;
extern nst_uint_t             nst_accept_events;
extern nst_uint_t             nst_accept_mutex_held;
extern nst_msec_t             nst_accept_mutex_delay;
extern nst_int_t              nst_accept_disabled;
#endif

#if (NST_STAT_STUB)

extern nst_atomic_t  *nst_stat_accepted;
extern nst_atomic_t  *nst_stat_handled;
extern nst_atomic_t  *nst_stat_requests;
extern nst_atomic_t  *nst_stat_active;
extern nst_atomic_t  *nst_stat_reading;
extern nst_atomic_t  *nst_stat_writing;

#endif

#if (NST_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    nst_event_t     *event;
    int              error;
} nst_event_ovlp_t;

#endif

#if (NST_THREADS)
typedef struct {
    nst_uint_t       lock;

    nst_event_t     *events;
    nst_event_t     *last;
} nst_event_mutex_t;
#endif

/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define NST_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define NST_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
#define NST_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define NST_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NST_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll, rtsig.
 */
#define NST_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
#define NST_USE_EPOLL_EVENT      0x00000040

/*
 * No need to add or delete the event filters: rtsig.
 */
#define NST_USE_RTSIG_EVENT      0x00000080

/*
 * No need to add or delete the event filters: overlapped, aio_read,
 * aioread, io_submit.
 */
#define NST_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 * It also requires NST_HAVE_AIO and NST_USE_AIO_EVENT to be set.
 */
#define NST_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll, rtsig.
 */
#define NST_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define NST_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define NST_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define NST_USE_VNODE_EVENT      0x00002000


/*
 * The event filter is deleted just before the closing file.
 * Has no meaning for select and poll.
 * kqueue, epoll, rtsig, eventport:  allows to avoid explicit delete,
 *                                   because filter automatically is deleted
 *                                   on file close,
 *
 * /dev/poll:                        we need to flush POLLREMOVE event
 *                                   before closing file.
 */
#define NST_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define NST_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define NST_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define NST_LOWAT_EVENT    0
#define NST_VNODE_EVENT    0


#if (NST_HAVE_KQUEUE)

#define NST_READ_EVENT     EVFILT_READ
#define NST_WRITE_EVENT    EVFILT_WRITE

#undef  NST_VNODE_EVENT
#define NST_VNODE_EVENT    EVFILT_VNODE

/*
 * NST_CLOSE_EVENT, NST_LOWAT_EVENT, and NST_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  NST_CLOSE_EVENT
#define NST_CLOSE_EVENT    EV_EOF

#undef  NST_LOWAT_EVENT
#define NST_LOWAT_EVENT    EV_FLAG1

#undef  NST_FLUSH_EVENT
#define NST_FLUSH_EVENT    EV_ERROR

#define NST_LEVEL_EVENT    0
#define NST_ONESHOT_EVENT  EV_ONESHOT
#define NST_CLEAR_EVENT    EV_CLEAR

#undef  NST_DISABLE_EVENT
#define NST_DISABLE_EVENT  EV_DISABLE


#elif (NST_HAVE_DEVPOLL || NST_HAVE_EVENTPORT)

#define NST_READ_EVENT     POLLIN
#define NST_WRITE_EVENT    POLLOUT

#define NST_LEVEL_EVENT    0
#define NST_ONESHOT_EVENT  1


#elif (NST_HAVE_EPOLL)
#include <sys/epoll.h>
#define NST_READ_EVENT     EPOLLIN
#define NST_WRITE_EVENT    EPOLLOUT

#define NST_LEVEL_EVENT    0
#define NST_CLEAR_EVENT    EPOLLET
#define NST_ONESHOT_EVENT  0x70000000
#if 0
#define NST_ONESHOT_EVENT  EPOLLONESHOT
#endif


#elif (NST_HAVE_POLL)

#define NST_READ_EVENT     POLLIN
#define NST_WRITE_EVENT    POLLOUT

#define NST_LEVEL_EVENT    0
#define NST_ONESHOT_EVENT  1


#else /* select */

#define NST_READ_EVENT     0
#define NST_WRITE_EVENT    1

#define NST_LEVEL_EVENT    0
#define NST_ONESHOT_EVENT  1

#endif /* NST_HAVE_KQUEUE */


#if (NST_HAVE_IOCP)
#define NST_IOCP_ACCEPT      0
#define NST_IOCP_IO          1
#define NST_IOCP_CONNECT     2
#endif


#ifndef NST_CLEAR_EVENT
#define NST_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define nst_process_changes  nst_event_actions.process_changes
#define nst_process_events   nst_event_actions.process_events
#define nst_done_events      nst_event_actions.done

#define nst_add_event        nst_event_actions.add
#define nst_del_event        nst_event_actions.del
#define nst_add_conn         nst_event_actions.add_conn
#define nst_del_conn         nst_event_actions.del_conn

#define nst_add_timer        nst_event_add_timer
#define nst_del_timer        nst_event_del_timer

#define NST_UPDATE_TIME         1
#define NST_POST_EVENTS         2
#define NST_POST_THREAD_EVENTS  4

static inline bool
nst_event_is_postponed(const nst_event_t *ev)
{
    return (ev->queue_entry.tqe_prev != NULL
            || ev->queue_entry.tqe_next != NULL);
}

void nst_event_timer_handler(struct nst_timer_s *timer);

#endif
