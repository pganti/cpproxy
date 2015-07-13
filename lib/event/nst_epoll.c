#include "nst_epoll.h"

#include "nst_event_int.h"

#include <nst_time.h>
#include <nst_errno.h>

#include <signal.h>

static void nst_epoll_done(void);
static nst_int_t nst_epoll_add_event(nst_event_t *ev, nst_int_t event,
                                     nst_uint_t flags);
static nst_int_t nst_epoll_del_event(nst_event_t *ev, nst_int_t event,
                                     nst_uint_t flags);
static nst_int_t nst_epoll_add_connection(nst_connection_t *c);
static nst_int_t nst_epoll_del_connection(nst_connection_t *c,
                                          nst_uint_t flags);
static nst_int_t nst_epoll_process_events(nst_msec_t timer, nst_uint_t flags);

static int                  ep = -1;
static struct epoll_event  *event_list = NULL;
static nst_uint_t           nevents = 0;

static nst_event_actions_t nst_epoll_actions = {
    nst_epoll_add_event,             /* add an event */
    nst_epoll_del_event,             /* delete an event */
    nst_epoll_add_event,             /* enable an event */
    nst_epoll_del_event,             /* disable an event */
    nst_epoll_add_connection,        /* add an connection */
    nst_epoll_del_connection,        /* delete an connection */
    NULL,                            /* process the changes */
    nst_epoll_process_events,        /* process the events */
    nst_epoll_done,                  /* done the events */
};

nst_status_e
nst_epoll_init(const nst_cfg_event_t *event_cfg)
{
    nst_uint_t max_nepoll_events = event_cfg->max_nepoll_events_per_loop;

    if (ep == -1) {
        ep = epoll_create(event_cfg->max_nconnections / 2);

        if (ep == -1) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                        "epoll_create() failed. %s(%d)",
                        nst_strerror(errno), errno);
            return NST_ERROR;
        }
    }

    if (nevents < max_nepoll_events) {
        if (event_list) {
            nst_allocator_free(&event_ctx.allocator, event_list);
        }

        event_list =
            nst_allocator_malloc(&event_ctx.allocator,
                                 sizeof(struct epoll_event) * max_nepoll_events);
        if (event_list == NULL) {
            return NST_ERROR;
        }
    }

    nevents = max_nepoll_events;

    /* nst_io = nst_os_io; */

    nst_event_actions = nst_epoll_actions;

    nst_event_flags = NST_USE_CLEAR_EVENT      /* Edge Trigger */
                      | NST_USE_GREEDY_EVENT   /* Always read till EAGAIN */
                      | NST_USE_EPOLL_EVENT;   /* Tell others that
                                                * epoll is used as the enginer
                                                * of the event loop.
                                                */

/* NGX: another unnecessary #if check which
 *            makes codes look difficult and horrible
 */
#if 0
#if (NST_HAVE_CLEAR_EVENT)
    nst_event_flags = NST_USE_CLEAR_EVENT
#else
    nst_event_flags = NST_USE_LEVEL_EVENT
#endif
                      |NST_USE_GREEDY_EVENT
                      |NST_USE_EPOLL_EVENT;
#endif

    return NST_OK;
}


static void
nst_epoll_done(void)
{
    if(ep != -1) {
        while(close(ep) == -1) {
            if(errno == EINTR) {
                continue;
            } else {
                NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                              "epoll close failed. %s(%d)",
                              nst_strerror(errno), errno);
                break;
            }
        }

        ep = -1;
    }

    if (event_list) {
        nst_allocator_free(&event_ctx.allocator, event_list);
    }

    event_list = NULL;
    nevents = 0;
}


static nst_int_t
nst_epoll_add_event(nst_event_t *ev, nst_int_t event, nst_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    nst_event_t         *e;
    nst_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    events = (uint32_t) event;

    if (event == NST_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NST_READ_EVENT != EPOLLIN)
        events = EPOLLIN;
#endif
    } else {
        e = c->read;
        prev = EPOLLIN;
#if (NST_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

    /* for epoll, flags will be NST_CLEAR_EVENT which is EPOLLET */
    ee.events = events | (uint32_t) flags | EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "epoll_ctl: ep:%Xd op:%Xd add-event:%08XD "
                  "for %s",
                  ep, op, ee.events,
                  nst_connection_get_dbg_str(c));

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                    "epoll_ctl failed %s(%d): "
                    "ep:%Xd op:%Xd add-event:%08XD "
                    "for %s",
                    nst_strerror(errno), errno,
                    ep, op, ee.events,
                    nst_connection_get_dbg_str(c));

        return NST_ERROR;
    }

    ev->active = 1;
#if 0
    ev->oneshot = (flags & NST_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NST_OK;
}


static nst_int_t
nst_epoll_del_event(nst_event_t *ev, nst_int_t event, nst_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    nst_event_t         *e;
    nst_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "%s",
                  nst_connection_get_dbg_str((nst_connection_t *)ev->data));

    if (flags & NST_CLOSE_EVENT) {
        ev->active = 0;
        return NST_OK;
    }

    c = ev->data;

    if (event == NST_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "epoll_ctl: ep:%Xd op:%Xd del-event:%08XD "
                  "for %s",
                  ep, op, ee.events,
                  nst_connection_get_dbg_str(c));


    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "epoll_ctl failed %s(%d): "
                      "ep:%Xd op:%Xd del-event:%08XD "
                      "for %s",
                      nst_strerror(errno), errno,
                      ep, op, ee.events,
                      nst_connection_get_dbg_str(c));

        return NST_ERROR;
    }

    ev->active = 0;

    return NST_OK;
}


static nst_int_t
nst_epoll_add_connection(nst_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "epoll_ctl: ep:%Xd op:%Xd add-connection-event:%08XD "
                  "for %s",
                  ep, EPOLL_CTL_ADD, ee.events,
                  nst_connection_get_dbg_str(c));

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "epoll_ctl failed %s(%d): "
                      "ep:%Xd op:%Xd add-connection-event:%08XD "
                      "for %s",
                      nst_strerror(errno), errno,
                      ep, EPOLL_CTL_ADD, ee.events,
                      nst_connection_get_dbg_str(c));
        return NST_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NST_OK;
}


static nst_int_t
nst_epoll_del_connection(nst_connection_t *c, nst_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "%s",
                  nst_connection_get_dbg_str(c));

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    if (flags & NST_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NST_OK;
    }

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "epoll_ctl: ep:%Xd op:%Xd del-connection-event:%08XD "
                      "for %s",
                      ep, op, ee.events,
                      nst_connection_get_dbg_str(c));

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "epoll_ctl failed %s(%d): "
                      "ep:%Xd op:%Xd del-connection-event:%08XD "
                      "for %s",
                      nst_strerror(errno), errno,
                      ep, op, ee.events,
                      nst_connection_get_dbg_str(c));
        return NST_ERROR;
    } else {
        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "epoll_ctl: ep:%Xd op:%Xd del-connection-event:%08XD "
                      "for %s",
                      ep, op, ee.events,
                      nst_connection_get_dbg_str(c));
    }


    c->read->active = 0;
    c->write->active = 0;

    return NST_OK;
}


static nst_int_t
nst_epoll_process_events(nst_msec_t timer, nst_uint_t flags)
{
    int                events;
    uint32_t           revents;
    nst_int_t          instance, i;
    nst_event_t       *rev, *wev; /*, **queue; */
    nst_connection_t  *c;
    
    sigset_t alrm_sigset;
    /* NST_TIMER_INFINITE == INFTIM */


    sigemptyset(&alrm_sigset);
    sigaddset(&alrm_sigset, SIGALRM);

#if !(NST_THREADS)
    sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);   /* disable alrm signal */
#else
#error "sigprocmask needs to be replaced with pthread_sigmask"
#endif

    NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                  "epoll_wait() with %M ms timeout",
                  timer);
    events = epoll_wait(ep, event_list, (int) nevents, timer);

#if !(NST_THREADS)
    sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL); /* reenable alrm signal */
#else
#error "sigprocmask needs to be replaced with pthread_sigmask"
#endif

    NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE, "epoll_wait()=>%d", events);

    if (events == -1) {
        nst_time_update(0, 0);
        if (errno == EINTR) {
            /* We got some signals, probably HUP or TERM but not ALRM.
             * We break the event loop to allow the process to handle config
             * reload or termination.
             */
            return NST_OK;

        } else {
            NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                          "epoll_wait() failed. %s(%d).",
                          nst_strerror(errno), errno);
            return NST_ERROR;

        }
    }

    if (flags & NST_UPDATE_TIME) {
        nst_time_update(0, 0);
    }

    if (events == 0) {
        if (timer != NST_TIMER_INFINITE) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                          "epoll_wait() returned after timeout");
            return NST_OK; /* timer expired */
        } else {
            NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                          "epoll_wait() returned no events without timeout");
            return NST_ERROR;
        }
    }

    NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                  "epoll_wait(%M)=>%d",
                  timer, events);
    nst_mutex_lock(nst_posted_events_mutex);

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (nst_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                          "epoll: stale event c:%p", c);
            continue;
        }

        revents = event_list[i].events;

        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "epoll got event: %s ev:%04XD d:%p",
                      nst_connection_get_dbg_str(c),
                      revents,
                      event_list[i].data.ptr);

        if (revents & EPOLLERR) {
            c->flags.io_err_from_ev = 1;
        }

        if (revents & EPOLLRDHUP) {
            nst_int_io_opss[c->type]->set_io_eof_from_ev(c);
        }

        if ((revents & (EPOLLERR|EPOLLHUP|EPOLLRDHUP))
            && (revents & (EPOLLIN|EPOLLOUT)) == 0) {
            /*
             * if the error events were returned without EPOLLIN or EPOLLOUT,
             * then add these flags to handle the events at least in one
             * active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

        if ((revents & EPOLLIN) && rev->active) {

            if ((flags & NST_POST_THREAD_EVENTS) && !rev->accept) {
                rev->posted_ready = 1;

            } else {
                rev->ready = 1;
            }

            if(!nst_event_is_postponed(rev))
                rev->handler(rev);
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (flags & NST_POST_THREAD_EVENTS) {
                wev->posted_ready = 1;

            } else {
                wev->ready = 1;
            }

            if(!nst_event_is_postponed(wev))
                wev->handler(wev);
        }
    }

    nst_mutex_unlock(nst_posted_events_mutex);

    return NST_OK;
}

