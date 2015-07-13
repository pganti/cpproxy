/* ALWAYS include myself first */
#include "nst_event.h"

/* local includes */
#include "nst_event_int.h"
#include "nst_cfg_event.h"
#include "nst_connection.h"
#include "nst_unix_io_ops.h"
#include "nst_epoll.h"

/* libnst_cfg includes */
#include <nst_cfg_common.h>

/* nst core includes */
#include <nst_string.h>
#include <nst_types.h>
#include <nst_mem_stat_allocator.h>
#include <nst_allocator.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_times.h>
#include <nst_timer.h>
#include <nst_assert.h>
#include <queue.h>

/* sys and std includes MUST be the last */
#include <sys/resource.h>
#include <signal.h>
#include <string.h>

/* The following globals are decalred in nst_event_int.h.
 * These globals are used internally within libevent.
 */

/* init in this file */
nst_event_context_t         event_ctx = {
    .connections = NULL,
    .read_events = NULL,
    .write_events = NULL,
};

/* init in nst_epoll.c */
nst_event_actions_t         nst_event_actions = {
    .add             = NULL,
    .del             = NULL,
    .enable          = NULL,
    .disable         = NULL,
    .add_conn        = NULL,
    .del_conn        = NULL,
    .process_changes = NULL,
    .process_events  = NULL,
    .done            = NULL,
};

nst_uint_t                  nst_event_flags;       /* init in nst_epoll.c */
nst_uint_t                  nst_connection_counter = 1;

static inline void
nst_event_recycle_connections(void)
{
    if(event_ctx.pending_free_connections_head) {
        event_ctx.pending_free_connections_tail->data = event_ctx.free_connections;
        event_ctx.free_connections = event_ctx.pending_free_connections_head;
        event_ctx.nfree_connections += event_ctx.npending_free_connections;

        event_ctx.pending_free_connections_tail =
            event_ctx.pending_free_connections_head = NULL;
        event_ctx.npending_free_connections = 0;
    }
}

static void
nst_event_ctx_init(void)
{
    memset(&event_ctx, 0, sizeof(nst_event_context_t));
    TAILQ_INIT(&event_ctx.postponed_queue);
    event_ctx.allocator = nst_mem_stat_register("libevent");
}

nst_status_e
nst_event_reinit(const nst_cfg_event_t *new_event_cfg)
{
    nst_cfg_reload_status_e reload_status;

    reload_status = nst_cfg_event_apply_modified(&event_ctx.cfg, new_event_cfg);

    if(reload_status == NST_CFG_RELOAD_STATUS_NO_CHANGE)
        return NST_OK;

    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        return NST_ERROR;

    return nst_epoll_init(&event_ctx.cfg);
}

nst_status_e
nst_event_init(const nst_cfg_event_t *new_event_cfg,
               nst_timer_context_t *timer_ctx)
{
    nst_uint_t           i;
    nst_event_t         *rev, *wev;
    nst_connection_t    *c, *next;
    nst_uint_t max_nconnections;
    struct rlimit  rlmt;

    nst_event_ctx_init();
    event_ctx.timer_ctx = timer_ctx;

    event_ctx.cfg = *new_event_cfg;

    max_nconnections = new_event_cfg->max_nconnections;

    nst_epoll_init(new_event_cfg);

    if(getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "getrlimit(RLIMIT_NOFILE) failed, ignored. %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;

    } else if(max_nconnections > rlmt.rlim_cur) {
        rlmt.rlim_cur = max_nconnections;
        if(max_nconnections > rlmt.rlim_max) {
            rlmt.rlim_max = max_nconnections;
        }

        if(setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "setrlimit(RLIMIT_NOFILE) failed. "
                        "target = %ud, rlim_cur = %ud, rlim_max = %ud. %s(%d)",
                        max_nconnections,
                        rlmt.rlim_cur, rlmt.rlim_max,
                        nst_strerror(errno), errno);
            /* return NST_ERROR; */
        }
    }

    /* - start - pre allocate and init connections */
    event_ctx.connections =
        nst_allocator_malloc(&event_ctx.allocator,
                             sizeof(nst_connection_t) * max_nconnections);
    if (event_ctx.connections == NULL) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot pre allocate %ud nst_connection_t objects",
                    max_nconnections);
        return NST_ERROR;
    }
    c = event_ctx.connections;
    /* - end - pre allocate and init connections */

    /* - start - pre allocate and read_events */
    event_ctx.read_events = 
        nst_allocator_malloc(&event_ctx.allocator,
                             sizeof(nst_event_t) * max_nconnections);
    if (event_ctx.read_events == NULL) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot pre allocate %ud nst_event_t objects",
                    max_nconnections);
        return NST_ERROR;
    }

    rev = event_ctx.read_events;
    for (i = 0; i < max_nconnections; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
#if (NGX_THREADS)
        rev[i].lock = &c[i].lock;
        rev[i].own_lock = &c[i].lock;
#endif
    }
    /* - end - pre allocate and read_events */

    /* - start - pre allocate and write_events */
    event_ctx.write_events =
        nst_allocator_malloc(&event_ctx.allocator,
                             sizeof(nst_event_t) * max_nconnections);
    if (event_ctx.write_events == NULL) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot pre allocate %ud nst_event_t objects",
                    max_nconnections);
        return NST_ERROR;
    }

    wev = event_ctx.write_events;
    for (i = 0; i < max_nconnections; i++) {
        wev[i].closed = 1;
#if (NGX_THREADS)
        wev[i].lock = &c[i].lock;
        wev[i].own_lock = &c[i].lock;
#endif
    }
    /* - end - pre allocate and write_events */

    i = max_nconnections;
    next = NULL;

    do {
        i--;

        c[i].data = next;
        c[i].read = &event_ctx.read_events[i];
        c[i].write = &event_ctx.write_events[i];
        c[i].fd = -1;

        next = &c[i];

#if (NGX_THREADS)
        c[i].lock = 0;
#endif
    } while (i);

    event_ctx.free_connections = next;
    event_ctx.nfree_connections = max_nconnections;

    /* ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    return NST_OK;
}

void
nst_event_postpone(nst_event_t *ev)
{
    nst_connection_t *c = ev->data;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "%s postponed %s event",
                  nst_connection_get_brief_str(c),
                  ev->write ? "write" : "read");

    nst_assert(ev->active);
    nst_assert(ev->ready);
    nst_assert(c->fd != -1);
#if 0
    nst_assert(ev->queue_entry.tqe_prev == NULL);
    nst_assert(ev->queue_entry.tqe_next == NULL);
#endif

    if(!nst_event_is_postponed(ev)) {
        TAILQ_INSERT_TAIL(&event_ctx.postponed_queue, ev, queue_entry);
    } else {
        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "%s already has postponed %s event",
                      nst_connection_get_brief_str(c),
                      ev->write ? "write" : "read");
    }
}

void
nst_process_events_and_timers(void)
{
    nst_uint_t  flags;
    nst_msec_t  delta;
    nst_msec_t  wait_time;
    nst_msec_t  new_event_spent_ms;
    nst_msec_t  postponed_event_spent_ms;
    nst_msec_t  expired_timer_spent_ms;
    nst_uint_t  npostponed_event = 0;
    nst_event_t *postponed_event;
    nst_event_t *tmp_postponed_event;
    nst_event_t *last_postponed_event;
    bool         any_timer_event;
    
    flags = NST_UPDATE_TIME;        /* Always ask nst_epoll_process_events()
                                     * to call nst_time_update() to 
                                     * update the cached nst_current_time.
                                     */
    wait_time = nst_timer_find(event_ctx.timer_ctx);
    any_timer_event = (wait_time != NST_TIMER_INFINITE);
    
    if(!TAILQ_ETPTY(&event_ctx.postponed_queue)) {
        last_postponed_event = TAILQ_LAST(&event_ctx.postponed_queue,
                                          nst_event_queue_s);
        NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                      "last_postponed_event: %p",
                      last_postponed_event);
        wait_time = 0;
    } else {
        last_postponed_event = NULL;
        if(wait_time > (nst_msec_t)100)
            wait_time = 100;
    }

    delta = nst_current_msec;
    nst_process_events(wait_time, flags);
    nst_time_update(0, 0);
    new_event_spent_ms = nst_current_msec - delta;
    NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                  "event loop spent %M ms on new event",
                  new_event_spent_ms);

    delta = nst_current_msec;
    if(last_postponed_event) {
        nst_connection_t *c;
        bool done = FALSE;

        TAILQ_FOREACH_SAFE(postponed_event,
                           &event_ctx.postponed_queue,
                           queue_entry,
                           tmp_postponed_event) {
            if(done)
                break;

            TAILQ_REMOVE(&event_ctx.postponed_queue,
                         postponed_event, queue_entry);
            nst_memzero(&postponed_event->queue_entry,
                        sizeof(postponed_event->queue_entry));

            c = postponed_event->data;
            
            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                          "handling %s postponed %s event",
                          nst_connection_get_brief_str(c),
                          postponed_event->write ? "write" : "read");

            if(postponed_event == last_postponed_event) {
                NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                              "it is the last postponed event(%p)",
                              postponed_event);
                done = TRUE; /* the last one we will handle during
                              * this event loop
                              */
            }
            
            if(c->postponed_free) {
                nst_assert(c->fd == -1);
                if(!nst_event_is_postponed(c->write)
                   && !nst_event_is_postponed(c->read)) {
                    nst_do_free_connection(c);
                    continue;
                }
            } else {
                nst_assert(c->fd != -1 && "c->postponed_free is not set?");
                postponed_event->handler(postponed_event);
                /* don't ever touch postponed_event after this point!
                 * the postponed_event->handler may have freed the
                 * connection and hence the postponed_event.
                 */
                npostponed_event++;
            }
        }

        nst_time_update(0, 0);
    }
    postponed_event_spent_ms = nst_current_msec - delta;
    NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                  "event loop spent %M on %ud postponed events",
                  postponed_event_spent_ms,
                  npostponed_event);

    if(any_timer_event) {
        delta = nst_current_msec;
        nst_timer_expire_timers (event_ctx.timer_ctx);
        nst_time_update(0, 0);
        expired_timer_spent_ms = nst_current_msec - delta;
        NST_DEBUG_LOG(NST_LOG_LEVEL_VERBOSE,
                      "process expired timers spent %M ms",
                      expired_timer_spent_ms);
    }

    nst_event_recycle_connections();
}

nst_int_t
nst_handle_read_event(nst_event_t *rev, nst_uint_t flags)
{
    if (nst_event_flags & NST_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (nst_add_event(rev, NST_READ_EVENT, NST_CLEAR_EVENT)
                == NST_ERROR)
            {
                return NST_ERROR;
            }
        }

        return NST_OK;

    } else if (nst_event_flags & NST_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (nst_add_event(rev, NST_READ_EVENT, NST_LEVEL_EVENT)
                == NST_ERROR)
            {
                return NST_ERROR;
            }

            return NST_OK;
        }

        if (rev->active && (rev->ready || (flags & NST_CLOSE_EVENT))) {
            if (nst_del_event(rev, NST_READ_EVENT, NST_LEVEL_EVENT | flags)
                == NST_ERROR)
            {
                return NST_ERROR;
            }

            return NST_OK;
        }

    } else if (nst_event_flags & NST_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (nst_add_event(rev, NST_READ_EVENT, 0) == NST_ERROR) {
                return NST_ERROR;
            }

            return NST_OK;
        }

        if (rev->oneshot && !rev->ready) {
            if (nst_del_event(rev, NST_READ_EVENT, 0) == NST_ERROR) {
                return NST_ERROR;
            }

            return NST_OK;
        }
    }

    /* aio, iocp, rtsig */

    return NST_OK;
}


nst_int_t
nst_handle_write_event(nst_event_t *wev, size_t lowat)
{

/*  Linux doesn't have nst_send_lowat and it is not
 *     useful to us.  We always wanna send ASAP.
 *
 *     For now, we keep the 'size_t lowat' argument but safely
 *     ignore it.
 */
#if 0
    nst_connection_t  *c;

    if (lowat) {
        c = wev->data;

        if (nst_send_lowat(c, lowat) == NST_ERROR) {
            return NST_ERROR;
        }
    }
#endif

    if (nst_event_flags & NST_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        /*   for EPOLLET, we only need to add event if
         *     the fd is not in epfd (!wev->active)
         *     AND we did get EAGAIN in the last send
         */
        if (!wev->active && !wev->ready) {
            if (nst_add_event(wev, NST_WRITE_EVENT,
                              NST_CLEAR_EVENT | (lowat ? NST_LOWAT_EVENT : 0))
                == NST_ERROR)
            {
                return NST_ERROR;
            }
        }

        return NST_OK;

    } else if (nst_event_flags & NST_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (nst_add_event(wev, NST_WRITE_EVENT, NST_LEVEL_EVENT)
                == NST_ERROR)
            {
                return NST_ERROR;
            }

            return NST_OK;
        }

        if (wev->active && wev->ready) {
            if (nst_del_event(wev, NST_WRITE_EVENT, NST_LEVEL_EVENT)
                == NST_ERROR)
            {
                return NST_ERROR;
            }

            return NST_OK;
        }

    } else if (nst_event_flags & NST_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (nst_add_event(wev, NST_WRITE_EVENT, 0) == NST_ERROR) {
                return NST_ERROR;
            }

            return NST_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (nst_del_event(wev, NST_WRITE_EVENT, 0) == NST_ERROR) {
                return NST_ERROR;
            }

            return NST_OK;
        }
    }

    /* aio, iocp, rtsig */

    return NST_OK;
}

void
nst_event_timer_handler(nst_timer_t *timer)
{
    nst_event_t *ev;
    nst_connection_t *c;

    ev = (nst_event_t *)timer->data;
    c = (nst_connection_t *)ev->data;
    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s %s event timed out",
                     nst_connection_get_brief_str(c),
                     ev->write ? "write" : "read");
    nst_assert(ev->handler);
    ev->handler(ev);
}

void
nst_event_add_timer(nst_event_t *ev, nst_msec_t timeout_ms)
{
    nst_connection_t *c = (nst_connection_t *)ev->data;

    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s add %s event timeout for %ud ms",
                     nst_connection_get_brief_str(c),
                     ev->write ? "write" : "read",
                     timeout_ms);

    nst_timer_add(event_ctx.timer_ctx,
                  &ev->timer,
                  timeout_ms);
}

void
nst_event_add_timer_if_not_set(nst_event_t *ev, nst_msec_t timeout_ms)
{
    if(!nst_event_is_timer_set(ev)) {
        nst_connection_t *c = (nst_connection_t *)ev->data;
        
        NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s add %s event timeout for %ud ms",
                     nst_connection_get_brief_str(c),
                     ev->write ? "write" : "read",
                     timeout_ms);

        nst_timer_add(event_ctx.timer_ctx,
                      &ev->timer,
                      timeout_ms);
    }
}

void
nst_event_clear_timedout(nst_event_t *ev)
{
    ev->timer.flags.timedout = 0;
}

void
nst_event_cleanup ()
{
    if(nst_event_actions.done)
        nst_event_actions.done();

    if (event_ctx.connections) {
        nst_allocator_free(&event_ctx.allocator, event_ctx.connections);
    }

    if (event_ctx.read_events) {
        nst_allocator_free(&event_ctx.allocator, event_ctx.read_events);
    }
    if (event_ctx.write_events) {
        nst_allocator_free(&event_ctx.allocator, event_ctx.write_events);
    }
}
