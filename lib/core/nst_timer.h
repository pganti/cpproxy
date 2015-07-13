
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_TIMER_H_INCLUDED_
#define _NST_TIMER_H_INCLUDED_

#include "nst_config.h"
#include "nst_rbtree.h"
#include "nst_time.h"
#include "nst_times.h"
#include "nst_thread.h"
#include "nst_types.h"
#include "nst_log_debug.h"

#define NST_TIMER_INFINITE  (nst_msec_t) -1
#define NST_TIMER_LAZY_DELAY  300

typedef struct nst_timer_s         nst_timer_t;
typedef struct nst_timer_context_s nst_timer_context_t;
typedef void (*nst_timer_handler_pt)(nst_timer_t *ev);

struct nst_timer_context_s {
    nst_rbtree_t            timer_rbtree;
    nst_rbtree_node_t       timer_sentinel;

#if (NST_THREADS)
    nst_mutex_t           * timer_mutex;
#endif
};

struct nst_timer_s {
    nst_rbtree_node_t               timer;
    nst_timer_context_t           * tc;
    nst_timer_handler_pt            handler;
    void                          * data;

    struct {
        unsigned int   timer_set:1;
        unsigned int   timedout:1;  /* Don't remove this flags */
    } flags;
};

static nst_inline void
nst_timer_delete (nst_timer_t * ev)
{
    nst_timer_context_t * cycle = ev->tc;

    if(!ev->flags.timer_set)
        return;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "timer del: %p: %M",
                   ev, ev->timer.key);

    nst_mutex_lock(cycle->timer_mutex);

    nst_rbtree_delete(&cycle->timer_rbtree, &ev->timer);

    nst_mutex_unlock(ev->timer_mutex);

#if (NST_DEBUG)
    ev->timer.left = NULL;
    ev->timer.right = NULL;
    ev->timer.parent = NULL;
#endif

    ev->flags.timer_set = 0;
}


static nst_inline void
nst_timer_add (nst_timer_context_t * cycle, nst_timer_t *ev, nst_msec_t timer)
{
    nst_msec_t      key;
    nst_msec_int_t  diff;

    key = nst_current_msec + timer;

    if (ev->flags.timer_set) {

        /*
         * Use a previous timer value if difference between it and a new
         * value is less than NST_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections.
         */

        diff = (nst_msec_int_t) (key - ev->timer.key);

        if (nst_abs(diff) < NST_TIMER_LAZY_DELAY) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                           "timer: %p, old: %M, new: %M",
                           ev, ev->timer.key, key);
            return;
        }

        nst_timer_delete (ev);
    }

    ev->timer.key = key;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "timer add: %p: %M:%M",
                  ev, timer, ev->timer.key);

    nst_mutex_lock(cycle->timer_mutex);

    nst_rbtree_insert(&cycle->timer_rbtree, &ev->timer);

    nst_mutex_unlock(cycle->timer_mutex);

    ev->tc = cycle;

    ev->flags.timer_set = 1;
}

static inline bool
nst_timer_is_set(const nst_timer_t *timer)
{
    return (bool)(timer->flags.timer_set);
}

static inline bool
nst_timer_is_timedout(const nst_timer_t *timer)
{
    return (bool)(timer->flags.timedout);
}

nst_int_t nst_timer_init(nst_timer_context_t * cycle);
nst_msec_t nst_timer_find (nst_timer_context_t * cycle);
void nst_timer_expire_timers (nst_timer_context_t * cycle);

#endif /* _NST_EVENT_TIMER_H_INCLUDED_ */
