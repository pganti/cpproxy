
/*
 * Copyright (C) Igor Sysoev
 */
#include <nst_core.h>
#include <nst_timer.h>

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */


nst_msec_t
nst_timer_find (nst_timer_context_t * cycle)
{
    nst_msec_int_t      timer;
    nst_rbtree_node_t  *node, *root, *sentinel;

    if (cycle->timer_rbtree.root == &cycle->timer_sentinel) {
        return NST_TIMER_INFINITE;
    }

    nst_mutex_lock(cycle->timer_mutex);

    root = cycle->timer_rbtree.root;
    sentinel = cycle->timer_rbtree.sentinel;

    node = nst_rbtree_min(root, sentinel);

    nst_mutex_unlock(cycle->timer_mutex);

    timer = (nst_msec_int_t) node->key - (nst_msec_int_t) nst_current_msec;

    return (nst_msec_t) (timer > 0 ? timer : 0);
}


void
nst_timer_expire_timers(nst_timer_context_t * cycle)
{
    nst_timer_t        *ev;
    nst_rbtree_node_t  *node, *root, *sentinel;

    sentinel = cycle->timer_rbtree.sentinel;

    for ( ;; ) {

        nst_mutex_lock(cycle->timer_mutex);

        root = cycle->timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = nst_rbtree_min(root, sentinel);

        /* node->key <= nst_current_time */

        if ((nst_msec_int_t) node->key - (nst_msec_int_t) nst_current_msec <= 0)
        {
            ev = (nst_timer_t *) ((char *) node - offsetof(nst_timer_t, timer));

            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                          "event timer del: %d: %M",
                          ev->data, ev->timer.key);

            nst_rbtree_delete(&cycle->timer_rbtree, &ev->timer);

            nst_mutex_unlock(cycle->timer_mutex);

#if (NST_DEBUG)
            ev->timer.left = NULL;
            ev->timer.right = NULL;
            ev->timer.parent = NULL;
#endif

            ev->flags.timer_set = 0;

            ev->flags.timedout = 1;

            ev->handler(ev);

            continue;
        }

        break;
    }

    nst_mutex_unlock(cycle->timer_mutex);
}


nst_int_t
nst_timer_init(nst_timer_context_t * cycle)
{
    nst_rbtree_init (&cycle->timer_rbtree, &cycle->timer_sentinel,
                     nst_rbtree_insert_timer_value);

#if (NST_THREADS)
    if (cycle->timer_mutex) {
        cycle->timer_mutex->log = nst_default_logger ();
        return NST_OK;
    }

    cycle->timer_mutex = nst_mutex_init(nst_default_logger (), 0);
    if (cycle->timer_mutex == NULL) {
        return NST_ERROR;
    }
    
#endif

    return NST_OK;
}
