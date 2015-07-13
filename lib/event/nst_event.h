#ifndef _NST_EVENT_H_
#define _NST_EVENT_H_

#include <nst_config.h>

#include "nst_event_common.h"
#include "nst_connection.h"

#include <nst_types.h>
#include <nst_time.h>
#include <nst_timer.h>

struct nst_cfg_svc_s;
struct nst_cfg_event_s;
struct nst_timer_context_s;

nst_status_e nst_event_init(const struct nst_cfg_event_s *new_event_cfg,
                            struct nst_timer_context_s *timer_ctx);

nst_status_e nst_event_reinit(const struct nst_cfg_event_s *new_event_cfg);

void nst_process_events_and_timers(void);

nst_int_t nst_handle_read_event(nst_event_t *rev, nst_uint_t flags);

nst_int_t nst_handle_write_event(nst_event_t *wev, size_t lowat);

void nst_event_add_timer(nst_event_t *ev, nst_msec_t timeout_ms);
void nst_event_add_timer_if_not_set(nst_event_t *ev,
                                    nst_msec_t timeout_ms);
void nst_event_cleanup (void);

static inline void
nst_event_del_timer(nst_event_t *ev)
{
    nst_connection_t *c = (nst_connection_t *)ev->data;

    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s del %s event timeout",
                     nst_connection_get_brief_str(c),
                     ev->write ? "write" : "read");

    nst_timer_delete(&ev->timer);
}

static inline bool
nst_event_is_timedout(const nst_event_t *ev)
{
    if(ev->timer.flags.timedout)
        return TRUE;
    else
        return FALSE;
}

static inline bool
nst_event_is_timer_set(const nst_event_t *ev)
{
    return (bool)(ev->timer.flags.timer_set);
}

void nst_event_clear_timedout(nst_event_t *ev);

nst_status_e nst_add_listener(struct nst_cfg_svc_s *svc);

void nst_del_listener(struct nst_cfg_svc_s *svc);

void nst_event_postpone(nst_event_t *ev);

static inline bool
nst_event_is_ready(const nst_event_t *ev)
{
    return ev->ready;
}

/* nst_int_t nst_send_lowat(nst_connection_t *c, size_t lowat); */

/* ML on NGX: for SSL only */
/* typedef void (*nst_connection_handler_f)(nst_connection_t *c); */

#endif
