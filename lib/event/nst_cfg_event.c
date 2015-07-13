#include "nst_cfg_event.h"

#include <nst_cfg_common.h>
#include <nst_cfg.h>
#include <nst_cfg_tag_action.h>

#include <nst_log.h>
#include <nst_limits.h>
#include <nst_assert.h>
#include <nst_errno.h>

#include <string.h>
#include <stddef.h>

#define MAX_NCONNECTIONS_TAG            "max-num-connections"
#define MAX_NEPOLL_EVENTS_PER_LOOP_TAG  "max-num-epoll-events"
#define MAX_NACCEPTS_PER_LOOP_TAG       "max-num-accepts-per-event"
#define MAX_NBYTES_PER_LOOP_TAG         "max-num-bytes-per-event"

typedef struct event_frame_data_s event_frame_data_t;

struct event_frame_data_s
{
    nst_cfg_event_t *event;
};

static void event_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void event_end_handler(void *udata,
                                 const XML_Char *name);

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(event, nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_event_capture(void *udata,
                      const XML_Char *name,
                      const XML_Char **attrs,
                      void **pevent, void **unused1,
                      void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(event);

    nst_assert(pevent);
    event_frame_data->event 
        = (nst_cfg_event_t *)pevent;
    return NST_OK;

    return 0;
}

static nst_cfg_tag_action_t event_tag_actions[] = {
    { MAX_NCONNECTIONS_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_event_t, max_nconnections),
      0,
      0,
      0,
    },

    { MAX_NEPOLL_EVENTS_PER_LOOP_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_event_t, max_nepoll_events_per_loop),
      0,
      0,
      0,
    },

    { MAX_NACCEPTS_PER_LOOP_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_event_t, max_naccepts_per_loop),
      0,
      0, 
      0,
    },

    { MAX_NBYTES_PER_LOOP_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_event_t, max_nbytes_per_loop),
      0,
      0, 
      0,
    },

};

static void
event_start_handler(void *udata,
                             const XML_Char *name,
                             const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(event, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   event_tag_actions,
                   sizeof(event_tag_actions)/sizeof(event_tag_actions[0]),
                   current,
                   udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   event_frame_data->event, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void event_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(event);

    ret = nst_cfg_tag_action_end_handler(
                   event_tag_actions,
                   sizeof(event_tag_actions)/sizeof(event_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   event_frame_data->event,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        nst_cfg_event_t *event = event_frame_data->event;
        if(event->max_nconnections < MIN_NCONNECTIONS) {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "<%s> has value < %d. resetting to %d.",
                        MAX_NCONNECTIONS_TAG,
                        MIN_NCONNECTIONS,
                        MIN_NCONNECTIONS);
            event->max_nconnections = MIN_NCONNECTIONS;
        }
        event->max_ntp_connections = (event->max_nconnections * 3) / 5;
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

void
nst_cfg_event_init(nst_cfg_event_t *event)
{
    event->max_nconnections
        = DF_MAX_NCONNECTIONS;

    event->max_ntp_connections
        = DF_MAX_NTP_CONNECTIONS;

    event->max_nepoll_events_per_loop
        = DF_MAX_NEPOLL_EVENTS_PER_LOOP;

    event->max_naccepts_per_loop
        = DF_MAX_NACCEPTS_PER_LOOP;

    event->max_nbytes_per_loop
        = DF_MAX_NBYTES_PER_LOOP;

    event->connection_pool_size
        = DF_CONN_POOL_SIZE;
}

nst_cfg_reload_status_e
nst_cfg_event_apply_modified(nst_cfg_event_t *event,
                             const nst_cfg_event_t *new_event)
{
    nst_cfg_reload_status_e reload_status =
        NST_CFG_RELOAD_STATUS_NO_CHANGE;

    if(event->max_nconnections != new_event->max_nconnections) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "maximum number of connections is changed. "
                    "restart is required");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
    }

    if(event->max_ntp_connections != new_event->max_ntp_connections) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "maximum number of TP connections is changed. "
                    "restart is required");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
    }

    if(event->connection_pool_size != new_event->connection_pool_size) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "connection pool size is changed. restart is required");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
    }

    if(event->max_nepoll_events_per_loop
       != new_event->max_nepoll_events_per_loop) {
        event->max_nepoll_events_per_loop
            = new_event->max_nepoll_events_per_loop;
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
    }

    if(event->max_naccepts_per_loop != new_event->max_naccepts_per_loop) {
        event->max_naccepts_per_loop = new_event->max_naccepts_per_loop;
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
    }

    if(event->max_nbytes_per_loop != new_event->max_nbytes_per_loop) {
        event->max_nbytes_per_loop = new_event->max_nbytes_per_loop;
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
    }

    if(event->max_nbytes_per_loop != new_event->max_nbytes_per_loop) {
        event->max_nbytes_per_loop = new_event->max_nbytes_per_loop;
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
    }

 DONE:
    return reload_status;
                    
}
