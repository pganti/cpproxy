/* always include myself first */
#include "nst_cfg_svc.h"

/* local includes */
#include "nst_accept.h"
#include "nst_connection.h"

/* libnst_cfg includes */
#include <nst_cfg_tag_action.h>
#include <nst_cfg_elt_data.h>
#include <nst_cfg_common.h>

/* libcore includes */
#include <nst_enum_type_helpers.h>
#include <nst_sockaddr.h>
#include <nst_log.h>
#include <nst_limits.h>
#include <nst_allocator.h>
#include <nst_assert.h>
#include <nst_errno.h>
#include <nst_types.h>

/* std and sys includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <string.h>

#define DF_LISTEN_BACKLOG               (1024) 
#define DF_POST_ACCEPT_TIMEOUT_MS       (60000)   /* 60 seconds */
#define DF_NEW_ACCEPTED_CONN_TPOOL_SIZE (256)
#define DF_NACCEPTS_PER_LOOP            (1024)

#define SERVICE_NAME_TAG   "name"
#define SERVICE_TYPE_TAG   "type"
#define VIP_INDEX_TAG      "vip-index"
#define PUBLIC_IP_TAG      "public-ip"
#define PORT_TAG           "port"
#define EDOMAIN_TAG        "effective-domain"
#define POST_ACCEPT_TIMEOUT_S_TAG "post-accept-timeout-s"
#define NOC_LOG_LEVEL_TAG  "noc-log-level"
#define DBG_LOG_LEVEL_TAG  "debug-log-level"

typedef struct svc_frame_data_s svc_frame_data_t;

struct svc_frame_data_s
{
    nst_cfg_svc_t **ret_svc;
    nst_cfg_svc_t *new_svc;
};

static void svc_start_handler(void *udata,
                              const XML_Char *name,
                              const XML_Char **attrs);

static void svc_end_handler(void *udata,
                            const XML_Char *name);

static void
nst_cfg_svc_do_free(void *data)
{
    nst_event_del_listener((nst_cfg_svc_t *)data);
    nst_allocator_free(&nst_cfg_allocator, data);
}

static inline nst_cfg_svc_t *
nst_cfg_svc_new(void)
{
    nst_cfg_svc_t *new_svc;

    new_svc = nst_allocator_calloc(&nst_cfg_allocator, 1,
                                   sizeof(nst_cfg_svc_t));
    if(new_svc) {
        new_svc->deferred_accept = 1;

        new_svc->backlog = DF_LISTEN_BACKLOG;
        new_svc->new_conn_mpool_size = DF_NEW_ACCEPTED_CONN_TPOOL_SIZE;
        new_svc->post_accept_timeout_ms = DF_POST_ACCEPT_TIMEOUT_MS;
        new_svc->naccepts_per_loop = DF_NACCEPTS_PER_LOOP;

        new_svc->noc_log_lvl = NST_LOG_LEVEL_DEFAULT;
        new_svc->dbg_log_lvl = NST_LOG_DEBUG_DEFAULT_LEVEL;
        NST_REFC_INIT(new_svc, nst_cfg_svc_do_free);
        return new_svc;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "cannot allocate svc_t object: %s(%d)",
                    nst_strerror(errno), errno);
        return NULL;
    }
}

void
nst_cfg_svc_free(void *data)
{
    NST_REFC_PUT((nst_cfg_svc_t *)data);

    return;
}

const char *nst_svc_type_str[] = {
    [NST_SVC_TYPE_UNKNOWN] = "unknown",
    [NST_SVC_TYPE_TUNNEL]  = "tunnel",
    [NST_SVC_TYPE_HTTP]    = "http",
    [NST_SVC_TYPE_TP]      = "mp",
    [NST_SVC_TYPE_TCP]     = "tcp",
};

nst_svc_type_e
nst_cfg_svc_type_from_str(const char *buf)
{
    return nst_enum_type_from_str(nst_svc_type_str,
                                  NST_SVC_TYPE_UNKNOWN,
                                  _NUM_NST_SVC_TYPE,
                                  NST_SVC_TYPE_UNKNOWN,
                                  buf);
}


const char *
nst_cfg_svc_type_to_str(nst_svc_type_e type) {
    return nst_enum_type_to_str(nst_svc_type_str,
                                NST_SVC_TYPE_UNKNOWN,
                                _NUM_NST_SVC_TYPE,
                                NST_SVC_TYPE_UNKNOWN,
                                type);
}

nst_status_e
nst_cfg_tag_action_set_svc_type(void *data0,
                                const nst_cfg_tag_action_t *action,
                                nst_expat_stack_frame_t *current,
                                const char *value,
                                size_t value_len)
{
    nst_svc_type_e *svc_type = (nst_svc_type_e *)((char *)(data0) + action->offset0);
    *svc_type = nst_cfg_svc_type_from_str(value);

    if(*svc_type == NST_SVC_TYPE_UNKNOWN) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static inline void
handle_svc_port(nst_expat_stack_frame_t *current,
                nst_cfg_svc_t *svc,
                const char *buf)
{
    int port = atoi(buf);

    if(port <= 0) {
        nst_cfg_log_capture_error(current->name,
                                  "port", TRUE,
                                  XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = TRUE;
        
    } else {
        /* The family must be initialized first! */
        nst_sockaddr_set_ip(&svc->listen_sockaddr, AF_INET, NULL);
        nst_sockaddr_set_port(&svc->listen_sockaddr, htons((in_port_t)port));
    }
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(svc,
                                      nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_svc_capture(void *udata,
                    const XML_Char *name,
                    const XML_Char **attrs,
                    void **ppsvc, void **unused1,
                    void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(svc);

    svc_frame_data->ret_svc = (nst_cfg_svc_t **)ppsvc;
    svc_frame_data->new_svc = nst_cfg_svc_new();

    if(svc_frame_data->new_svc) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }
}

static nst_cfg_tag_action_t svc_tag_actions[] = {
    { SERVICE_TYPE_TAG,
      nst_cfg_tag_action_set_svc_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cfg_svc_t, type),
      0,
      0,
      0,
    },


    { SERVICE_NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_svc_t, name),
      0,
      0,
      0,
    },


    { VIP_INDEX_TAG,
      nst_cfg_tag_action_set_uint32,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cfg_svc_t, vip_index),
      0,
      0,
      0,
    },


    { PUBLIC_IP_TAG,
      nst_cfg_tag_action_enable_bool,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cfg_svc_t, public_ip),
      0,
      0,
      0,
    },


    { EDOMAIN_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_svc_t, edomain_name),
      0,
      0,
      0,
    },


    { POST_ACCEPT_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cfg_svc_t, post_accept_timeout_ms),
      0,
      0,
      0,
    },

    { NOC_LOG_LEVEL_TAG,
      nst_cfg_tag_action_set_int,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_svc_t, noc_log_lvl),
      0,
      0,
      0,
    },

    { DBG_LOG_LEVEL_TAG,
      nst_cfg_tag_action_set_int,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_svc_t, dbg_log_lvl),
      0,
      0,
      0,
    },
};

static void
svc_start_handler(void *udata,
                  const XML_Char *name,
                  const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(svc, TRUE);

    if(!strcmp(name, PORT_TAG)) {
        if(nst_cfg_elt_data_capture(udata, name, attrs,
                                    current->tmp_elt_data,
                                    sizeof(current->tmp_elt_data),
                                    FALSE)) {
            nst_cfg_log_capture_error(current->name, name, FALSE, line_num);
            current->skip_on_error = TRUE;
        }
    } else {
        ret = nst_cfg_tag_action_start_handler(
                svc_tag_actions,
                sizeof(svc_tag_actions)/sizeof(svc_tag_actions[0]),
                current, udata,
                current->tmp_elt_data, sizeof(current->tmp_elt_data),
                svc_frame_data->new_svc, NULL,
                NULL, NULL,
                name, attrs);

        NST_CFG_UN_NESTED_START_HANDLER_FINALE();
    }
}

static void
svc_end_handler(void *udata,
                const XML_Char *name)
{
    nst_cfg_svc_t *new_svc;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(svc);

    new_svc = svc_frame_data->new_svc;
    if(!strcmp(name, PORT_TAG)) {
        handle_svc_port(current, new_svc,
                        current->tmp_elt_data);
    } else {
    
        ret = nst_cfg_tag_action_end_handler(
                  svc_tag_actions,
                  sizeof(svc_tag_actions)/sizeof(svc_tag_actions[0]),
                  current,
                  current->tmp_elt_data, current->child_ret,
                  svc_frame_data->new_svc,
                  name);
        if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
            current->skip_on_error = TRUE;
    }

    return;
        
 RET_TO_PARENT:
    
    if(!current->skip_on_error) {
        new_svc = *(svc_frame_data->ret_svc) = svc_frame_data->new_svc;
        svc_frame_data->new_svc = NULL; /* ownership transferred
                                         * to parent.
                                         */
        new_svc->edomain_name_len = strlen(new_svc->edomain_name);
        parent->child_ret = NST_OK;
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "captured <%s>: name=\"%s\" type=\"%s\" "
                    "vip-index=%ud public-ip=%d ssl=%d edomain-name=\"%s\"",
                    SERVICE_TAG,
                    new_svc->name,
                    nst_cfg_svc_type_to_str(new_svc->type),
                    new_svc->vip_index,
                    new_svc->public_ip,
                    new_svc->ssl,
                    new_svc->edomain_name);
                    
    } else {
        parent->child_ret = NST_ERROR;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

bool
nst_cfg_svc_is_http_like(const nst_cfg_svc_t *svc)
{
    switch(svc->type) {
    case NST_SVC_TYPE_TUNNEL:
    case NST_SVC_TYPE_TP:
        return TRUE;
    case NST_SVC_TYPE_HTTP:
    default:
        return FALSE;
    }
}

nst_cfg_reload_status_e
nst_cfg_svc_apply_modified(nst_cfg_svc_t *svc,
                           nst_cfg_svc_t *new_svc,
                           bool test_only_mode)
{
    nst_cfg_reload_status_e reload_status
        = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    if(strcmp(svc->name, new_svc->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "applying differences between two services with different "
                    "names. new service \"%s\" and current service \"%s\"",
                    new_svc->name, svc->name);
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }

    if(svc->type != new_svc->type) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the type of service \"%s\" type is changed from "
                    "\"%s\" to \"%s\". removing and adding it back",
                    new_svc->name,
                    nst_cfg_svc_type_to_str(svc->type),
                    nst_cfg_svc_type_to_str(new_svc->type));
        reload_status |= NST_CFG_RELOAD_STATUS_READD;
        goto DONE;
    }

    if(svc->vip_index != new_svc->vip_index) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the index of the service \"%s\" is changed from "
                    "\"%ud\" to \"%ud\". removing and adding it back",
                    new_svc->name,
                    svc->vip_index,
                    new_svc->vip_index);
        reload_status |= NST_CFG_RELOAD_STATUS_READD;
        goto DONE;
    }

    if(svc->public_ip != new_svc->public_ip) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the public IP of the service \"%s\" is changed from "
                    "\"%s\" to \"%s\". removing and adding it back",
                    new_svc->name,
                    svc->public_ip ? "TRUE" : "FALSE",
                    new_svc->public_ip ? "TRUE" : "FALSE");
        reload_status |= NST_CFG_RELOAD_STATUS_READD;
        goto DONE;
    }

    if(nst_sockaddr_get_port(&svc->listen_sockaddr)
       != nst_sockaddr_get_port(&new_svc->listen_sockaddr)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the IP port of the service \"%s\" is changed from "
                    "\"%ud\" to \"%ud\". removing and adding it back",
                    new_svc->name,
                    nst_sockaddr_get_port(&svc->listen_sockaddr),
                    nst_sockaddr_get_port(&new_svc->listen_sockaddr));
        reload_status |= NST_CFG_RELOAD_STATUS_READD;
        goto DONE;
    }

    if(svc->edomain_name_len != new_svc->edomain_name_len
       || strcmp(svc->edomain_name, new_svc->edomain_name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the effective domain of the service \"%s\" is "
                    "changed from  \"%s\" to \"%s\". "
                    "removing and adding it back",
                    new_svc->name,
                    svc->edomain_name,
                    new_svc->edomain_name);
        reload_status |= NST_CFG_RELOAD_STATUS_READD;
        goto DONE;
    }

    nst_assert(svc->tcp_ext == new_svc->tcp_ext);
    nst_assert(svc->handler == new_svc->handler);

    if(svc->post_accept_timeout_ms != new_svc->post_accept_timeout_ms) {
        int tcp_accept_timeout = new_svc->post_accept_timeout_ms;
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "the post-accept-timeout-ms of service \"%s\" "
                    "is changed from %ud to %ud",
                    new_svc->name,
                    svc->post_accept_timeout_ms,
                    new_svc->post_accept_timeout_ms);
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;

        if(!test_only_mode && svc->listener
           && setsockopt(svc->listener->conn->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                      &tcp_accept_timeout, sizeof(tcp_accept_timeout)) == -1) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot setsockopt(TCP_DEFER_ACCEPT) on service "
                        "\"%s\" during reload. restarting peacefully",
                        new_svc->name);
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            goto DONE;
        }

    }
            
    if(svc->dbg_log_lvl != new_svc->dbg_log_lvl
       || svc->noc_log_lvl != new_svc->noc_log_lvl) {
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
    }

    svc->dbg_log_lvl = new_svc->dbg_log_lvl;
    svc->noc_log_lvl = new_svc->noc_log_lvl;
    
 DONE:
    return reload_status;
}

NST_REFC_GENHASH_COPY_FUNC_DEF(nst_cfg_svc_s)
