/* always include myself first */
#include "nst_cfg_log.h"

/* libnstcfg headers */
#include <nst_cfg_elt_data.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

/* libcore includes */
#include <nst_enum_type_helpers.h>

#define LOG_TARGET_TAG "target"
#define LOG_DIR_TAG    "dir"
#define LOG_SRV_IP_TAG "server"

typedef struct log_frame_data_s log_frame_data_t;

struct log_frame_data_s
{
    nst_cfg_log_t *ret_log;
};

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(log, nst_cfg_frame_data_empty_extra_free)

static void log_start_handler(void *udata,
                              const XML_Char *name,
                              const XML_Char **attrs);
static void log_end_handler(void *udata,
                            const XML_Char *name);

nst_cfg_reload_status_e
nst_cfg_log_apply_modified(nst_cfg_log_t *log,
                           const nst_cfg_log_t *new_log)
{
    nst_cfg_reload_status_e reload_status =
        NST_CFG_RELOAD_STATUS_NO_CHANGE;

    /* bug in nst_log.c. cannot change the log config */

    if(strcmp(log->target, new_log->target)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "log target has been changed. restart needed");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
        /* reload_status |= NST_CFG_RELOAD_STATUS_CHANGED; */
        /* strcpy(log->target, new_log->target); */
    }
    if(strcmp(log->dirname, new_log->dirname)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO, 
                    "log dirname has been changed. restart needed");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
        /* reload_status |= NST_CFG_RELOAD_STATUS_CHANGED; */
        /* strcpy(log->dirname, new_log->dirname); */
    }
    if(strcmp(log->srv_ip, new_log->srv_ip)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO, 
                    "log server IP has been changed. restart needed");
        reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
        goto DONE;
        /* reload_status |= NST_CFG_RELOAD_STATUS_CHANGED; */
        /* strcpy(log->srv_ip, new_log->srv_ip); */
    }

 DONE:
    return reload_status;
}

nst_status_e
nst_cfg_log_capture(void *udata,
                    const XML_Char *name,
                    const XML_Char **attrs,
                    void **plogcfg, void **unused1,
                    void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(log);

    nst_assert(plogcfg);
    log_frame_data->ret_log = (nst_cfg_log_t *)plogcfg;
    return NST_OK;
}

static nst_cfg_tag_action_t log_tag_actions[] = {
    { LOG_TARGET_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_log_t, target),
      0,
      0,
      0,
    },

    { LOG_DIR_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_log_t, dirname),
      0,
      0,
      0,
    },

    { LOG_SRV_IP_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_log_t, srv_ip),
      0,
      0,
      0,
    },

};

static void
log_start_handler(void *udata,
                  const XML_Char *name,
                  const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(log, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   log_tag_actions,
                   sizeof(log_tag_actions)/sizeof(log_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   log_frame_data->ret_log, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
log_end_handler(void *udata, const XML_Char *name)
{
    nst_cfg_log_t *ret_log;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(log);

    ret_log = log_frame_data->ret_log;

    ret = nst_cfg_tag_action_end_handler(
                   log_tag_actions,
                   sizeof(log_tag_actions)/sizeof(log_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   ret_log,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        nst_cfg_log_t *ret_log;
        ret_log = log_frame_data->ret_log;
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                      "captured <%s> "
                      "target \"%s\" dir \"%s\" srv-ip \"%s\" "
                      "at around line %ud",
                      current->name,
                      ret_log->target,
                      ret_log->dirname,
                      ret_log->srv_ip,
                      line_num);
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
