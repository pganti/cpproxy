/* always include myself first */
#include "nst_cfg_log_fac.h"

/* local headers */
#include "nst_cpproxy_cfg_local_proc.h"

/* libnstcfg headers */
#include <nst_cfg_elt_data.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

/* libcore includes */
#include <nst_enum_type_helpers.h>

#define LOG_FAC_TYPE_TAG   "type"
#define LOG_FAC_LVL_TAG    "level"

static const char *nst_log_type_str[] = {
    [0] = "unknown",
    [NST_LOG_TYPE_NOC]    = "noc",
    [NST_LOG_TYPE_ACCESS] = "access",
    [NST_LOG_TYPE_DEBUG]  = "debug",
    [NST_LOG_TYPE_AUDIT]  = "audit",
};

static const char *
nst_log_type_to_str(enum nst_log_facility_type type)
{
    return nst_enum_type_to_str(nst_log_type_str,
                                0,
                                sizeof(nst_log_type_str)/sizeof(nst_log_type_str[0]),
                                0,
                                type);
}

static enum nst_log_facility_type
nst_log_type_from_str(const char *str)
{
    return nst_enum_type_from_str(nst_log_type_str,
                                  0,
                                  sizeof(nst_log_type_str)/sizeof(nst_log_type_str[0]),
                                  0,
                                  str);
}

static nst_status_e
nst_cfg_tag_action_set_log_type(void *cfg_obj,
                                const nst_cfg_tag_action_t *action,
                                nst_expat_stack_frame_t *current,
                                const char *value,
                                size_t value_len)
{
    enum nst_log_facility_type *log_type = (enum nst_log_facility_type *)((char *)(cfg_obj) + action->offset0);
    *log_type = nst_log_type_from_str(value);

    if(*log_type == 0) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static nst_status_e
nst_cfg_tag_action_set_log_lvl(void *cfg_obj,
                               const nst_cfg_tag_action_t *action,
                               nst_expat_stack_frame_t *current,
                               const char *value,
                               size_t value_len)
{
    enum nst_log_level *log_lvl = (enum nst_log_level *)((char *)(cfg_obj) + action->offset0);
    *log_lvl = atoi(value);

    if(*log_lvl < NST_LOG_LEVEL_CRITICAL || *log_lvl > NST_LOG_LEVEL_VERBOSE) {
        nst_cfg_log_capture_error(current->name,
                                  action->tag, TRUE, 
                                  XML_GetCurrentLineNumber(current->parser));
        errno = EINVAL;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

typedef struct log_fac_frame_data_s log_fac_frame_data_t;

struct log_fac_frame_data_s
{
    nst_cpproxy_cfg_local_proc_t *my_proc;
    nst_log_facility_type_t type;
    nst_log_level_t lvl;
};

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(log_fac,
                                      nst_cfg_frame_data_empty_extra_free)

static void log_fac_start_handler(void *udata,
                                  const XML_Char *name,
                                  const XML_Char **attrs);
static void log_fac_end_handler(void *udata,
                                const XML_Char *name);

nst_status_e
nst_cfg_log_fac_capture(void *udata,
                        const XML_Char *name,
                        const XML_Char **attrs,
                        void **pmyproc, void **unused1,
                        void **unused2, void **unused3)

{
    NST_CFG_CAPTURE_PROLOGUE(log_fac);

    nst_assert(pmyproc);
    log_fac_frame_data->my_proc = (nst_cpproxy_cfg_local_proc_t *)pmyproc;
    return NST_OK;
}

static nst_cfg_tag_action_t log_fac_tag_actions[] = {
    { LOG_FAC_TYPE_TAG,
      nst_cfg_tag_action_set_log_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(log_fac_frame_data_t, type),
      0,
      0,
      0,
    },

    { LOG_FAC_LVL_TAG,
      nst_cfg_tag_action_set_log_lvl,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(log_fac_frame_data_t, lvl),
      0,
      0,
      0,
    },
};

static void
log_fac_start_handler(void *udata,
                      const XML_Char *name,
                      const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(log_fac, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   log_fac_tag_actions,
                   sizeof(log_fac_tag_actions)/sizeof(log_fac_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   log_fac_frame_data, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
log_fac_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(log_fac);

    ret = nst_cfg_tag_action_end_handler(
                   log_fac_tag_actions,
                   sizeof(log_fac_tag_actions)/sizeof(log_fac_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   log_fac_frame_data,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        nst_log_level_t *ret_log_lvl;
        nst_cpproxy_cfg_local_proc_t *my_proc;
        my_proc = log_fac_frame_data->my_proc;
        switch(log_fac_frame_data->type) {
        case NST_LOG_TYPE_NOC:
            ret_log_lvl = &my_proc->noc_log_lvl;
            break;
        case NST_LOG_TYPE_DEBUG:
            ret_log_lvl = &my_proc->dbg_log_lvl;
            break;
        default:
            ret_log_lvl = NULL;
        }

        if(ret_log_lvl) {
            /* good case */
            NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                        "log-facility type \"%s\" level \"%d\" "
                        "at around line %ud",
                        nst_log_type_to_str(log_fac_frame_data->type),
                        log_fac_frame_data->lvl,
                        line_num);
            *ret_log_lvl = log_fac_frame_data->lvl;
        }
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
