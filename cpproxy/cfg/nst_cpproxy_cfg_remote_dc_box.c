#include "nst_cpproxy_cfg_remote_dc_box.h"

#include "nst_cpproxy_cfg_remote_proc.h"
#include "nst_cpproxy_cfg_box.h"
#include "nst_cpproxy_cfg_remote_dc.h"
#include "nst_cpproxy_cfg.h"

#include <nst_cfg_sproxy.h>

#include <nst_cfg_ip_block.h>
#include <nst_cfg_box.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

#include <nst_log.h>
#include <nst_errno.h>

#include <stddef.h>

static void box_start_handler(void *udata,
                              const XML_Char *name,
                              const XML_Char **attrs);
static void box_end_handler(void *udata, const XML_Char *name);
static nst_status_e
add_remote_proxy_proc(nst_cpproxy_cfg_remote_dc_t *remote_dc,
                      nst_cpproxy_cfg_remote_proc_t *new_proc,
                      const nst_cpproxy_cfg_box_t *parsing_box);

typedef struct box_frame_data_s box_frame_data_t;
struct box_frame_data_s
{
    nst_cpproxy_cfg_remote_dc_t *remote_dc;
    nst_cpproxy_cfg_remote_proc_t *new_proc;

    nst_cpproxy_cfg_box_t parsing_box;
};

static void
box_extra_free(box_frame_data_t *fdata)
{
    nst_cpproxy_cfg_remote_proc_free(fdata->new_proc);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(box, box_extra_free)

nst_status_e
nst_cpproxy_cfg_remote_dc_box_capture(void *udata,
                                      const XML_Char *name,
                                      const XML_Char **attrs,
                                      void **premote_dc, void **unused1,
                                      void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(box);

    nst_assert(premote_dc);
    box_frame_data->remote_dc =
        (nst_cpproxy_cfg_remote_dc_t *)premote_dc;

    return NST_OK;
}

static nst_cfg_tag_action_t box_tag_actions[] = {
    { BOX_TYPE_TAG,
      nst_cfg_tag_action_set_box_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cpproxy_cfg_box_t, type),
      0,
      0,
      0,
    },

    { BOX_NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cpproxy_cfg_box_t, name),
      0,
      0,
      0,
    },

    { BOX_NATTED_FRONTEND_IP_TAG,
      NULL,
      nst_cfg_ip_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_box_t, natted_frontend_ip),
      0,
      0,
      0,
    },

    { BOX_FRONTEND_IP_TAG,
      NULL,
      nst_cfg_ip_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_box_t, frontend_ip),
      0,
      0,
      0,
    },

    { BOX_BACKEND_IP_TAG,
      NULL,
      nst_cfg_ip_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_box_t, backend_ip),
      0,
      0,
      0,
    },

    { PROC_TAG,
      NULL,
      nst_cpproxy_cfg_remote_proc_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },

};

static void box_start_handler(void *udata,
                                        const XML_Char *name,
                                        const XML_Char **attrs)
{
    void **cfg_obj;
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(box, TRUE);

    if(!strcmp(name, PROC_TAG))
        cfg_obj = (void **)&box_frame_data->new_proc;
    else
        cfg_obj = (void **)&box_frame_data->parsing_box;

    ret = nst_cfg_tag_action_start_handler(
                box_tag_actions,
                sizeof(box_tag_actions)/sizeof(box_tag_actions[0]),
                current, udata,
                current->tmp_elt_data,
                sizeof(current->tmp_elt_data),
                cfg_obj, NULL,
                NULL, NULL,
                name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
box_end_handler(void *udata,
                          const XML_Char *name)
{
    nst_cpproxy_cfg_box_t  *box;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(box);

    box = &box_frame_data->parsing_box;
    ret = nst_cfg_tag_action_end_handler(
                  box_tag_actions,
                  sizeof(box_tag_actions)/sizeof(box_tag_actions[0]),
                  current,
                  current->tmp_elt_data, current->child_ret,
                  &box_frame_data->parsing_box,
                  name);

    if(ret == NST_ERROR) {
        if(errno == ENOENT) {
            return;
        } else if(errno != EPROTONOSUPPORT) {
            current->skip_on_error = TRUE;
            return;
        }
    }

    /* I am only interested to the proxy boxes on remote dc */
    box = &box_frame_data->parsing_box;
    if(!strcmp(name, BOX_TYPE_TAG)) {
        switch(box->type) {
        case NST_CFG_BOX_TYPE_PROXY:
            return;
        default:
            break;
        }
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "ignored <box>/<type> \"%s\" at around line %ud. "
                    "not interested",
                    nst_cfg_box_type_to_str(box->type),
                    line_num);

        current->skip_on_ignore = TRUE;
    } else if(!strcmp(name, PROC_TAG)) {
        if(add_remote_proxy_proc(box_frame_data->remote_dc,
                                 box_frame_data->new_proc,
                                 box) == NST_ERROR) {
            current->skip_on_error = TRUE;
        }
        box_frame_data->new_proc = NULL;
    }

    return;

 RET_TO_PARENT:

    if(current->skip_on_error)
        parent->child_ret = NST_ERROR;
    else
        parent->child_ret = NST_OK;

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

static nst_status_e
add_remote_proxy_proc(nst_cpproxy_cfg_remote_dc_t *remote_dc,
                      nst_cpproxy_cfg_remote_proc_t *new_proc,
                      const nst_cpproxy_cfg_box_t *parsing_box)
{
    nst_status_e ret = NST_OK;
    int snprintf_ret;

    if(strcmp(new_proc->cmd, NST_CPPROXY_CFG_CMD_NAME)) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "ignore remote process \"%s@s%s\". not interested",
                    new_proc->cmd, parsing_box->name, remote_dc->name);
        nst_cpproxy_cfg_remote_proc_free(new_proc);
        return NST_OK;
    }

    snprintf_ret = snprintf(new_proc->sysid, sizeof(new_proc->sysid),
                            "%s@%s@%s",
                            NST_CPPROXY_CFG_CMD_NAME,
                            parsing_box->name,
                            remote_dc->name);
    if(snprintf_ret <=0 || (nst_uint_t)snprintf_ret >= sizeof(new_proc->sysid)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "sysid \"%s@%s@%s\" length > %ud",
                    NST_CPPROXY_CFG_CMD_NAME,
                    parsing_box->name,
                    remote_dc->name,
                    sizeof(new_proc->sysid) - 1);
        ret = NST_ERROR;
        goto DONE;
    }
                        
    memcpy(&new_proc->box, parsing_box, sizeof(nst_cpproxy_cfg_box_t));
    if(nst_genhash_add(remote_dc->sproxy_proc_ghash,
                       new_proc->sysid, new_proc) == NST_ERROR) {
        if(errno == EEXIST) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "duplicate remote \"%s\" found",
                        new_proc->sysid);
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add remote \"%s\" to ghash. "
                        "%s(%d)",
                        new_proc->sysid);
        }
        ret = NST_ERROR;
    }

 DONE:
    if(ret == NST_OK) {
        return NST_OK;
    } else {
        nst_cpproxy_cfg_remote_proc_free(new_proc);
        return ret;
    }
}
