#include "nst_cpproxy_cfg_local_dc_box.h"
#include "nst_cfg_log.h"
#include "nst_cpproxy_cfg_local_proc.h"
#include "nst_cpproxy_cfg_box.h"
#include "nst_cpproxy_cfg_local_dc.h"
#include "nst_cpproxy_cfg.h"

#include <nst_cfg_sproxy.h>

#include <nst_cfg_ip_block.h>
#include <nst_cfg_box.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

#include <nst_string.h>
#include <nst_log.h>
#include <nst_errno.h>

#include <stddef.h>

static void box_start_handler(void *udata,
                                        const XML_Char *name,
                                        const XML_Char **attrs);
static void box_end_handler(void *udata, const XML_Char *name);
static nst_status_e add_my_proc(nst_cpproxy_cfg_local_dc_t *local_dc,
                                nst_cpproxy_cfg_local_proc_t *new_proc,
                                const nst_cpproxy_cfg_box_t *parsing_box,
				const nst_cfg_log_t *log);
static nst_status_e add_local_box(nst_cpproxy_cfg_local_dc_t *local_dc,
                                  const nst_cpproxy_cfg_box_t *parsing_box);


typedef struct box_frame_data_s box_frame_data_t;
struct box_frame_data_s
{
    nst_cpproxy_cfg_local_dc_t *local_dc;
    nst_cpproxy_cfg_local_proc_t *new_proc;

    nst_cpproxy_cfg_box_t parsing_box;

    struct nst_cfg_log_s log;

};

static void
box_extra_free(box_frame_data_t *fdata)
{
    nst_cpproxy_cfg_local_proc_free(fdata->new_proc);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(box, box_extra_free)

nst_status_e
nst_cpproxy_cfg_local_dc_box_capture(void *udata,
                                      const XML_Char *name,
                                      const XML_Char **attrs,
                                      void **plocal_dc, void **unused1,
                                     void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(box);

    nst_assert(plocal_dc);
    box_frame_data->local_dc =
        (nst_cpproxy_cfg_local_dc_t *)plocal_dc;

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
      nst_cpproxy_cfg_local_proc_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },
    { LOG_TAG,
      NULL,
      nst_cfg_log_capture,
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
    nst_cpproxy_cfg_local_dc_t *local_dc;
    void **cfg_obj;
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(box, TRUE);

    local_dc = box_frame_data->local_dc;
    if(!strcmp(name, PROC_TAG)) {
        cfg_obj = (void **)&box_frame_data->new_proc;
    } else {
        cfg_obj = (void **)&box_frame_data->parsing_box;
    }

    if(!strcmp(name, PROC_TAG)
       && 
       (local_dc->my_proc
        || 
        strcmp(box_frame_data->parsing_box.name, cpproxy_cfg.my_box_name)
       )
      ) {
        nst_cfg_log_ignore_tag(current->name, name, FALSE, line_num,
                               "not interested");
        nst_cfg_ignore(udata, name, attrs, NULL);
        return;
    }

    ret = nst_cfg_tag_action_start_handler(
                box_tag_actions,
                sizeof(box_tag_actions)/sizeof(box_tag_actions[0]),
                current, udata,
                current->tmp_elt_data, sizeof(current->tmp_elt_data),
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
    nst_cpproxy_cfg_local_dc_t *local_dc;
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

    local_dc = box_frame_data->local_dc;
    box = &box_frame_data->parsing_box;
    if(!strcmp(name, BOX_TYPE_TAG)) {
        switch(box->type) {
        case NST_CFG_BOX_TYPE_PROXY:
        case NST_CFG_BOX_TYPE_MISC:
        case NST_CFG_BOX_TYPE_CACHE:
            break;
        default:
            nst_cfg_log_ignore_tag(current->name,
                                   name,
                                   TRUE,
                                   line_num, "not interested");
            current->skip_on_ignore = TRUE;
            return;
        }
    } else if(!strcmp(name, BOX_TAG)) {
        if(add_local_box(local_dc, box) == NST_ERROR) {
            current->skip_on_error = TRUE;
        }
    } else if(!strcmp(name, PROC_TAG) && box_frame_data->new_proc) {
        if(add_my_proc(box_frame_data->local_dc,
                       box_frame_data->new_proc,
                       box,
                       &box_frame_data->log) == NST_ERROR) {
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
add_misc_box(nst_cpproxy_cfg_local_dc_t *local_dc,
             const nst_cpproxy_cfg_box_t *parsing_box)
{
    return NST_OK;
}

static nst_status_e
add_cache_box(nst_cpproxy_cfg_local_dc_t *local_dc,
              const nst_cpproxy_cfg_box_t *parsing_box)
{
    return NST_OK;
}

static nst_status_e
add_my_proc(nst_cpproxy_cfg_local_dc_t *local_dc,
            nst_cpproxy_cfg_local_proc_t *new_proc,
            const nst_cpproxy_cfg_box_t *parsing_box,
            const nst_cfg_log_t *log)
{
    nst_status_e ret = NST_OK;
    int snprintf_ret;

    if(strcmp(new_proc->cmd, NST_CPPROXY_CFG_CMD_NAME)) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "<%s> parsing verbose: ignored process "
                    "\"%s@%s@%s\". not interested",
                    BOX_TAG,
                    new_proc->cmd,
                    parsing_box->name,
                    local_dc->name);
        nst_cpproxy_cfg_local_proc_free(new_proc);
        return NST_OK;
    }

    snprintf_ret = snprintf(new_proc->sysid, sizeof(new_proc->sysid),
                            "%s@%s@%s",
                            new_proc->cmd,
                            parsing_box->name,
                            local_dc->name);
    if(snprintf_ret <=0
       || (nst_uint_t)snprintf_ret >= sizeof(new_proc->sysid)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "sysid \"%s@%s@%s\" length > %ud",
                    NST_CPPROXY_CFG_CMD_NAME,
                    parsing_box->name,
                    local_dc->name,
                    NST_MAX_SYSID_BUF_SIZE - 1);
        ret = NST_ERROR;
        goto DONE;
    }
                        
    memcpy(&new_proc->box, parsing_box, sizeof(nst_cpproxy_cfg_box_t));
    memcpy(&new_proc->log, log, sizeof(new_proc->log));

    local_dc->my_proc = new_proc;

 DONE:
    if(ret == NST_OK) {
        return NST_OK;
    } else {
        nst_cpproxy_cfg_local_proc_free(new_proc);
        return ret;
    }
}

static nst_status_e
add_local_box(nst_cpproxy_cfg_local_dc_t *local_dc,
              const nst_cpproxy_cfg_box_t *parsing_box)
{
    switch(parsing_box->type) {
    case NST_CFG_BOX_TYPE_MISC:
        return add_misc_box(local_dc, parsing_box);
    case NST_CFG_BOX_TYPE_CACHE:
        return add_cache_box(local_dc, parsing_box);
    case NST_CFG_BOX_TYPE_UNKNOWN:
    case NST_CFG_BOX_TYPE_PROXY:
    case NST_CFG_BOX_TYPE_LVS:
    default:
        break;
    }

    return NST_OK;
}
