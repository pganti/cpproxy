#include "nst_cpproxy_cfg_local_dc.h"

#include "nst_cpproxy_cfg_local_proc.h"
#include "nst_cpproxy_cfg_local_dc_box.h"
#include "nst_cpproxy_cfg.h"

#include <nst_cfg_vips.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_common.h>

#include <nst_log.h>
#include <nst_assert.h>
#include <nst_errno.h>
#include <nst_types.h>

#include <expat.h>
#include <string.h>
#include <stddef.h>

#define CAPTURING_ENTITY_TAG "cluster"
#define NAME_TAG             "name"
#define TYPE_TAG             "type"
#define VIPS_TAG             "vips"

static void dc_start_handler(void *udata,
                                       const XML_Char *name,
                                       const XML_Char **attrs);
static void dc_end_handler(void *udata,
                                 const XML_Char *name);

typedef struct dc_frame_data_s dc_frame_data_t;
struct dc_frame_data_s
{
    nst_cpproxy_cfg_local_dc_t **ret_local_dc;
    nst_cpproxy_cfg_local_dc_t *new_local_dc;
};

static void
dc_extra_free(dc_frame_data_t *frame_data)
{
    if(!frame_data)
        return;

    
    nst_cpproxy_cfg_local_dc_free(frame_data->new_local_dc);
}


NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(dc, dc_extra_free)

static inline nst_cpproxy_cfg_local_dc_t *
nst_cpproxy_cfg_local_dc_new(void)
{
    return nst_allocator_calloc(&nst_cfg_allocator,
                                1,
                                sizeof(nst_cpproxy_cfg_local_dc_t));
}

void
nst_cpproxy_cfg_local_dc_free(void *data)
{
    nst_cpproxy_cfg_local_dc_t *local_dc =
        (nst_cpproxy_cfg_local_dc_t *)data;

    if(!local_dc)
        return;

    nst_cpproxy_cfg_local_proc_free(local_dc->my_proc);
    nst_cfg_vips_free(local_dc->vips);
    nst_allocator_free(&nst_cfg_allocator, local_dc);
}

static nst_status_e
nst_cpproxy_cfg_local_dc_capture(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs,
                                 void **ret_local_dc, void **unused1,
                                 void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(dc);

    nst_assert(ret_local_dc);
    dc_frame_data->ret_local_dc = 
        (nst_cpproxy_cfg_local_dc_t **)ret_local_dc;

    dc_frame_data->new_local_dc = nst_cpproxy_cfg_local_dc_new();
    if(dc_frame_data->new_local_dc) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }
}

static void
local_dc_log_debug_details(const nst_cpproxy_cfg_local_dc_t *local_dc)
{
    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "captured local <cluster> name=\"%s\" type=\"%s\"",
                local_dc->name, nst_cfg_dc_type_to_str(local_dc->type));
}

static bool
validate_local_dc(const nst_cpproxy_cfg_local_dc_t *local_dc)
{
    if(!local_dc->my_proc) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "cannot find process config for %s@%s@%s",
                    NST_CPPROXY_CFG_CMD_NAME,
                    cpproxy_cfg.my_box_name,
                    cpproxy_cfg.my_dc_name);
        return FALSE;
    } else {
        return TRUE;
    }
}

nst_cfg_tag_action_t dc_tag_actions[] = {
    { NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cpproxy_cfg_local_dc_t, name),
      0,
      0,
      0,
    },

    { TYPE_TAG,
      nst_cfg_tag_action_set_dc_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cpproxy_cfg_local_dc_t, type),
      0,
      0,
      0,
    },


    { VIPS_TAG,
      NULL,
      nst_cfg_vips_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_local_dc_t, vips),
      0,
      0,
      0,
    },


    { BOX_TAG,
      NULL,
      nst_cpproxy_cfg_local_dc_box_capture,
      TRUE,
      0,
      0,
      0,
      0,
      0,
    },
};

static void
dc_start_handler(void *udata, const XML_Char *name, const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(dc, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   dc_tag_actions,
                   sizeof(dc_tag_actions)/sizeof(dc_tag_actions[0]),
                   current,  udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   dc_frame_data->new_local_dc, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
dc_end_handler(void *udata, const XML_Char *name)
{
    nst_cpproxy_cfg_local_dc_t *new_local_dc;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(dc);

    new_local_dc = dc_frame_data->new_local_dc;

    ret = nst_cfg_tag_action_end_handler(
                   dc_tag_actions,
                   sizeof(dc_tag_actions)/sizeof(dc_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   new_local_dc,
                   name);


    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;
        
 RET_TO_PARENT:
    
    if(!current->skip_on_error && !current->skip_on_ignore
       && validate_local_dc(dc_frame_data->new_local_dc)) {
        local_dc_log_debug_details(dc_frame_data->new_local_dc);
        *(dc_frame_data->ret_local_dc) =
            dc_frame_data->new_local_dc;
        dc_frame_data->new_local_dc = NULL; /* ownership transferred
                                             * to parent.
                                             */
        parent->child_ret = NST_OK;
    } else {
        parent->child_ret = NST_ERROR;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

nst_status_e
nst_cpproxy_cfg_local_dc_read(nst_cpproxy_cfg_local_dc_t **local_dc,
                              const char *my_dc_name,
                              const nst_cpproxy_cfg_dir_names_t *dir_names)
{
    u_char full_local_dc_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];

    nst_cfg_file_read_ctx_t local_dc_read_ctx = {
        .entity_start_tag = CAPTURING_ENTITY_TAG,
        .capture = nst_cpproxy_cfg_local_dc_capture,
        .capture_data0 = (void **)local_dc,
        .capture_data1 = NULL,
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_cb = NULL,
        .done_data = NULL,
    };

    if(nst_snprintf(full_local_dc_filename,
                    sizeof(full_local_dc_filename),
                    "%s%c%s%s",
                    dir_names->dcs,
                    NST_DIR_DELIMITER_CHAR,
                    my_dc_name,
                    NST_CFG_FILENAME_EXT)
       >= full_local_dc_filename + sizeof(full_local_dc_filename)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "\"%s%c%s%s\" length is too long > %ud",
                    dir_names->dcs,
                    NST_DIR_DELIMITER_CHAR,
                    my_dc_name,
                    NST_CFG_FILENAME_EXT,
                    sizeof(full_local_dc_filename));
    }
                    
    return nst_cfg_file_read((char *)full_local_dc_filename,
                             &local_dc_read_ctx);
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_local_dc_apply_modified(nst_cpproxy_cfg_local_dc_t *my_dc,
                                        nst_cpproxy_cfg_local_dc_t *my_new_dc,
                                        bool *relisten,
                                        bool *reset_log_cfg)
{
    nst_cfg_reload_status_e reload_status
        = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    if(strcmp(my_dc->name, my_new_dc->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "my cluster name is changed from \"%s\" to \"%s\" "
                    "restart is needed",
                    my_dc->name, my_new_dc->name);
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }

    if(my_dc->type != my_new_dc->type) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "my cluster type is changed from \"%s\" to \"%s\" "
                    "restart is needed",
                    nst_cfg_dc_type_to_str(my_dc->type),
                    nst_cfg_dc_type_to_str(my_new_dc->type));
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }
    
    if((my_dc->vips ? 0 : 1) != (my_new_dc->vips ? 0 : 1)
       || 
       (my_dc->vips && !nst_cfg_vips_is_equal(my_dc->vips, my_new_dc->vips))
       ) {
        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        *relisten = TRUE;
        nst_cfg_vips_free(my_dc->vips);
        my_dc->vips = my_new_dc->vips;
        my_new_dc->vips = NULL;
    }

    if(!(reload_status & NST_CFG_RELOAD_STATUS_CHANGED)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "nothing has changed in local cluster \"%s\"",
                    my_new_dc->name);
    }

 DONE:
    return reload_status;
}
