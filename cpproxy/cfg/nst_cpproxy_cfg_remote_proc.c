#include "nst_cpproxy_cfg_remote_proc.h"

#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>
#include <nst_cfg.h>

#include <nst_allocator.h>
#include <nst_errno.h>

#include <stddef.h>

nst_cpproxy_cfg_remote_proc_t *
nst_cpproxy_cfg_remote_proc_new(void)
{
    nst_cpproxy_cfg_remote_proc_t *new_proc_cfg =
        nst_allocator_calloc(&nst_cfg_allocator,
                             1,
                             sizeof(nst_cpproxy_cfg_remote_proc_t));

    if(!new_proc_cfg)
        return NULL;

    if(nst_cpproxy_cfg_listen_init(&new_proc_cfg->listen) == NST_OK) {
        return new_proc_cfg;
    } else {
        nst_allocator_free(&nst_cfg_allocator, new_proc_cfg);
        return NULL;
    }
}

void
nst_cpproxy_cfg_remote_proc_free(void *data)
{
    nst_cpproxy_cfg_remote_proc_t *proc_cfg;

    if(!data)
        return;

    proc_cfg = (nst_cpproxy_cfg_remote_proc_t *)data;
    nst_cpproxy_cfg_listen_reset(&proc_cfg->listen);
    
    nst_allocator_free(&nst_cfg_allocator, proc_cfg);
}

typedef struct proc_frame_data_s proc_frame_data_t;
struct proc_frame_data_s
{
    nst_cpproxy_cfg_remote_proc_t      **ret_proc;
    nst_cpproxy_cfg_remote_proc_t      *new_proc;
};

static void
proc_extra_free(proc_frame_data_t *fdata)
{
    nst_cpproxy_cfg_remote_proc_free(fdata->new_proc);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(proc, proc_extra_free)

static void proc_start_handler(void *udata,
                                         const XML_Char *name,
                               const XML_Char **attrs);
static void proc_end_handler(void *udata,
                               const XML_Char *name);

nst_status_e
nst_cpproxy_cfg_remote_proc_capture(void *udata,
                                    const XML_Char *name,
                                    const XML_Char **attrs,
                                    void **ppnew_proc, void **unused1,
                                    void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(proc);

    nst_assert(ppnew_proc);

    proc_frame_data->ret_proc = (nst_cpproxy_cfg_remote_proc_t **)ppnew_proc;
    proc_frame_data->new_proc = nst_cpproxy_cfg_remote_proc_new();

    if(proc_frame_data->new_proc) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }

}

static nst_cfg_tag_action_t proc_tag_actions[] = {
    { PROC_CMD_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cpproxy_cfg_remote_proc_t, cmd),
      0,
      0,
      0,
    },

    { LISTEN_TAG,
      NULL,
      nst_cpproxy_cfg_listen_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_remote_proc_t, listen),
      0,
      0,
      0,
    },

};

static void proc_start_handler(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(proc, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                proc_tag_actions,
                sizeof(proc_tag_actions)/sizeof(proc_tag_actions[0]),
                current, udata,
                current->tmp_elt_data, sizeof(current->tmp_elt_data),
                proc_frame_data->new_proc, NULL,
                NULL, NULL,
                name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void proc_end_handler(void *udata,
                             const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(proc);

    ret = nst_cfg_tag_action_end_handler(
                  proc_tag_actions,
                  sizeof(proc_tag_actions)/sizeof(proc_tag_actions[0]),
                  current,
                  current->tmp_elt_data, current->child_ret,
                  proc_frame_data->new_proc,
                  name);

    if(ret == NST_ERROR) {
        if(errno != EPROTONOSUPPORT && errno != ENOENT) {
            current->skip_on_error = TRUE;
        }
    }

    return;

 RET_TO_PARENT:

    if(!current->skip_on_error) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "captured one remote proc %s cmd and %ud services at around line %ud",
                    proc_frame_data->new_proc->cmd,
                    nst_genhash_get_nelts(proc_frame_data->new_proc->listen.ref_name_ghash),
                    line_num);
        *(proc_frame_data->ret_proc) = proc_frame_data->new_proc;
        proc_frame_data->new_proc = NULL;
        parent->child_ret = NST_OK;
    } else {
        parent->child_ret = NST_ERROR;
    }
    
    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
