#include "nst_cfg_ignore.h"

#include <nst_cfg_common.h>

static void ignore_start_handler(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs);

static void ignore_end_handler(void *udata,
                               const XML_Char *name);

typedef struct ignore_frame_data_s ignore_frame_data_t;
struct ignore_frame_data_s
{
    void **dummy_data;
};

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(ignore,
                                      nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_ignore(void *udata, const XML_Char *name,
               const XML_Char **attrs, void **not_used_data)
{
    NST_CFG_CAPTURE_PROLOGUE(ignore);

    return NST_OK;
}

static void ignore_start_handler(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(remote_dc, 0);

    (void)ret;
}


static void
ignore_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(ignore);

    (void)ret;

    return;

 RET_TO_PARENT:
    
    if(current->skip_on_error)
        parent->child_ret = NST_ERROR;
    else
        parent->child_ret = NST_OK;

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
