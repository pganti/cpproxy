#include "nst_cfg_version.h"

#include "nst_cfg_elt_data.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_common.h"

#include <nst_types.h>

#include <nst_assert.h>

typedef struct version_frame_data_s version_frame_data_t;

struct version_frame_data_s
{
    nst_uint_t *ret_version;
};

static void version_start_handler(void *udata,
                                  const XML_Char *name,
                                  const XML_Char **attrs);
static void version_end_handler(void *udata,
                                const XML_Char *name);

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(version, nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_version_capture(void *udata,
                        const XML_Char *name,
                        const XML_Char **attrs,
                        void **pversion, void **unused1,
                        void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(version);

    nst_assert(pversion);
    version_frame_data->ret_version 
        = (nst_uint_t *)pversion;

    if(nst_cfg_elt_data_capture(udata, name, attrs,
                                current->tmp_elt_data,
                                sizeof(current->tmp_elt_data),
                                FALSE)
       != NST_OK) {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static nst_cfg_tag_action_t version_tag_actions[] = {
    { NST_CFG_VERSION_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },
};

static void
version_start_handler(void *udata,
                   const XML_Char *name,
                   const XML_Char **attrs)
{
    nst_assert(0 && "should never reach here");
}

static
void version_end_handler(void *udata, const XML_Char *name)
{
    nst_status_e ret = NST_OK;
    nst_expat_stack_frame_t *parent;
    nst_expat_stack_frame_t *current;
    struct version_frame_data_s *version_frame_data;
    nst_uint_t line_num;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    version_frame_data = (version_frame_data_t *)current->data;
    line_num = XML_GetCurrentLineNumber(current->parser);

    if(strcmp(name, current->name)) {
        current->skip_on_error = TRUE;
    }

    if(current->child_ret == NST_ERROR) {
        nst_cfg_log_capture_error(current->name, name, TRUE, line_num);
        current->skip_on_error = 1;
    }

    if(current->skip_on_ignore || current->skip_on_error)
        goto RET_TO_PARENT;

    ret = nst_cfg_tag_action_end_handler(
                   version_tag_actions,
                   sizeof(version_tag_actions)/sizeof(version_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   version_frame_data->ret_version,
                   name);

    if(ret == NST_ERROR)
        current->skip_on_error = TRUE;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
