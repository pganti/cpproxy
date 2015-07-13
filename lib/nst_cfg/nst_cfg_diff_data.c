#include "nst_cfg_diff_data.h"

#include <nst_cfg_common.h>
#include <nst_cfg_tag_action.h>

#include <nst_allocator.h>
#include <nst_genhash.h>
#include <nst_assert.h>
#include <nst_log.h>

#define NAME_TAG "name"

typedef struct diff_data_frame_data_s diff_data_frame_data_t;

struct diff_data_frame_data_s
{
    nst_genhash_t *ghash;
    nst_cfg_diff_data_t *new_diff_data;
};

static void diff_data_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void diff_data_end_handler(void *udata,
                                 const XML_Char *name);


NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(diff_data,
                                       nst_cfg_frame_data_empty_extra_free);

nst_status_e
nst_cfg_diff_data_capture(void *udata,
                          const XML_Char *name,
                          const XML_Char **attrs,
                          void **ppghash, void **unused1,
                          void **unused2, void **unused3)

{
    NST_CFG_CAPTURE_PROLOGUE(diff_data);

    nst_assert(ppghash);
    diff_data_frame_data->ghash = *(nst_genhash_t **)ppghash;
    nst_assert(diff_data_frame_data->ghash);
 
    return NST_OK;
}

static nst_cfg_tag_action_t diff_data_tag_actions[] = {
    { NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_diff_data_t, name) ,
      0,
      0,
      0,
    },
};

static void
diff_data_start_handler(void *udata,
                        const XML_Char *name,
                        const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(diff_data, TRUE);

    if(!diff_data_frame_data->new_diff_data) {
        diff_data_frame_data->new_diff_data = nst_cfg_diff_data_new();
        if(!diff_data_frame_data->new_diff_data) {
            current->skip_on_error = TRUE;
            return;
        }
    }

   ret = nst_cfg_tag_action_start_handler(
                   diff_data_tag_actions,
                   sizeof(diff_data_tag_actions)/sizeof(diff_data_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data,
                   sizeof(current->tmp_elt_data),
                   diff_data_frame_data->new_diff_data, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void diff_data_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(diff_data);

    ret = nst_cfg_tag_action_end_handler(
                   diff_data_tag_actions,
                   sizeof(diff_data_tag_actions)/sizeof(diff_data_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   diff_data_frame_data->new_diff_data,
                   name);

    if(ret == NST_OK) {
        if(nst_genhash_add(diff_data_frame_data->ghash,
                           diff_data_frame_data->new_diff_data->name,
                           diff_data_frame_data->new_diff_data)
           == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add %s to genhash at around line %ud. %s(%d). "
                        "ignored.",
                        diff_data_frame_data->new_diff_data->name,
                        line_num,
                        strerror(errno), errno);
        } else {
            /* ownership has been taken */
            diff_data_frame_data->new_diff_data = NULL;
        }
    } else if(errno != ENOENT && errno != EPROTONOSUPPORT) {
        current->skip_on_error = TRUE;
    }

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

nst_cfg_diff_data_t *
nst_cfg_diff_data_new(void)
{
    return nst_allocator_calloc(&nst_cfg_allocator, 1,
                                sizeof(nst_cfg_diff_data_t));
}

void
nst_cfg_diff_data_free(nst_cfg_diff_data_t *diff_data)
{
    if(!diff_data)
        return;

    if(diff_data->data && diff_data->data_free)
        diff_data->data_free(diff_data->data);

    nst_allocator_free(&nst_cfg_allocator, diff_data);
}

uint32_t
nst_cfg_diff_data_genhash(const void *diff_data)
{
    return nst_genhash_cstr( ((const nst_cfg_diff_data_t *)diff_data)->name );
}

int
nst_cfg_diff_data_cmp(const void *diff_data1,
                      const void *diff_data2)
{
    return nst_genhash_cstr_cmp( ((nst_cfg_diff_data_t *)diff_data1)->name,
                                 ((nst_cfg_diff_data_t *)diff_data2)->name);
}
