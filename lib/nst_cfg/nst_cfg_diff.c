#include "nst_cfg_diff.h"

#include <nst_cfg_diff_block.h>
#include <nst_cfg_common.h>
#include <nst_cfg_tag_action.h>

#include <nst_assert.h>

#define OLD_VERSION_TAG "old-version"
#define MODIFIED_TAG    "modified"
#define REMOVED_TAG     "removed"
#define ADDED_TAG       "added"

typedef struct diff_frame_data_s diff_frame_data_t;

struct diff_frame_data_s
{
    nst_cfg_diff_t *diff;
};

static void diff_start_handler(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs);
static void diff_end_handler(void *udata,
                             const XML_Char *name);

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(diff, nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_diff_capture(void *udata,
                     const XML_Char *name,
                     const XML_Char **attrs,
                     void **pdiff, void **unused1,
                     void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(diff);

    nst_assert(pdiff);
    diff_frame_data->diff 
        = (nst_cfg_diff_t *)pdiff;
    return NST_OK;
}

static nst_cfg_tag_action_t diff_tag_actions[] = {
    { OLD_VERSION_TAG,
      nst_cfg_tag_action_set_uint,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_t, old_version),
      0,
      0,
      0,
    },

    { MODIFIED_TAG,
      NULL,
      nst_cfg_diff_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_t, modified),
      0,
      0,
      0,
    },

    { REMOVED_TAG,
      NULL,
      nst_cfg_diff_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_t, removed),
      0,
      0,
      0,
    },

    { ADDED_TAG,
      NULL,
      nst_cfg_diff_block_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_t, added),
      0,
      0,
      0,
    },
};

static void
diff_start_handler(void *udata,
                   const XML_Char *name,
                   const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(diff, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   diff_tag_actions,
                   sizeof(diff_tag_actions)/sizeof(diff_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data,
                   sizeof(current->tmp_elt_data),
                   diff_frame_data->diff, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void diff_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(diff);

    ret = nst_cfg_tag_action_end_handler(
                   diff_tag_actions,
                   sizeof(diff_tag_actions)/sizeof(diff_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   diff_frame_data->diff,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

void
nst_cfg_diff_init(nst_cfg_diff_t *diff)
{
    size_t i;
    nst_cfg_diff_block_t *diff_blocks[] = {
        &diff->modified,
        &diff->removed,
        &diff->added,
    };

    for(i = 0; i < sizeof(diff_blocks)/sizeof(diff_blocks[0]); i++)
        nst_cfg_diff_block_init(diff_blocks[i]);
}

void
nst_cfg_diff_flush(nst_cfg_diff_t *diff)
{
    size_t i;
    nst_cfg_diff_block_t *diff_blocks[] = {
        &diff->modified,
        &diff->removed,
        &diff->added,
    };

    for(i = 0; i < sizeof(diff_blocks)/sizeof(diff_blocks[0]); i++)
        nst_cfg_diff_block_flush(diff_blocks[i]);
}

void
nst_cfg_diff_reset(nst_cfg_diff_t *diff)
{
    size_t i;
    nst_cfg_diff_block_t *diff_blocks[] = {
        &diff->modified,
        &diff->removed,
        &diff->added,
    };

    for(i = 0; i < sizeof(diff_blocks)/sizeof(diff_blocks[0]); i++)
        nst_cfg_diff_block_reset(diff_blocks[i]);

    diff->old_version = 0;
}
