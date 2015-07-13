#include "nst_cfg_diff_block.h"

#include <nst_cfg_diff_data.h>
#include <nst_cfg_common.h>
#include <nst_cfg_tag_action.h>

#include <nst_gen_func.h>
#include <nst_allocator.h>
#include <nst_genhash.h>
#include <nst_assert.h>
#include <nst_log.h>
#include <nst_string.h>

#define SERVICES_TAG  "services"
#define DCS_TAG       "clusters"
#define CUSTOMERS_TAG "applications"

typedef struct diff_block_frame_data_s diff_block_frame_data_t;

struct diff_block_frame_data_s
{
    nst_cfg_diff_block_t *diff_block;
};

static void diff_block_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void diff_block_end_handler(void *udata,
                                 const XML_Char *name);


NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(diff_block,
                                       nst_cfg_frame_data_empty_extra_free);

nst_status_e
nst_cfg_diff_block_capture(void *udata,
                           const XML_Char *name,
                           const XML_Char **attrs,
                           void **pdiff_block, void **unused1,
                           void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(diff_block);

    nst_assert(pdiff_block);
    diff_block_frame_data->diff_block 
        = (nst_cfg_diff_block_t *)pdiff_block;
 
   return NST_OK;
}

static nst_cfg_tag_action_t diff_block_tag_actions[] = {
    { SERVICES_TAG,
      NULL,
      nst_cfg_diff_data_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_block_t, services),
      0,
      0,
      0,
    },

    { DCS_TAG,
      NULL,
      nst_cfg_diff_data_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_block_t, dcs),
      0,
      0,
      0,
    },

    { CUSTOMERS_TAG,
      NULL,
      nst_cfg_diff_data_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_diff_block_t, applications),
      0,
      0,
      0,
    },

};

static void
diff_block_start_handler(void *udata,
                         const XML_Char *name,
                         const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(diff_block, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   diff_block_tag_actions,
                   sizeof(diff_block_tag_actions)/sizeof(diff_block_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   diff_block_frame_data->diff_block, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void diff_block_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(diff_block);

    ret = nst_cfg_tag_action_end_handler(
                   diff_block_tag_actions,
                   sizeof(diff_block_tag_actions)/sizeof(diff_block_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   diff_block_frame_data->diff_block,
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
nst_cfg_diff_block_init(nst_cfg_diff_block_t *diff_block)
{
    diff_block->services = nst_genhash_new(NST_GENHASH_MODE_NONE,
                                      64, 0, 0,
                                      &nst_cfg_allocator,
                                      nst_genhash_cstr,
                                      nst_genhash_cstr_cmp,
                                      NULL, (nst_gen_destructor_f)nst_cfg_diff_data_free,
                                      NULL, NULL);
    diff_block->dcs = nst_genhash_new(NST_GENHASH_MODE_NONE,
                                      64, 0, 0,
                                      &nst_cfg_allocator,
                                      nst_genhash_cstr,
                                      nst_genhash_cstr_cmp,
                                      NULL, (nst_gen_destructor_f)nst_cfg_diff_data_free,
                                      NULL, NULL);
    diff_block->applications = nst_genhash_new(NST_GENHASH_MODE_NONE,
                                           64, 0, 0,
                                           &nst_cfg_allocator,
                                           nst_cfg_diff_data_genhash,
                                           nst_cfg_diff_data_cmp,
                                           (nst_gen_destructor_f)nst_cfg_diff_data_free, NULL,
                                           NULL, NULL);
}

void
nst_cfg_diff_block_flush(nst_cfg_diff_block_t *diff_block)
{
    nst_genhash_flush(diff_block->services);
    nst_genhash_flush(diff_block->dcs);
    nst_genhash_flush(diff_block->applications);
}

void
nst_cfg_diff_block_reset(nst_cfg_diff_block_t *diff_block)
{
    nst_genhash_free(diff_block->services);
    nst_genhash_free(diff_block->dcs);
    nst_genhash_free(diff_block->applications);
    nst_memzero(diff_block, sizeof(*diff_block));
}
