#include "nst_cfg_box.h"

#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

#include <nst_enum_type_helpers.h>
#include <nst_errno.h>

static const char *nst_cfg_box_type_str[] = {
    [NST_CFG_BOX_TYPE_UNKNOWN] = "unknown",
    [NST_CFG_BOX_TYPE_PROXY]   = "proxy",
    [NST_CFG_BOX_TYPE_MISC]    = "misc",
    [NST_CFG_BOX_TYPE_CACHE]   = "cache",
    [NST_CFG_BOX_TYPE_LVS]     = "lvs",
};

const char *
nst_cfg_box_type_to_str(nst_cfg_box_type_e type)
{
    return nst_enum_type_to_str(nst_cfg_box_type_str,
                                NST_CFG_BOX_TYPE_UNKNOWN,
                                _NUM_NST_CFG_BOX_TYPE,
                                NST_CFG_BOX_TYPE_UNKNOWN,
                                type);
}

nst_cfg_box_type_e
nst_cfg_box_type_from_str(const char *str)
{
    return nst_enum_type_from_str(nst_cfg_box_type_str,
                                  NST_CFG_BOX_TYPE_UNKNOWN,
                                  _NUM_NST_CFG_BOX_TYPE,
                                  NST_CFG_BOX_TYPE_UNKNOWN,
                                  str);
}

nst_status_e
nst_cfg_tag_action_set_box_type(void *cfg_obj,
                                const nst_cfg_tag_action_t *action,
                                nst_expat_stack_frame_t *current,
                                const char *value, size_t value_len)
{
    nst_cfg_box_type_e *box_type = (nst_cfg_box_type_e *)((char *)(cfg_obj) + action->offset0);
    *box_type = nst_cfg_box_type_from_str(value);

    if(*box_type == NST_CFG_BOX_TYPE_UNKNOWN) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}
