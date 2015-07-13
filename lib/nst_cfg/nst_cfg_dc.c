#include "nst_cfg_dc.h"

#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

#include <nst_enum_type_helpers.h>
#include <nst_errno.h>

static const char *nst_cfg_dc_type_str[] = {
    [NST_CFG_DC_TYPE_UNKNOWN] = "unknown",
    [NST_CFG_DC_TYPE_PUBLIC]  = "public",
    [NST_CFG_DC_TYPE_PRIVATE] = "private",
};

nst_cfg_dc_type_e
nst_cfg_dc_type_from_str(const char *dc_str)
{
    return nst_enum_type_from_str(nst_cfg_dc_type_str,
                                  NST_CFG_DC_TYPE_UNKNOWN,
                                  _NUM_NST_CFG_DC_TYPE,
                                  NST_CFG_DC_TYPE_UNKNOWN,
                                  dc_str);
}

const char *
nst_cfg_dc_type_to_str(nst_cfg_dc_type_e dc_type)
{
    return nst_enum_type_to_str(nst_cfg_dc_type_str,
                                NST_CFG_DC_TYPE_UNKNOWN,
                                _NUM_NST_CFG_DC_TYPE,
                                NST_CFG_DC_TYPE_UNKNOWN,
                                dc_type);
}

nst_status_e
nst_cfg_tag_action_set_dc_type(void *cfg_obj,
                               const nst_cfg_tag_action_t *action,
                               nst_expat_stack_frame_t *current,
                               const char *value, size_t value_len)
{
    nst_cfg_dc_type_e *dc_type = (nst_cfg_dc_type_e *)((char *)(cfg_obj) + action->offset0);
    *dc_type = nst_cfg_dc_type_from_str(value);

    if(*dc_type == NST_CFG_DC_TYPE_UNKNOWN) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}
