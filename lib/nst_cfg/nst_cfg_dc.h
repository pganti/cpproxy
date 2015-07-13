#ifndef _NST_CFG_DC_H_
#define _NST_CFG_DC_H_

#include <nst_config.h>
#include <nst_types.h>

#define NST_CFG_DATA_CENTER_TAG        "cluster"
#define NST_CFG_DATA_CENTER_TYPE_TAG   "type"
#define NST_CFG_DATA_CENTER_NAME_TAG   "name"

struct nst_cfg_tag_action_s;
struct nst_expat_stack_frame_s;

typedef enum nst_cfg_dc_type_e nst_cfg_dc_type_e;

enum nst_cfg_dc_type_e {
    NST_CFG_DC_TYPE_UNKNOWN = 0,
    NST_CFG_DC_TYPE_PUBLIC  = 1,
    NST_CFG_DC_TYPE_PRIVATE = 2,
    _NUM_NST_CFG_DC_TYPE    = 3,
};

enum nst_cfg_dc_type_e nst_cfg_dc_type_from_str(const char *dc_str);
const char *nst_cfg_dc_type_to_str(nst_cfg_dc_type_e dc_type);

nst_status_e nst_cfg_tag_action_set_dc_type(
                            void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t value_len);

#endif
