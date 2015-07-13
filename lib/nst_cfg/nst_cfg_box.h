#ifndef _NST_CFG_BOX_H_
#define _NST_CFG_BOX_H_

#include <nst_config.h>
#include <nst_types.h>

#define BOX_TAG              "box"
#define BOX_NAME_TAG         "name"
#define BOX_TYPE_TAG         "type"
#define BOX_VIPS_TAG         "vips"

#define BOX_NATTED_FRONTEND_IP_TAG "natted-frontend-ip"
#define BOX_FRONTEND_IP_TAG       "frontend-ip"
#define BOX_BACKEND_IP_TAG        "backend-ip"

struct nst_cfg_tag_action_s;
struct nst_expat_stack_frame_s;

typedef enum nst_cfg_box_type_e nst_cfg_box_type_e;

enum nst_cfg_box_type_e {
    NST_CFG_BOX_TYPE_UNKNOWN = 0,
    NST_CFG_BOX_TYPE_PROXY   = 1,
    NST_CFG_BOX_TYPE_MISC    = 2,
    NST_CFG_BOX_TYPE_CACHE   = 3,
    NST_CFG_BOX_TYPE_LVS     = 4,
    _NUM_NST_CFG_BOX_TYPE    = 5,
};


const char *
nst_cfg_box_type_to_str(nst_cfg_box_type_e type);

nst_cfg_box_type_e
nst_cfg_box_type_from_str(const char *str);

nst_status_e nst_cfg_tag_action_set_box_type(
                            void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t value_len);

#endif
