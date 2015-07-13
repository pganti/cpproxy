#ifndef _NST_CFG_PROC_H_
#define _NST_CFG_PROC_H_

#include <nst_config.h>
#include <nst_types.h>

#define PROC_TAG             "process"
#define PROC_TYPE_TAG        "type"
#define PROC_CMD_TAG         "cmd"

struct nst_cfg_tag_action_s;
struct nst_expat_stack_frame_s;

typedef enum nst_cfg_proc_type_e nst_cfg_proc_type_e;

enum nst_cfg_proc_type_e {
    NST_CFG_PROC_TYPE_UNKNOWN = 0,
    NST_CFG_PROC_TYPE_PROXY   = 1,
    NST_CFG_PROC_TYPE_MCPD    = 2,
    NST_CFG_PROC_TYPE_CACHE   = 3,
    NST_CFG_PROC_TYPE_LOG     = 4,
    _NUM_NST_CFG_PROC_TYPE    = 5,
};

const char *nst_cfg_proc_type_to_str(nst_cfg_proc_type_e type);

nst_cfg_proc_type_e nst_cfg_proc_type_from_str(const char *str);

nst_status_e nst_cfg_tag_action_set_proc_type(
                            void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t value_len);

#endif
