#ifndef _NST_CFG_H_
#define _NST_CFG_H_

#include <nst_allocator.h>
#include <nst_types.h>

#define NST_CFG_WORKING_DIR_NAME "working"
#define NST_CFG_LATEST_DIR_NAME  "latest"

extern nst_allocator_t nst_cfg_allocator;

struct nst_allocator_s;

typedef enum nst_dc_type_e nst_dc_type_e;
enum nst_dc_type_e {
    NST_DC_TYPE_UNKNOWN = 0,
    NST_DC_TYPE_PUBLIC  = 1,
    NST_DC_TYPE_PRIVATE = 2,
    _NUM_NST_DC_TYPE    = 3,
};

void nst_cfg_init(void);
void nst_cfg_reset(void);

#endif
