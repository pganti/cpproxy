#ifndef _NST_CFG_DIFF_H_
#define _NST_CFG_DIFF_H_

#include <nst_config.h>
#include <errno.h>
#include "nst_cfg_diff_block.h"

#include <nst_types.h>

#include <expat.h>

#define NST_CFG_DIFF_ROOT_TAG "diff-root"

typedef struct nst_cfg_diff_s nst_cfg_diff_t;

struct nst_cfg_diff_s
{
    nst_uint_t old_version;
    nst_cfg_diff_block_t modified;
    nst_cfg_diff_block_t removed;
    nst_cfg_diff_block_t added;
};

nst_status_e nst_cfg_diff_capture(void *udata,
                                  const XML_Char *name,
                                  const XML_Char **attrs,
                                  void **pcfg_diff, void **unused1,
                                  void **unused2, void **unused3);

void nst_cfg_diff_init(nst_cfg_diff_t *cfg_diff);
void nst_cfg_diff_reset(nst_cfg_diff_t *cfg_diff);
void nst_cfg_diff_flush(nst_cfg_diff_t *diff);

#endif
