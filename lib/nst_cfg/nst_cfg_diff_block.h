#ifndef _NST_CFG_DIFF_BLOCK_H_
#define _NST_CFG_DIFF_BLOCK_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

struct nst_genhash_s;

typedef struct nst_cfg_diff_block_s nst_cfg_diff_block_t;

struct nst_cfg_diff_block_s {
    struct nst_genhash_s *services;
    struct nst_genhash_s *dcs;
    struct nst_genhash_s *applications;
};

nst_status_e nst_cfg_diff_block_capture(void *udata,
                                        const XML_Char *name,
                                        const XML_Char **attrs,
                                        void **pdiff_block, void **unused1,
                                        void **unused2, void **unused3);
void nst_cfg_diff_block_init(nst_cfg_diff_block_t *diff_block);
void nst_cfg_diff_block_reset(nst_cfg_diff_block_t *diff_block);
void nst_cfg_diff_block_flush(nst_cfg_diff_block_t *diff_block);

#endif
