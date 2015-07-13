#ifndef _NST_CFG_DIFF_DATA_H_
#define _NST_CFG_DIFF_DATA_H_

#include <nst_config.h>

#include <nst_gen_func.h>
#include <nst_limits.h>
#include <nst_types.h>

#include <expat.h>

typedef struct nst_cfg_diff_data_s nst_cfg_diff_data_t;

struct nst_cfg_diff_data_s {
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    void *data;
    nst_gen_destructor_f data_free;
};

nst_status_e
nst_cfg_diff_data_capture(void *udata,
                          const XML_Char *name,
                          const XML_Char **attrs,
                          void **ppghash, void **unused1,
                          void **unused2, void **unused3);


nst_cfg_diff_data_t * nst_cfg_diff_data_new(void);
void nst_cfg_diff_data_free(nst_cfg_diff_data_t *diff_data);
uint32_t nst_cfg_diff_data_genhash(const void *diff_data);
int nst_cfg_diff_data_cmp(const void *diff_data1,
                          const void *diff_data2);


#endif
