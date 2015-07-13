#ifndef _NST_CFG_FILE_READ_H_
#define _NST_CFG_FILE_READ_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

struct nst_genhash_s;

typedef struct nst_cfg_file_read_ctx_s nst_cfg_file_read_ctx_t;

typedef nst_status_e (*nst_cfg_file_capture_f)(void *udata,
                                               const XML_Char *name,
                                               const XML_Char **attrs,
                                               void **data0, void **data1,
                                               void **data2, void **data3);
typedef nst_status_e (*nst_cfg_file_done_cb_f)(nst_cfg_file_read_ctx_t *rf_ctx);

struct nst_cfg_file_read_ctx_s
{
    const char *entity_start_tag;
    nst_cfg_file_capture_f capture;
    void **capture_data0;
    void **capture_data1;
    void **capture_data2;
    void **capture_data3;
    nst_cfg_file_done_cb_f done_cb;
    void *done_data;
};

nst_status_e nst_cfg_file_read(const char *filename,
                               nst_cfg_file_read_ctx_t *ctx);

nst_status_e nst_cfg_dir_read(const char *full_dir_name,
                              struct nst_genhash_s *fn_ghash);

#endif
