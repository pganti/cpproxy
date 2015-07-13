#include "nst_cpproxy_cfg_diff.h"

#include "nst_cpproxy_cfg.h"

#include <nst_cfg_diff.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_common.h>

#include <nst_log.h>
#include <nst_string.h>

nst_status_e
nst_cpproxy_cfg_diff_read(nst_cfg_diff_t *diff,
                          nst_cpproxy_cfg_dir_names_t *dir_names)
{
    u_char full_diff_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];
    nst_cfg_file_read_ctx_t diff_read_ctx = {
        .entity_start_tag = NST_CFG_DIFF_ROOT_TAG,
        .capture = nst_cfg_diff_capture,
        .capture_data0 = (void **)diff,
        .capture_data1 = NULL,
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_cb = NULL,
        .done_data = NULL,
    };

    if(nst_snprintf(full_diff_filename,
                    sizeof(full_diff_filename),
                    "%s%c%s",
                    dir_names->base,
                    NST_DIR_DELIMITER_CHAR,
                    NST_CFG_DIFF_FILENAME)
       >= full_diff_filename + sizeof(full_diff_filename)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "length \"%s%c%s\" is too long > %ud",
                    dir_names->base,
                    NST_DIR_DELIMITER_CHAR,
                    NST_CFG_DIFF_FILENAME,
                    sizeof(full_diff_filename));
        return NST_ERROR;
    }

    return nst_cfg_file_read((char *)full_diff_filename, &diff_read_ctx);
}
