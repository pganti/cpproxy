#include "nst_cpproxy_cfg_version.h"

#include "nst_cpproxy_cfg.h"

#include <nst_cfg_version.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_common.h>

#include <nst_string.h>
#include <nst_types.h>

nst_status_e nst_cpproxy_cfg_version_read(nst_uint_t *version,
                             const nst_cpproxy_cfg_dir_names_t *dir_names)
{
    u_char full_version_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];

    nst_cfg_file_read_ctx_t version_read_ctx = {
        .entity_start_tag = NST_CFG_VERSION_TAG,
        .capture = nst_cfg_version_capture,
        .capture_data0 = (void **)version,
        .capture_data1 = NULL,
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_cb = NULL,
        .done_data = NULL,
    };

    if(nst_snprintf(full_version_filename,
                    sizeof(full_version_filename),
                    "%s%c%s",
                    dir_names->base,
                    NST_DIR_DELIMITER_CHAR,
                    NST_CFG_VERSION_FILENAME)
       >= full_version_filename + sizeof(full_version_filename)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "\"%s%c%s\" length is too long > %ud",
                    dir_names->dcs,
                    NST_DIR_DELIMITER_CHAR,
                    NST_CFG_VERSION_FILENAME,
                    sizeof(full_version_filename));
    }
                    
    return nst_cfg_file_read((char *)full_version_filename,
                             &version_read_ctx);
}
