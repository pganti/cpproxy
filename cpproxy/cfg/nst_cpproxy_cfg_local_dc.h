#ifndef _NST_CPPROXY_CFG_LOCAL_DC_H_
#define _NST_CPPROXY_CFG_LOCAL_DC_H_

#include <nst_config.h>

#include "nst_cpproxy_cfg_box.h"

#include <nst_cfg_dc.h>
#include <nst_cfg_common.h>

#include <nst_limits.h>

struct nst_cpproxy_cfg_s;
struct nst_cpproxy_cfg_local_dc_s;
struct nst_cpproxy_cfg_dir_names_s;
struct nst_cpproxy_cfg_local_proc_s;

typedef struct nst_cpproxy_cfg_local_dc_s nst_cpproxy_cfg_local_dc_t;

struct nst_cpproxy_cfg_local_dc_s
{
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    enum nst_cfg_dc_type_e type;
    struct nst_cfg_vips_s *vips;
    struct nst_cpproxy_cfg_local_proc_s *my_proc;
    struct nst_cpproxy_cfg_box_s current_parsing_box;
    /* cache machines */

};

void nst_cpproxy_cfg_local_dc_free(void *data);

nst_status_e
nst_cpproxy_cfg_local_dc_read(nst_cpproxy_cfg_local_dc_t **local_dc,
                              const char *my_dc_name,
                              const struct nst_cpproxy_cfg_dir_names_s *dir_names);

nst_cfg_reload_status_e
nst_cpproxy_cfg_local_dc_apply_modified(nst_cpproxy_cfg_local_dc_t *my_dc,
                                        nst_cpproxy_cfg_local_dc_t *my_new_dc,
                                        bool *relisten,
                                        bool *reset_log_cfg);

#endif /* _NST_CPPROXY_CFG_LOCAL_DC_H_ */
