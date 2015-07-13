#ifndef _NST_CPPROXY_CFG_CUSTOMER_H_
#define _NST_CPPROXY_CFG_CUSTOMER_H_

#include <nst_config.h>

#include <nst_cfg_common.h>

#include <nst_types.h>

struct nst_cpproxy_cfg_s;
struct nst_cpproxy_cfg_dir_names_s;
struct nst_cfg_diff_s;

nst_status_e nst_cpproxy_cfg_application_refresh_all(struct nst_cpproxy_cfg_s *cpproxy_cfg);
nst_status_e nst_cpproxy_cfg_application_read(struct nst_cfg_diff_s *diff,
                          const struct nst_cpproxy_cfg_dir_names_s *dir_names,
                          const char *my_dc_name);
nst_status_e nst_cpproxy_cfg_application_apply_added(struct nst_cpproxy_cfg_s *cpproxy_cfg);
nst_cfg_reload_status_e nst_cpproxy_cfg_application_apply_modified(struct nst_cpproxy_cfg_s *cpproxy_cfg);
void nst_cpproxy_cfg_application_apply_removed(struct nst_cpproxy_cfg_s *cpproxy_cfg);

#endif
