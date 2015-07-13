#ifndef _NST_CPPROXY_CFG_SVC_H_
#define _NST_CPPROXY_CFG_SVC_H_

#include <nst_config.h>

#include <nst_cfg_common.h>

#include <nst_types.h>

struct nst_cpproxy_cfg_s;
struct nst_cfg_svc_s;
struct nst_cfg_diff_s;
struct nst_genhash_s;
struct nst_cpproxy_cfg_dir_names_s;

nst_status_e nst_cpproxy_cfg_svc_refresh_all(struct nst_cpproxy_cfg_s *cpproxy_cfg);
nst_status_e nst_cpproxy_cfg_svc_read(struct nst_cfg_diff_s *diff,
                           const struct nst_cpproxy_cfg_dir_names_s *dir_names);
nst_status_e nst_cpproxy_cfg_svc_listen(struct nst_cpproxy_cfg_s *cpproxy_cfg);

nst_cfg_reload_status_e
nst_cpproxy_cfg_svc_apply_added(struct nst_cpproxy_cfg_s *cpproxy_cfg);

nst_cfg_reload_status_e
nst_cpproxy_cfg_svc_apply_modified(struct nst_cpproxy_cfg_s *cpproxy_cfg,
                                   bool *relisten);

void nst_cpproxy_cfg_svc_apply_removed(struct nst_cpproxy_cfg_s *cpproxy_cfg);

#endif
