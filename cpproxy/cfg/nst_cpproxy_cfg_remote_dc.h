#ifndef _NST_CPPROXY_CFG_REMOTE_DC_H_
#define _NST_CPPROXY_CFG_REMOTE_DC_H_

#include <nst_config.h>

#include <nst_cfg_dc.h>
#include <nst_cfg_common.h>

#include <nst_limits.h>
#include <nst_types.h>
#include <nst_vector.h>

struct nst_cpproxy_cfg_s;
struct nst_vector_s;
struct nst_cfg_diff_s;
struct nst_cpproxy_cfg_dir_names_s;
struct nst_genhash_s;

typedef struct nst_cpproxy_cfg_remote_dc_s nst_cpproxy_cfg_remote_dc_t;

struct nst_cpproxy_cfg_remote_dc_s
{
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    enum nst_cfg_dc_type_e type;
    struct nst_vector_s *sproxy_vec;
    struct nst_genhash_s *sproxy_proc_ghash; /* key:   sysid
                                        * value: nst_cpproxy_cfg_remote_proc_t *
                                        */
};

void nst_cpproxy_cfg_remote_dc_free(void *data);

nst_status_e
nst_cpproxy_cfg_remote_dc_refresh_all(struct nst_cpproxy_cfg_s *cpproxy_cfg);

nst_status_e
nst_cpproxy_cfg_remote_dc_read(struct nst_cfg_diff_s *diff,
                               const struct nst_cpproxy_cfg_dir_names_s *dir_names,
                               const struct nst_genhash_s *svc_ghash);

nst_status_e
nst_cpproxy_cfg_remote_dc_apply_added(struct nst_cpproxy_cfg_s *cpproxy_cfg);

void
nst_cpproxy_cfg_remote_dc_apply_removed(struct nst_cpproxy_cfg_s *cpproxy_cfg);

nst_cfg_reload_status_e
nst_cpproxy_cfg_remote_dc_apply_modified(struct nst_cpproxy_cfg_s *cpproxy_cfg);

#endif
