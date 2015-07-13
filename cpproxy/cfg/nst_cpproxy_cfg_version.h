#ifndef _NST_CPPROXY_CFG_VERSION_H_
#define _NST_CPPROXY_CFG_VERSION_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_cpproxy_cfg_dir_names_s;

nst_status_e
nst_cpproxy_cfg_version_read(nst_uint_t *version,
                             const struct nst_cpproxy_cfg_dir_names_s *dir_names);

#endif /* _NST_CPPROXY_CFG_VERSION_H_ */
