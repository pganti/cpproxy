#ifndef _NST_CPPROXY_CFG_DIFF_H_
#define _NST_CPPROXY_CFG_DIFF_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_cfg_diff_s;
struct nst_cpproxy_cfg_dir_names_s;

nst_status_e
nst_cpproxy_cfg_diff_read(struct nst_cfg_diff_s *diff,
                          struct nst_cpproxy_cfg_dir_names_s *dir_names);

#endif /* _NST_CPPROXY_CFG_DIFF_H_ */
