#ifndef _NST_CPPROXY_CFG_DOMAIN_H_
#define _NST_CPPROXY_CFG_DOMAIN_H_

#include <nst_config.h>

#include <nst_types.h>

extern struct nst_genhash_s *domain_ghash;

struct nst_cpproxy_cfg_s;
struct nst_cfg_domain_s;
struct nst_vector_s;
struct nst_str_s;

nst_status_e
nst_cpproxy_cfg_domain_add(struct nst_cpproxy_cfg_s *cpproxy_cfg,
                           struct nst_cfg_domain_s *domain);

struct nst_cfg_domain_s *
nst_cpproxy_cfg_domain_get_by_mstr(const struct nst_cpproxy_cfg_s *cpproxy_cfg,
                                   const struct nst_str_s *domain_name);

void nst_cpproxy_cfg_domain_del(struct nst_cpproxy_cfg_s *cpproxy_cfg,
                                struct nst_cfg_domain_s *domain,
                                bool set_domain_down);

void nst_cpproxy_cfg_domain_inherit(struct nst_vector_s *new_domains,
                                    const struct nst_vector_s *old_domains,
                                    bool test_only_mode);

#endif
