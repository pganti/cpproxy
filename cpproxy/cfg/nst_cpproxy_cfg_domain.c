#include "nst_cpproxy_cfg_domain.h"

#include "nst_cpproxy_cfg.h"


#include <nst_cpt_osrv_node.h>
#include <nst_cpt_node.h>

#include <nst_cfg_domain.h>
#include <nst_cfg_common.h>

#include <nst_vector.h>
#include <nst_genhash.h>
#include <nst_types.h>

static void
nst_cpproxy_cfg_domain_inherit_osrv_score(const char *domain_name,
                                          nst_cpt_node_t *new_osite,
                                          const nst_cpt_node_t *old_osite,
                                          bool test_only_mode)
{
    size_t i;
    size_t j;
    size_t nnew_osrvs;
    size_t nold_osrvs;
    nst_cpt_node_t *new_osrv;
    nst_cpt_node_t *old_osrv;
    nst_cpt_osrv_node_data_t *new_osrv_data;
    nst_cpt_osrv_node_data_t *old_osrv_data;

    nst_assert(new_osite->children);
    nst_assert(old_osite->children);

    nnew_osrvs = nst_vector_get_nelts(new_osite->children);
    nold_osrvs = nst_vector_get_nelts(old_osite->children);


    nst_assert(nnew_osrvs);
    nst_assert(nold_osrvs);

    for(i = 0; i < nold_osrvs; i++) {
        old_osrv
            = *(nst_cpt_node_t **)nst_vector_get_elt_at(old_osite->children, i);
        old_osrv_data = (nst_cpt_osrv_node_data_t *)old_osrv->data;

        for(j = 0; j < nnew_osrvs; j++) {
            new_osrv
            = *(nst_cpt_node_t **)nst_vector_get_elt_at(new_osite->children, j);
            new_osrv_data = (nst_cpt_osrv_node_data_t *)new_osrv->data;

            if(nst_cpt_osrv_node_is_equal(new_osrv, old_osrv)) {
                new_osrv->score = old_osrv->score;
                new_osrv_data->hc_success = old_osrv_data->hc_success;
                new_osrv_data->hc_failures = old_osrv_data->hc_failures;
                new_osrv_data->flags.health = old_osrv_data->flags.health;
                new_osrv_data->rtt = old_osrv_data->rtt;
                NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                            "inherited origin-server (\"%s\") score (%Xd) "
                            "rtt (%Xd) healthiness (%s)",
                            old_osrv->name,
                            old_osrv->score,
                            old_osrv_data->rtt,
                            old_osrv_data->flags.health == 1 ? "yes" : "no");
                break;
            }
        }

    }
}

static void
nst_cpproxy_cfg_domain_inherit_dmon_sites(const char *domain_name,
                                          nst_vector_t *new_dmon_sites,
                                          const nst_vector_t *old_dmon_sites,
                                          bool test_only_mode)
{
    size_t i;
    size_t j;
    size_t nnew_dmon_sites;
    size_t nold_dmon_sites;
    nst_cpt_node_t *new_osite;
    nst_cpt_node_t *old_osite;

    nnew_dmon_sites = nst_vector_get_nelts(new_dmon_sites);
    nold_dmon_sites = nst_vector_get_nelts(old_dmon_sites);
    nst_assert(nnew_dmon_sites);
    nst_assert(nold_dmon_sites);

    for(i = 0; i < nnew_dmon_sites; i++) {
        new_osite
            = *(nst_cpt_node_t **)nst_vector_get_elt_at(new_dmon_sites, i);
        
        for(j = 0; j < nold_dmon_sites; j++) {
            old_osite
                = *(nst_cpt_node_t **)nst_vector_get_elt_at(old_dmon_sites, j);
            if(strcmp(new_osite->name, old_osite->name) == 0) {
                nst_cpproxy_cfg_domain_inherit_osrv_score(domain_name,
                                                          new_osite,
                                                          old_osite,
                                                          test_only_mode);
                break;
            }
        }
    }
}

void
nst_cpproxy_cfg_domain_inherit(nst_vector_t *new_domains,
                               const nst_vector_t *old_domains,
                               bool test_only_mode)
{
    size_t i;
    size_t j;
    size_t nnew_domains;
    size_t nold_domains;
    nst_cfg_domain_t *new_domain;
    nst_cfg_domain_t *old_domain;
    const nst_str_t *new_domain_name;
    const nst_str_t *old_domain_name;

    nnew_domains = nst_vector_get_nelts(new_domains);
    nold_domains = nst_vector_get_nelts(old_domains);
    nst_assert(nnew_domains);
    nst_assert(nold_domains);

    for(i = 0; i < nold_domains; i++) {
        old_domain
            = *(nst_cfg_domain_t **)nst_vector_get_elt_at(old_domains, i);
        old_domain_name = nst_cfg_domain_get_name(old_domain);

        for(j = 0; j < nnew_domains; j++) {
            new_domain
                = *(nst_cfg_domain_t **)nst_vector_get_elt_at(new_domains, j);
            new_domain_name = nst_cfg_domain_get_name(new_domain);

            if(nst_strcmp(new_domain_name->data, old_domain_name->data))
                continue;
            
            if(old_domain->dmon_sites) {
                /* found the old domain. try to inherit osrv score under
                 * the same osite
                 */
                NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                            "inheriting domain monitors for \"%s\"",
                            new_domain_name->data);

                nst_cpproxy_cfg_domain_inherit_dmon_sites((char *)new_domain_name->data,
                                                     new_domain->dmon_sites,
                                                     old_domain->dmon_sites,
                                                     test_only_mode);
            }
            break;
        }

    } /* for(i = 0; i < nnold_domains; i++) */
}

nst_status_e
nst_cpproxy_cfg_domain_add(nst_cpproxy_cfg_t *cpproxy_cfg,
                           nst_cfg_domain_t *domain)
{
    size_t i;
    size_t naliases;
    nst_str_t *alias;

    if(nst_cpproxy_cfg_am_i_private_spc()
       && !nst_cfg_domain_am_i_responsible(domain)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "I am not interested to domain \"%s\". ignored",
                    nst_cfg_domain_get_name(domain)->data);
    }

    naliases = nst_vector_get_nelts(domain->aliases);
    for(i = 0; i < naliases; i++) {
        alias = nst_vector_get_elt_at(domain->aliases, i);

        if(nst_genhash_add(cpproxy_cfg->domain_ghash,
                           alias, (void *)domain) == NST_ERROR) {
            nst_cpproxy_cfg_domain_del(cpproxy_cfg, domain, FALSE);
            return NST_ERROR;
        }
    }

    return NST_OK;
}

nst_cfg_domain_t *
nst_cpproxy_cfg_domain_get_by_mstr(const nst_cpproxy_cfg_t *cpproxy_cfg,
                                   const nst_str_t *domain_name)
{
    nst_cfg_domain_t *domain;
    nst_str_t tmp_domain_name;

    tmp_domain_name.data = domain_name->data;
    tmp_domain_name.len = domain_name->len;

    while(tmp_domain_name.len) {
        domain = nst_genhash_find(cpproxy_cfg->domain_ghash, &tmp_domain_name);
        if(domain)
            return domain;

        /* skip till the next upper level domain */
        while(--(tmp_domain_name.len) && *(++(tmp_domain_name.data)) != '.');
    }
     
    return NULL;
}

void
nst_cpproxy_cfg_domain_del(nst_cpproxy_cfg_t *cpproxy_cfg,
                           nst_cfg_domain_t *domain,
                           bool set_domain_down)
{
    size_t i;
    size_t naliases;
    nst_str_t *alias;

    naliases = nst_vector_get_nelts(domain->aliases);
    for(i = 0; i < naliases; i++) {
        alias = nst_vector_get_elt_at(domain->aliases, i);
        nst_genhash_del(cpproxy_cfg->domain_ghash, alias);
    }

    return;
}
