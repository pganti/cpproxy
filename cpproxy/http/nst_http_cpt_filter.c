/* always include myself first */
#include "nst_http_cpt_filter.h"
#include "nst_http_cpt_request.h"
#include "nst_http_request.h"

/* cpproxy/cfg includes */
#include <nst_cpproxy_cfg.h>

/* libnstcpt includes */
#include <nst_cpt_osrv_node.h>
#include <nst_cpt_spc_node.h>
#include <nst_cpt_node.h>
#include <nst_cpt_request.h>

/* libnstcfg includes */
#include <nst_cfg_domain.h>

bool
nst_http_cpt_filter(const nst_cpt_node_t *node,
                    const nst_cpt_request_t *cpt_request)
{
    const nst_http_cpt_request_t *http_cpt_request;
    const nst_http_request_t *r;

    http_cpt_request = (const nst_http_cpt_request_t *)cpt_request;
    r = http_cpt_request->http_request;

    nst_assert(r->domain_cfg);

    switch(node->type) {
    case NST_CPT_NODE_TYPE_INTERMEDIATE_SPC:
        if(nst_http_downstream_is_mp(r))
            /* we only allow one intermediate SProxy now */
            return TRUE;
        else
            return FALSE;
    case NST_CPT_NODE_TYPE_SPC: {
        const char *dc_name;

        if(nst_http_downstream_is_mp(r)
           || nst_cfg_domain_am_i_spc(r->domain_cfg)
           || nst_cpproxy_cfg_am_i_private_spc())
            return TRUE;

        dc_name = nst_cpt_spc_node_get_dc_name(node);
        if(!strcmp(dc_name, cpproxy_cfg.my_dc_name))
            return TRUE;

        return FALSE;
    }
    case NST_CPT_NODE_TYPE_OSITE:
        return FALSE;
    case NST_CPT_NODE_TYPE_OSRV:
        if(nst_cfg_domain_am_i_spc(r->domain_cfg)
           && !nst_cpt_osrv_node_am_i_responsible(node))
            return TRUE;
        else
            return FALSE;
    case NST_CPT_NODE_TYPE_CACHE:
        if(r->downstream_flags.is_cache 
           || nst_http_downstream_is_mp(r)
           || nst_cpproxy_cfg_am_i_private_spc())
            return TRUE;
        else
            return FALSE;
    default:
        return TRUE;
    }

    return FALSE;
}
