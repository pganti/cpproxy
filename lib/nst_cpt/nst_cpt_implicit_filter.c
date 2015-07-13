#include "nst_cpt_implicit_filter.h"

#include "nst_cpt_request.h"

int nst_cpt_implicit_filter_by_request(const nst_cpt_node_t *node,
                                       const nst_cpt_request_t *request)
{
    return (nst_cpt_implicit_filter_by_last_tried_nodes(node, request)
            || nst_cpt_implicit_filter_by_loc(node, request->loc)
            || nst_cpt_implicit_filter_by_role(node, request->role)
            );
}

static inline
bool nst_cpt_implicit_filter_by_last_tried_nodes(const nst_cpt_node_t *node,
                                                 const nst_cpt_request_t *request)
{
    int i;
    /* TODO: if we have tried cache before, we should not try this time
    for(i = 0; i < request->ntries; i++) {

    }
    */

    return false;
}
                                                           
static inline bool nst_cpt_implicit_filter_by_loc(const nst_cpt_node_t *node,
                                                  const char *request_loc)
{
    
    nst_cpt_core_data_t *core_data;

    if(node->type != NST_CPT_NODE_SPC
       && node->type != NST_CPT_NODE_INTERMEIDATE_SPC)
        return false;

    core_data = node->data[NST_CPT_MODULE_TYPE_CORE];
    if(strcmp(core_data->loc_name, request_loc) == 0)
        
        return true;
    else
        return false;
}

static inline bool nst_cpt_implicit_filter_by_role(const nst_cpt_node_t *node,
                                                   nst_cpt_request_role_e request_role)
{
    switch(node->type) {
    case NST_CPT_NODE_MAPPED_CPC:
    case NST_CPT_NODE_FORCE_CPC:
        if(request_role == NST_CPT_ROLE_DNS)
            return false;
        else
            return true;
        break;
    case NST_CPT_NODE_CPC:
    case NST_CPT_NODE_CACHE:
        if(request_role == NST_CPT_ROLE_CPC)
            return true;
        else
            return false;
        break;
    case NST_CPT_NODE_SPC:
    case NST_CPT_NODE_INTERMEDIATE_SPC:
    case NST_CPT_NODE_OS:
        if(request_role == NST_CPT_ROLE_SPC)
            return true;
        else
            return false;
        break;
    default:
        assert("Un-handled node->type" && 0);
    };
}
