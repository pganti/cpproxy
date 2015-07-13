#include "nst_cpt_walk.h"

#include "nst_cpt_node.h"

#include <nst_vector.h>

nst_status_e
nst_cpt_walk(nst_cpt_node_t *node, nst_cpt_walk_f walk, void *data)
{
    size_t nchildren;
    size_t i;
    nst_status_e ret;

    ret = walk(node, data);
    if(ret == NST_DONE)
        return NST_DONE;
    else if(ret == NST_ERROR)
        return NST_ERROR;

    if(!node->children 
       || (nchildren = nst_vector_get_nelts(node->children)) == 0)
        return NST_OK;

    for(i = 0; i < nchildren; i++) {
        nst_cpt_node_t *child;
        child = *(nst_cpt_node_t **)nst_vector_get_elt_at(node->children, i);
        ret = nst_cpt_walk(child, walk, data);
        if(ret == NST_ERROR)
            return NST_ERROR;
    }

    return NST_OK;
}

                
