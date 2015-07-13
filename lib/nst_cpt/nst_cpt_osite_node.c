#include "nst_cpt_osite_node.h"

#include "nst_cpt_osrv_node.h"
#include "nst_cpt_common.h"
#include "nst_cpt_node.h"

#include <nst_types.h>
#include <nst_allocator.h>
#include <nst_vector.h>
#include <nst_assert.h>
#include <nst_limits.h>

#include <string.h>

static int nst_cpt_osite_node_set_data(nst_cpt_node_t *node);
static void nst_cpt_osite_node_free_data(nst_cpt_node_t *node);
static nst_status_e
nst_cpt_osite_node_copy_cstor(nst_cpt_node_t *dst_node,
                              const nst_cpt_node_t *src_node);
static void nst_cpt_osite_node_reg_log(const nst_cpt_node_t *node,
                                       nst_log_level_t ovr_lvl,
                                       nst_log_level_t msg_lvl,
                                       size_t tree_depth);
static void nst_cpt_osite_node_eval_reg_log(const nst_cpt_node_t *node,
                                            const nst_cpt_node_t *picked_node,
                                            nst_cpt_node_score_t score,
                                            nst_log_level_t ovr_lvl,
                                            nst_log_level_t msg_lvl,
                                            size_t tree_depth);
static bool nst_cpt_osite_node_is_valid(const nst_cpt_node_t *node);

static nst_cpt_node_score_t
nst_cpt_osite_node_get_score(const nst_cpt_node_t *node);

nst_cpt_node_ops_t nst_cpt_osite_node_ops = {
    .set_data = nst_cpt_osite_node_set_data,
    .free_data = nst_cpt_osite_node_free_data,
    .copy_cstor = nst_cpt_osite_node_copy_cstor,
    .reg_log = nst_cpt_osite_node_reg_log,
    .eval_reg_log = nst_cpt_osite_node_eval_reg_log,
    .get_score = nst_cpt_osite_node_get_score,
    .is_valid = nst_cpt_osite_node_is_valid,
};

static void
nst_cpt_osite_node_child_vec_free(nst_cpt_node_t **node)
{
    nst_assert(node);
    nst_assert((*node)->type == NST_CPT_NODE_TYPE_OSRV);

    nst_cpt_node_free(*node);
}

static void
node_data_free(nst_cpt_osite_node_data_t *node_data)
{
    if(!node_data)
        return;

    nst_vector_free(node_data->responsible_spc_names);
    nst_allocator_free(&nst_cpt_allocator, node_data);
}

static nst_cpt_osite_node_data_t *
node_data_new(void)
{
    nst_cpt_osite_node_data_t *node_data;

    node_data = nst_allocator_calloc(&nst_cpt_allocator,
                                     1,
                                     sizeof(*node_data));

    if(!node_data)
        return NULL;

    node_data->responsible_spc_names = nst_vector_new(&nst_cpt_allocator,
                                                NULL,
                                                1,
                                                NST_MAX_CFG_NAME_ELT_BUF_SIZE);
    if(!node_data->responsible_spc_names) {
        node_data_free(node_data);
        return NULL;
    }

    return node_data;
}

static nst_cpt_osite_node_data_t *
node_data_copy(const nst_cpt_osite_node_data_t *src_node_data)
{
    nst_cpt_osite_node_data_t *node_data;
    size_t i;
    size_t nspc;

    node_data = nst_allocator_calloc(&nst_cpt_allocator,
                                     1,
                                     sizeof(*node_data));

    if(!node_data)
        return NULL;

    nspc = nst_vector_get_nelts(src_node_data->responsible_spc_names);
    nst_assert(nspc);

    node_data->responsible_spc_names = nst_vector_new(&nst_cpt_allocator,
                                                NULL,
                                                nspc,
                                                NST_MAX_CFG_NAME_ELT_BUF_SIZE);
    if(!node_data->responsible_spc_names) {
        node_data_free(node_data);
        return NULL;
    }

    for(i = 0; i < nspc; i++) {
        const char *src_spc_name;
        char *dst_spc_name;

        src_spc_name
            = (const char *)nst_vector_get_elt_at(src_node_data->responsible_spc_names, i);
        dst_spc_name = nst_vector_push(node_data->responsible_spc_names);
        nst_assert(dst_spc_name); /* we did allocate enough before */

        strcpy(dst_spc_name, src_spc_name);
    }

    memcpy(&node_data->flags, &src_node_data->flags, sizeof(node_data->flags));
    return node_data;
}

static int
nst_cpt_osite_node_set_data(nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);

    node->children = nst_vector_new(&nst_cpt_allocator, 
                                    (nst_gen_destructor_f)nst_cpt_osite_node_child_vec_free,
                                    4,
                                    sizeof(nst_cpt_node_t*));
    if(node->children == NULL)
        return -1;

    node->data = node_data_new();
    if(node->data)
        return 0;
    else {
        nst_vector_free(node->children);
        node->children = NULL;
        return -1;
    }
}

static void
nst_cpt_osite_node_free_data(nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);
    node_data_free((nst_cpt_osite_node_data_t *)node->data);
    nst_vector_free(node->children);
}

static void
nst_cpt_osite_node_reg_log(const nst_cpt_node_t *node,
                           nst_log_level_t ovr_lvl,
                           nst_log_level_t msg_lvl,
                           size_t tree_depth)
{
    size_t i;
    size_t nspc;
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);
    nst_cpt_osite_node_data_t *node_data =
        (nst_cpt_osite_node_data_t *)node->data;

    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=\"%s\" name=\"%s\" selection=\"%s\" no-of-children=%ud%s]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   node->name,
                   nst_cpt_node_sel_type_to_str(node->sel_type),
                   nst_vector_get_nelts(node->children),
                   node_data->flags.am_i_responsible == 1 ?
                   " i-am-responsible" : "");

    indent = nst_cpt_node_get_indent_str(tree_depth+1);
    nspc = nst_vector_get_nelts(node_data->responsible_spc_names);
    for(i = 0; i < nspc; i++) {
        const char *spc_name;
        spc_name
            = (char *)nst_vector_get_elt_at(node_data->responsible_spc_names,
                                            i);
        NST_NOC_LOG(msg_lvl,
                       "%s(responsible-spc=\"%s\")",
                       indent,
                       spc_name);
    }
}

static void
nst_cpt_osite_node_eval_reg_log(const nst_cpt_node_t *node,
                                const nst_cpt_node_t *picked_node,
                                nst_cpt_node_score_t score,
                                nst_log_level_t ovr_lvl,
                                nst_log_level_t msg_lvl,
                                size_t tree_depth)
{
    char score_str[16];
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);

    nst_cpt_node_score_to_str(score, score_str, sizeof(score_str));
    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=\"%s\" name=\"%s\" selection=\"%s\" no-of-children=%ud score=%s my-id=%p picked-child-id=%p]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   node->name,
                   nst_cpt_node_sel_type_to_str(node->sel_type),
                   nst_vector_get_nelts(node->children),
                   score_str,
                   node,
                   picked_node);
}

static nst_cpt_node_score_t
nst_cpt_osite_node_get_score(const nst_cpt_node_t *node)
{
    nst_assert(0 && "cannot get score directly from osite CPT node");

    return node->score;
}

static bool
nst_cpt_osite_node_is_valid(const nst_cpt_node_t *node)
{
    return (node->children != NULL
            && nst_vector_get_nelts(node->children) > 0
            && nst_vector_get_nelts(((nst_cpt_osite_node_data_t *)node->data)->responsible_spc_names) > 0);
}

nst_status_e
nst_cpt_osite_node_add_dc(nst_cpt_node_t *node,
                          const char *dc_name,
                          size_t dc_name_len)
{
    char *new_dc_name;
    nst_cpt_osite_node_data_t *node_data;


    if(dc_name_len + 1 > NST_MAX_CFG_NAME_ELT_BUF_SIZE)
        return NST_ERROR;

    node_data = (nst_cpt_osite_node_data_t *)node->data;
    new_dc_name = (char *)nst_vector_push(node_data->responsible_spc_names);
    if(!new_dc_name)
        return NST_ERROR;

    memcpy(new_dc_name, dc_name, dc_name_len + 1);
    return NST_OK;
}

nst_status_e
nst_cpt_osite_node_add_child(nst_cpt_node_t *node, nst_cpt_node_t *child)
{
    nst_cpt_osite_node_data_t *node_data;

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);
    nst_assert(child->type == NST_CPT_NODE_TYPE_OSRV);

    if(nst_vector_append(node->children, &child, 1) == NST_ERROR)
        return NST_ERROR;

    node_data = (nst_cpt_osite_node_data_t *)node->data;
    if(node_data->flags.am_i_responsible == 1)
        nst_cpt_osrv_node_set_responsible(child);
    
    return NST_OK;
}

void
nst_cpt_osite_node_set_responsible(struct nst_cpt_node_s *node)
{
    nst_cpt_osite_node_data_t *node_data;

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);
    node_data = (nst_cpt_osite_node_data_t *)node->data;

    node_data->flags.am_i_responsible = 1;
}

bool
nst_cpt_osite_node_am_i_responsible(const struct nst_cpt_node_s *node)
{
    nst_cpt_osite_node_data_t *node_data;

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);
    node_data = (nst_cpt_osite_node_data_t *)node->data;

    return (node_data->flags.am_i_responsible == 1);
}

static nst_status_e
nst_cpt_osite_node_copy_cstor(nst_cpt_node_t *dst_node,
                              const nst_cpt_node_t *src_node)
{
    size_t nchildren;
    size_t i;

    nst_assert(dst_node->type == NST_CPT_NODE_TYPE_OSITE);
    nst_assert(dst_node->data == NULL);
    nst_assert(src_node->type == NST_CPT_NODE_TYPE_OSITE);
    nst_assert(src_node->data);

    dst_node->data = node_data_copy(src_node->data);

    nst_assert(src_node->children);
    nchildren = nst_vector_get_nelts(src_node->children);
    nst_assert(nchildren);

    nst_assert(dst_node->children == NULL);

    dst_node->children = nst_vector_new(&nst_cpt_allocator, 
                                        (nst_gen_destructor_f)nst_cpt_osite_node_child_vec_free,
                                        nchildren,
                                        sizeof(nst_cpt_node_t *));
        
    for(i = 0; i < nchildren; i++) {
        nst_cpt_node_t *new_child_node;
        nst_cpt_node_t *src_child_node;

        src_child_node = *(nst_cpt_node_t **)nst_vector_get_elt_at(src_node->children, i);
        new_child_node = nst_cpt_node_copy_cstor(src_child_node);
        if(!new_child_node)
            return NST_ERROR;
        else if(nst_vector_append(dst_node->children, &new_child_node, 1)
                == NST_ERROR)
            return NST_ERROR;
    }
        
    return NST_OK;
}
