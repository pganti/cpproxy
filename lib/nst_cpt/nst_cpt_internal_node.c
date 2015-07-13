#include "nst_cpt_internal_node.h"

#include "nst_cpt_common.h"
#include "nst_cpt_node.h"

#include <nst_vector.h>
#include <nst_log.h>
#include <nst_allocator.h>
#include <nst_sockaddr.h>
#include <nst_assert.h>

#include <string.h>
#include <unistd.h>

static int nst_cpt_internal_node_set_data(nst_cpt_node_t *node);

static void nst_cpt_internal_node_free_data(nst_cpt_node_t *data);

static void nst_cpt_internal_node_reg_log(const nst_cpt_node_t *node,
                                          nst_log_level_t ovr_lvl,
                                          nst_log_level_t msg_lvl,
                                          size_t tree_depth);
static void
nst_cpt_internal_node_eval_reg_log(const nst_cpt_node_t *node,
                                   const nst_cpt_node_t *picked_node,
                                   nst_cpt_node_score_t score,
                                   nst_log_level_t ovr_lvl,
                                   nst_log_level_t msg_lvl,
                                   size_t tree_depth);

static nst_cpt_node_score_t nst_cpt_internal_node_get_score(const nst_cpt_node_t *node);
static bool nst_cpt_internal_node_is_valid(const nst_cpt_node_t *node);

nst_cpt_node_ops_t nst_cpt_internal_node_ops = {
    .set_data = nst_cpt_internal_node_set_data,
    .free_data = nst_cpt_internal_node_free_data,
    .copy_cstor = nst_cpt_unhandled_node_copy_cstor,
    .reg_log = nst_cpt_internal_node_reg_log,
    .eval_reg_log = nst_cpt_internal_node_eval_reg_log,
    .get_score = nst_cpt_internal_node_get_score,
    .is_valid = nst_cpt_internal_node_is_valid,
};

static void
nst_cpt_internal_node_child_vec_free(nst_cpt_node_t **node)
{
    nst_assert(node);
    nst_cpt_node_free(*node);
}

static nst_status_e
nst_cpt_internal_node_set_data(nst_cpt_node_t *node)
{
    node->data = NULL;
    node->children
        = nst_vector_new(&nst_cpt_allocator,
                  (nst_gen_destructor_f) nst_cpt_internal_node_child_vec_free,
                  4,
                  sizeof(nst_cpt_node_t*));

    if(node->children)
        return NST_OK;
    else
        return NST_ERROR;
}

static void
nst_cpt_internal_node_free_data(nst_cpt_node_t *node)
{
    nst_vector_free(node->children);
}

static void
nst_cpt_internal_node_reg_log(const nst_cpt_node_t *node,
                              nst_log_level_t ovr_lvl,
                              nst_log_level_t msg_lvl,
                              size_t tree_depth)
{
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);
    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=\"%s\" selection=\"%s\" no-of-children=%ud]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   nst_cpt_node_sel_type_to_str(node->sel_type),
                   nst_vector_get_nelts(node->children));
}

static void
nst_cpt_internal_node_eval_reg_log(const nst_cpt_node_t *node,
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
                   "%s[type=\"%s\" selection=\"%s\" no-of-children=%ud score=%s my-id=%p picked-child-id=%p]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   nst_cpt_node_sel_type_to_str(node->sel_type),
                   nst_vector_get_nelts(node->children),
                   score_str,
                   node,
                   picked_node);
}

static nst_cpt_node_score_t
nst_cpt_internal_node_get_score(const nst_cpt_node_t *node)
{
    nst_assert(0 && "should not get score from internal CPT node");
}

static bool
nst_cpt_internal_node_is_valid(const nst_cpt_node_t *node)
{
    if(node->children == NULL || nst_vector_get_nelts(node->children) == 0)
        return FALSE;
    else
        return TRUE;
}

int
nst_cpt_internal_node_add_child(nst_cpt_node_t *node, nst_cpt_node_t *child)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_INTERNAL);

    return nst_vector_append(node->children, &child, 1);
}
