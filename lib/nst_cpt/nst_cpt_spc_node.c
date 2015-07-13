#include "nst_cpt_spc_node.h"

#include "nst_cpt_common.h"
#include "nst_cpt_node.h"

#include <nst_log.h>
#include <nst_assert.h>
#include <nst_sockaddr.h>
#include <nst_allocator.h>

#include <string.h>
#include <unistd.h>

static int nst_cpt_spc_node_set_data(nst_cpt_node_t *node);

static void nst_cpt_spc_node_free_data(nst_cpt_node_t *data);

static void nst_cpt_spc_node_reg_log(const nst_cpt_node_t *node,
                                     nst_log_level_t ovr_lvl,
                                     nst_log_level_t msg_lvl,
                                     size_t tree_depth);
static void nst_cpt_spc_node_eval_reg_log(const nst_cpt_node_t *node,
                                          const nst_cpt_node_t *picked_node,
                                          nst_cpt_node_score_t score,
                                          nst_log_level_t ovr_lvl,
                                          nst_log_level_t msg_lvl,
                                          size_t tree_depth);

static nst_cpt_node_score_t nst_cpt_spc_node_get_score(const nst_cpt_node_t *node);
static bool nst_cpt_spc_node_is_valid(const nst_cpt_node_t *node);

nst_cpt_node_ops_t nst_cpt_spc_node_ops = {
    .set_data = nst_cpt_spc_node_set_data,
    .free_data = nst_cpt_spc_node_free_data,
    .reg_log = nst_cpt_spc_node_reg_log,
    .eval_reg_log = nst_cpt_spc_node_eval_reg_log,
    .get_score = nst_cpt_spc_node_get_score,
    .is_valid = nst_cpt_spc_node_is_valid,
};

typedef struct nst_cpt_node_data_s {
    char         spc_name [NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    int          sproxy_count;
    char       * sproxy_vector;
} nst_cpt_node_data_t; 

static int
nst_cpt_spc_node_set_data(nst_cpt_node_t *node)
{
    nst_cpt_node_data_t        * nd;

    nd = nst_allocator_calloc (&nst_cpt_allocator,
                               1,
                               sizeof (nst_cpt_node_data_t));
    if (nd) {
        nd->sproxy_vector = NULL;
        nd->sproxy_count = 0;
        node->data = (void *)nd;
        return 0;
    }
    return -1;
    
#if 0
    node->data = (char *)nst_allocator_calloc(&nst_cpt_allocator,
                                              1,
                                              NST_MAX_CFG_NAME_ELT_BUF_SIZE);

    if(!node->data)
        return -1;
    return 0;
#endif
}

static void
nst_cpt_spc_node_free_data(nst_cpt_node_t *node)
{
    nst_cpt_node_data_t        * nd;

    nd = (nst_cpt_node_data_t *) node->data;
    if (nd) {
        if (nd->sproxy_vector) {
            nst_allocator_free(&nst_cpt_allocator, nd->sproxy_vector);
        }
        nst_allocator_free(&nst_cpt_allocator, nd);
    }

#if 0
    nst_allocator_free(&nst_cpt_allocator, node->data);
#endif
}


static void
nst_cpt_spc_node_reg_log(const nst_cpt_node_t *node,
                         nst_log_level_t ovr_lvl,
                         nst_log_level_t msg_lvl,
                         size_t tree_depth)
{
    char score_str[16];
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);
    nst_cpt_node_get_score_str(node, score_str, sizeof(score_str));
    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=\"%s\" data-center=\"%s\" score=%s]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   (const char *)node->data,
                   score_str);
}

static void
nst_cpt_spc_node_eval_reg_log(const nst_cpt_node_t *node,
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
                   "%s[type=\"%s\" data-center=\"%s\" score=%s my-id=%p picked-child-id=%p]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   (const char *)node->data,
                   score_str,
                   node,
                   picked_node);
}
    
void
nst_cpt_spc_node_set_dc_name(nst_cpt_node_t *node,
                             const char *dc_name)
{
    nst_cpt_node_data_t     * nd;
    char                    * my_dc_name;
    
    nd = (nst_cpt_node_data_t *)node->data;
    my_dc_name = nd->spc_name;
    
    strncpy(my_dc_name, dc_name, NST_MAX_CFG_NAME_ELT_BUF_SIZE);
    my_dc_name[NST_MAX_CFG_NAME_ELT_BUF_SIZE-1] = '\0'; /* just in case */
}

const char *
nst_cpt_spc_node_get_dc_name(const struct nst_cpt_node_s *node)
{
    nst_cpt_node_data_t     * nd;

    nd = (nst_cpt_node_data_t *)node->data;

    return (const char *) nd->spc_name;
}

static nst_cpt_node_score_t
nst_cpt_spc_node_get_score(const nst_cpt_node_t *node)
{
    return node->score;
    //return NST_CPT_NODE_SCORE_DOWN;
}

static bool
nst_cpt_spc_node_is_valid(const nst_cpt_node_t *node)
{
    const char *dc_name = (char *)node->data;
    if(!dc_name)
        return FALSE;

    if(*dc_name == '\0')
        return FALSE;
    else
        return TRUE;
}

char *
nst_cpt_spc_node_alloc_spc_health_vec (int scount, const nst_cpt_node_t *node)
{
    nst_cpt_node_data_t        * nd;

    nd = (nst_cpt_node_data_t *) node->data;
    nst_assert (nd != NULL && "Node data is NULL");

    if (nd->sproxy_count != scount) {
        if (nd->sproxy_vector != NULL) {
            nst_allocator_free(&nst_cpt_allocator, nd->sproxy_vector);
        }
        nd->sproxy_vector = nst_allocator_calloc (&nst_cpt_allocator,
                                                  scount,
                                                  sizeof(char));
        if (nd->sproxy_vector) {
            nd->sproxy_count = scount;
            return nd->sproxy_vector;
        }
        else {
            nd->sproxy_count = 0; /* Useless */
            return NULL;
        }
    }

    return nd->sproxy_vector;
}

int
nst_cpt_spc_node_get_health_vec_size (const nst_cpt_node_t *node)
{
    nst_cpt_node_data_t        * nd;

    nd = (nst_cpt_node_data_t *) node->data;

    return nd->sproxy_count;
}

char *
nst_cpt_spc_node_get_health_vec (const struct nst_cpt_node_s *node)
{
    nst_cpt_node_data_t        * nd;

    nd = (nst_cpt_node_data_t *) node->data;

    return nd->sproxy_vector;
}

