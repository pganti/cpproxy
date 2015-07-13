#include "nst_cpt_node.h"

#include "nst_cpt_osrv_node.h"
#include "nst_cpt_osite_node.h"
#include "nst_cpt_spc_node.h"
#include "nst_cpt_internal_node.h"
#include "nst_cpt_common.h"

#include <nst_log.h>
#include <nst_allocator.h>
#include <nst_vector.h>
#include <nst_assert.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>

static const char *null_str = "";

nst_cpt_node_ops_t nst_cpt_node_opss[_NST_CPT_NODE_TYPE_NUM];

nst_status_e
nst_cpt_unhandled_node_set_data(nst_cpt_node_t *node)
{
    nst_assert(0 && "unhandled node->type");
}

void
nst_cpt_unhandled_node_free_data(nst_cpt_node_t *node)
{
    nst_assert(0 && "unhandled node->type");
}

nst_status_e
nst_cpt_unhandled_node_copy_cstor(nst_cpt_node_t *dst_node,
                                  const nst_cpt_node_t *src_node)
{
    nst_assert(0 && "unhandled node->type");
}

void
nst_cpt_unhandled_node_reg_log(const nst_cpt_node_t *node,
                               nst_log_level_t ovr_lvl,
                               nst_log_level_t msg_lvl,
                               size_t tree_depth)
{
    nst_assert(0 && "unhandled node->type");
}

void nst_cpt_unhandled_node_eval_reg_log(const nst_cpt_node_t *node,
                                         const nst_cpt_node_t *picked_node,
                                         nst_cpt_node_score_t score,
                                         nst_log_level_t ovr_lvl,
                                         nst_log_level_t msg_lvl,
                                         size_t tree_depth)
{
    nst_assert(0 && "unhandled node->type");
}

nst_cpt_node_score_t
nst_cpt_unhandled_node_get_score(const nst_cpt_node_t *node)
{
    nst_assert(0 && "unhandled node->type");
}

bool
nst_cpt_unhandled_node_is_valid(const nst_cpt_node_t *node)
{
    nst_assert(0 && "unhandled node->type");
}

static nst_status_e
nst_cpt_unknown_node_set_data(nst_cpt_node_t *node)
{
    node->data = NULL;
    return NST_OK;
}

static void
nst_cpt_unknown_node_free_data(nst_cpt_node_t *node)
{
}

nst_cpt_node_ops_t nst_cpt_unhandled_node_ops = {
    .set_data = nst_cpt_unhandled_node_set_data,
    .free_data = nst_cpt_unhandled_node_free_data,
    .reg_log = nst_cpt_unhandled_node_reg_log,
    .eval_reg_log = nst_cpt_unhandled_node_eval_reg_log,
    .get_score = nst_cpt_unhandled_node_get_score,
    .is_valid = nst_cpt_unhandled_node_is_valid,
};

nst_cpt_node_ops_t nst_cpt_unknown_node_ops = {
    .set_data = nst_cpt_unknown_node_set_data,
    .free_data = nst_cpt_unknown_node_free_data,
    .copy_cstor = nst_cpt_unhandled_node_copy_cstor,
    .reg_log = nst_cpt_unhandled_node_reg_log,
    .eval_reg_log = nst_cpt_unhandled_node_eval_reg_log,
    .get_score = nst_cpt_unhandled_node_get_score,
    .is_valid = nst_cpt_unhandled_node_is_valid,
};

void
nst_cpt_node_init(void)
{
    nst_cpt_node_type_e type;
    for(type = NST_CPT_NODE_TYPE_UNKNOWN;
        type < _NST_CPT_NODE_TYPE_NUM;
        type++) {

        switch(type) {
        case NST_CPT_NODE_TYPE_SPC:
            nst_cpt_node_opss[type] = nst_cpt_spc_node_ops;
            break;
        case NST_CPT_NODE_TYPE_INTERNAL:
            nst_cpt_node_opss[type] = nst_cpt_internal_node_ops;
            break;
        case NST_CPT_NODE_TYPE_UNKNOWN:
            nst_cpt_node_opss[type] = nst_cpt_unknown_node_ops;
            break;
        case NST_CPT_NODE_TYPE_OSITE:
            nst_cpt_node_opss[type] = nst_cpt_osite_node_ops;
            break;
        case NST_CPT_NODE_TYPE_OSRV:
            nst_cpt_node_opss[type] = nst_cpt_osrv_node_ops;
            break;
        case NST_CPT_NODE_TYPE_MAPPED_CPC:
        case NST_CPT_NODE_TYPE_FORCE_CPC:
        case NST_CPT_NODE_TYPE_CACHE:
        case NST_CPT_NODE_TYPE_INTERMEDIATE_SPC:
            nst_cpt_node_opss[type] = nst_cpt_unhandled_node_ops;
            break;
        default:
            nst_assert(0 && "unhandled cpt node type");
        };
    }
}

nst_cpt_node_score_t
nst_cpt_node_get_score(const nst_cpt_node_t *node)
{
    /* TODO:
     * CPC:
     *   TP: measure the RTT
     *   origin-server: 4*RTT of CPC<->SPC + origin-server-score
     * SPC:
     *   origin-server: measure of downloading a 100k objects
     * DNS:
     *   from HealthNet of the mapped CPC
     */
    nst_assert(node->type != NST_CPT_NODE_TYPE_INTERNAL && "you should never get score from internal CPT node");

    if(node->score_from_cfg != NST_CPT_NODE_SCORE_DOWN_BY_UNKNOWN) {
        return node->score_from_cfg;
    } else {
        /* TODO: score math */
        return nst_cpt_node_opss[node->type].get_score(node);
    }
}

void
nst_cpt_node_score_to_str(const nst_cpt_node_score_t score,
                          char *buf, size_t buf_size)
{
    if(!buf || !buf_size)
        return;

    switch(score) {
    case NST_CPT_NODE_SCORE_DOWN_BY_TRIED:
        strncpy(buf, "down-by-tried", buf_size);
        break;
    case NST_CPT_NODE_SCORE_DOWN_BY_FILTERED:
        strncpy(buf, "down-by-filter", buf_size);
        break;
    case NST_CPT_NODE_SCORE_DOWN_BY_NO_SPC:
        strncpy(buf, "down-by-no-spc", buf_size);
        break;
    case NST_CPT_NODE_SCORE_DOWN_BY_RTT:
        strncpy(buf, "down-by-rtt", buf_size);
        break;
    case NST_CPT_NODE_SCORE_DOWN_BY_HC:
        strncpy(buf, "down-by-hc", buf_size);
        break;
    case NST_CPT_NODE_SCORE_DOWN_BY_UNKNOWN:
        strncpy(buf, "unknown", buf_size);
        break;
    default:
        snprintf(buf, buf_size, "%u", score);
    };

    buf[buf_size-1] = '\0';
}

void
nst_cpt_node_get_score_str(const nst_cpt_node_t *node,
                           char *buf, size_t buf_size)
{
    nst_cpt_node_score_t score;

    score = nst_cpt_node_get_score(node);

    nst_cpt_node_score_to_str(score, buf, buf_size);
}

int
nst_cpt_node_set_name(nst_cpt_node_t *node, const char *name, int name_len)
{
    char *new_name;

    if(!name)
        return 0;

    if(name_len == -1)
        name_len = strlen(name);

    if(name_len == 0) {
        if(node->name != null_str)
            nst_allocator_free(&nst_cpt_allocator, node->name);

        node->name = (char *)null_str;
        return 0;
    }

    new_name = nst_allocator_malloc(&nst_cpt_allocator,
                                    name_len + 1);
    if(new_name) {
        memcpy(new_name, name, name_len);
        new_name[name_len] = '\0';

        if(node->name != null_str)
            /* free NULL is safe */
            nst_allocator_free(&nst_cpt_allocator, node->name);

        node->name = new_name;
        return 0;
    } else {
        return -1;
    }
}

nst_status_e
nst_cpt_node_set_type(nst_cpt_node_t *node, nst_cpt_node_type_e type)
{
    if(node->type != NST_CPT_NODE_TYPE_UNKNOWN)
        nst_cpt_node_opss[type].free_data(node);
        
    node->type = type;

    switch(type) {
    case NST_CPT_NODE_TYPE_UNKNOWN:
    case NST_CPT_NODE_TYPE_INTERNAL:
    case NST_CPT_NODE_TYPE_MAPPED_CPC:
    case NST_CPT_NODE_TYPE_FORCE_CPC:
    case NST_CPT_NODE_TYPE_CACHE:
    case NST_CPT_NODE_TYPE_SPC: 
    case NST_CPT_NODE_TYPE_INTERMEDIATE_SPC:
    case NST_CPT_NODE_TYPE_OSITE:
    case NST_CPT_NODE_TYPE_OSRV:
        if(nst_cpt_node_opss[type].set_data(node)) {
            return NST_ERROR;
        }
        break;
    default:
        nst_assert(0 && "unhandled nst_cpt_node_type_e");
    };

    return NST_OK;
}

nst_cpt_node_t *
nst_cpt_node_new(void)
{
    nst_cpt_node_t *new_node;

    new_node = (nst_cpt_node_t *)nst_allocator_calloc(&nst_cpt_allocator,
                                                      1,
                                                      sizeof(nst_cpt_node_t));
    if(!new_node) {
        return NULL;
    }
        
    if(nst_cpt_node_set_type(new_node, NST_CPT_NODE_TYPE_UNKNOWN)
       == NST_ERROR) {
        nst_cpt_node_free(new_node);
        return NULL;
    } else {
        new_node->score_from_cfg = NST_CPT_NODE_SCORE_DOWN_BY_UNKNOWN;
        new_node->score = NST_CPT_NODE_SCORE_DOWN_BY_UNKNOWN;
        new_node->sel_type = NST_CPT_NODE_SEL_TYPE_SCORE;
        new_node->name = (char *)null_str;
        return new_node;
    }
}

void
nst_cpt_node_free(nst_cpt_node_t *node)
{
    if(!node)
        return;

    if(node->name != null_str)
        nst_allocator_free(&nst_cpt_allocator, node->name);

    nst_cpt_node_opss[node->type].free_data(node);

    nst_allocator_free(&nst_cpt_allocator, node);
}

nst_cpt_node_t *
nst_cpt_node_copy_cstor(const nst_cpt_node_t *src_node)
{
    nst_cpt_node_t *new_node;

    new_node = nst_cpt_node_new();
    if(!new_node)
        return NULL;

    new_node->type = src_node->type;
    if(nst_cpt_node_set_name(new_node, src_node->name, strlen(src_node->name))) {
        nst_cpt_node_free(new_node);
        return NULL;
    }
    new_node->sel_type = src_node->sel_type;
    new_node->score_from_cfg = src_node->score_from_cfg;

    if(nst_cpt_node_opss[src_node->type].copy_cstor(new_node, src_node)
       == NST_ERROR) {
        nst_cpt_node_free(new_node);
        return NULL;
    } else {
        return new_node;
    }
}

void
nst_cpt_node_vec_free(nst_cpt_node_t **node)
{
    nst_assert(node);
    nst_cpt_node_free(*node);
}

const char *
nst_cpt_node_get_indent_str(size_t level)
{
#if (NST_THREADS)
#error "TODO: implement a thread-safe version of nst_connection_get_dbg_str()"
#endif

#define MAX_CPT_INDENT_LEVEL (32)

    const size_t max_level = 32;
    static char indent_str[(MAX_CPT_INDENT_LEVEL * 2) + 1];

    if(level > max_level)
        level = max_level;

    memset(indent_str, ' ', level *  2);
    indent_str[level*2] = '\0';

    return indent_str;
}

void
nst_cpt_node_reg_log(const nst_cpt_node_t *node,
                     nst_log_level_t ovr_lvl,
                     nst_log_level_t msg_lvl,
                     size_t tree_depth)
{
    size_t i;
    nst_cpt_node_t *child;
    size_t nchildren;

    if(!nst_noc_log_level_test_ml(ovr_lvl, msg_lvl))
        return;

    nst_cpt_node_opss[node->type].reg_log(node, ovr_lvl, msg_lvl, tree_depth);

    if(node->children == NULL)
        return;

    nchildren = nst_vector_get_nelts(node->children);

    for(i = 0; i < nchildren; i++) {
        child = *(nst_cpt_node_t **)nst_vector_get_elt_at(node->children, i);
        nst_cpt_node_reg_log(child, ovr_lvl, msg_lvl, tree_depth+1);
    }
}

void
nst_cpt_node_eval_reg_log(const nst_cpt_node_t *node,
                          const nst_cpt_node_t *picked_node,
                          nst_cpt_node_score_t score,
                          nst_log_level_t ovr_lvl,
                          nst_log_level_t msg_lvl,
                          size_t tree_depth)
{
    if(!nst_noc_log_level_test_ml(ovr_lvl, msg_lvl))
        return;

    nst_cpt_node_opss[node->type].eval_reg_log(node, picked_node, score,
                                               ovr_lvl, msg_lvl, tree_depth);
}

nst_cpt_node_type_e
nst_cpt_node_get_type(const nst_cpt_node_t *node)
{
    return node->type;
}

const char *nst_cpt_node_type_to_str_table[_NST_CPT_NODE_TYPE_NUM] = {
    [NST_CPT_NODE_TYPE_UNKNOWN] = "unknown",
    [NST_CPT_NODE_TYPE_INTERNAL] = "internal",
    [NST_CPT_NODE_TYPE_MAPPED_CPC] = "mapped-cpc",
    [NST_CPT_NODE_TYPE_FORCE_CPC] = "force-cpc",
    [NST_CPT_NODE_TYPE_CACHE] = "cache",
    [NST_CPT_NODE_TYPE_SPC] = "spc",
    [NST_CPT_NODE_TYPE_INTERMEDIATE_SPC] = "i-spc",
    [NST_CPT_NODE_TYPE_OSITE] = "origin-site",
    [NST_CPT_NODE_TYPE_OSRV] = "origin-server"
};

const char *
nst_cpt_node_type_to_str(const nst_cpt_node_type_e type)
{
    nst_assert(type < _NST_CPT_NODE_TYPE_NUM);

    return nst_cpt_node_type_to_str_table[type];
}

nst_cpt_node_type_e
nst_cpt_node_type_from_str(const char *type_str)
{
    nst_cpt_node_type_e i;

    for(i = NST_CPT_NODE_TYPE_UNKNOWN; i < _NST_CPT_NODE_TYPE_NUM; i++) {
        if(!strcmp(type_str, nst_cpt_node_type_to_str_table[i])) {
            return i;
        }
    }

    return NST_CPT_NODE_TYPE_UNKNOWN;
}

const char *nst_cpt_node_sel_type_to_str_table[_NST_CPT_NODE_TYPE_NUM] = {
    [NST_CPT_NODE_SEL_TYPE_UNKNOWN] = "unknown",
    [NST_CPT_NODE_SEL_TYPE_SCORE] = "score",
    [NST_CPT_NODE_SEL_TYPE_FIRST] = "first",
    [NST_CPT_NODE_SEL_TYPE_RANDOM] = "random",
    [NST_CPT_NODE_SEL_TYPE_END_USER_IP_HASH] = "end-user-ip-hash",
};

const char*
nst_cpt_node_sel_type_to_str(nst_cpt_node_sel_type_e sel_type)
{
    nst_assert(sel_type < _NST_CPT_NODE_SEL_TYPE_NUM);
    
    return nst_cpt_node_sel_type_to_str_table[sel_type];
}

nst_cpt_node_sel_type_e
nst_cpt_node_sel_type_from_str(const char *sel_type_str)
{
    nst_cpt_node_sel_type_e i;

    for(i = NST_CPT_NODE_SEL_TYPE_UNKNOWN;
        i < _NST_CPT_NODE_SEL_TYPE_NUM;
        i++) {

        if(!strcmp(sel_type_str, nst_cpt_node_sel_type_to_str_table[i])) {
            return i;
        }

    }

    return NST_CPT_NODE_SEL_TYPE_UNKNOWN;
}

nst_cpt_node_sel_type_e
nst_cpt_node_get_sel_type_e(const nst_cpt_node_t *node)
{
    return node->sel_type;
}

nst_cpt_node_sel_type_e
nst_cpt_node_get_sel_type(const nst_cpt_node_t *node)
                          
{
    return node->sel_type;
}

void
nst_cpt_node_set_sel_type(nst_cpt_node_t *node,
                          nst_cpt_node_sel_type_e sel_type)
{
    nst_assert(sel_type < _NST_CPT_NODE_SEL_TYPE_NUM);

    node->sel_type = sel_type;
}

#if 0
void
nst_cpt_node_set_ref(nst_cpt_node_t *node, nst_cpt_node_t *ref_node)
{
    nst_assert(ref_node->type == NST_CPT_NODE_TYPE_OS_IP
           || ref_node->type == NST_CPT_NODE_TYPE_OS_HOSTNAME);

    node->ref_node = ref_node;
}

const nst_cpt_node_t *
nst_cpt_node_get_ref(const nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_REF_OS);
    return node->ref_node;
}
#endif

const char*
nst_cpt_node_get_name(const nst_cpt_node_t *node)
{
    return node->name;
}

bool
nst_cpt_node_is_valid(const nst_cpt_node_t *node)
{
    return nst_cpt_node_opss[node->type].is_valid(node);
}
