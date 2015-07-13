#include "cpt.h"

#include <stdlib.h>

#include "nst_allocator.h"
#include "nst_array.h"

typedef struct cpt_result_s cpt_result_t;

static nst_allocator_t cpt_allocator;
static cpt_log_t cpt_log;

static cpt_result_t cpt_internal_eval(const cpt_node_t *node,
                                      cpt_request_t *request);

struct cpt_result_s
{
    const cpt_node_t *node;
    cpt_score_t score;
};

static inline cpt_score_t cpt_score(const cpt_node_t *node)
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
    return node->score;
}

static int cpt_result_compare(const void *a, const void *b)
{
    cpt_score_t score_a = ((cpt_result_t *)a)->score;
    cpt_score_t score_b = ((cpt_result_t *)b)->score;

    if(score_a < score_b)
        return -1;
    else if(score_a > score_b)
        return 1;
    else
        return 0;
}

void cpt_init(const nst_allocator_t *allocator,
              const cpt_log_t *log)
{
    cpt_allocator = *allocator;
    cpt_log = *log;
}

cpt_node_t *cpt_node_create(cpt_node_type_e node_type)
{
    cpt_node_t *new_node;
    new_node = cpt_allocator.calloc(cpt_allocator.data, sizeof(cpt_node_t));
    new_node->type = node_type;

    switch(node_type) {
    case CPT_NODE_TYPE_UNKNOWN:
        assert(node_type != CPT_NODE_TYPE_UNKNOWN);
    case CPT_NODE_TYPE_INTERNAL:
    case CPT_NODE_TYPE_MAPPED_CPC:
    case CPT_NODE_TYPE_FORCE_CPC:
    case CPT_NODE_TYPE_CACHE:
    case CPT_NODE_TYPE_SPC: 
    case CPT_NODE_TYPE_INTERMEDIATE_SPC:
    case CPT_NODE_TYPE_OS:
        new_node->score = CPT_SCORE_UNKNOWN;
        break;
    default:
        assert("Invalid cpt_node_type_e sel_type" && 0);
    };

    new_node->sel_type = CPT_SEL_TYPE_UNKNOWN;

    new_node->data = NULL;
}

void cpt_node_destroy(cpt_node_t *node)
{
    nst_array_destroy(node->children);
    cpt_allocator.free(cpt_allocator.data, node);
}

const cpt_node_t *cpt_find_next_hop(cpt_node_t *node,
                              cpt_request_t *request)
{
    cpt_result_t result;

    if(request->ntried > CPT_MAX_NUM_TRIES)
        return NULL;

    result = cpt_internal_eval(node, request);
    return result.node;
}

static cpt_result_t cpt_internal_eval(const cpt_node_t *node,
                                       cpt_request_t *request)
{
    cpt_result_t *up_results;
    size_t nup = 0;

    /* TODO: log the request */
    /*
    if(request->debug_log_level > CPT_DEBUG_LOG_LEVEL_3) {
        if(request->current_depth == 0)
            request->debug_log(request);

        cpt_debug_log_node(request->debug_log_level,
                           node);
    }
    */

    switch(node->type) {
    case CPT_NODE_TYPE_INTERNAL:
        switch(node->sel_type) {
        case CPT_SEL_TYPE_SCORE:
        case CPT_SEL_TYPE_FIRST:
        case CPT_SEL_TYPE_RANDOM: {
            size_t  i;
            size_t nchildren = nst_array_get_nelts(node->children);
            up_results = alloca(nchildren * sizeof(cpt_result_t));
            if(!up_results) {
                cpt_result_t result = { NULL, CPT_SCORE_DOWN };
                return result;
            }

            for(i = 0; i < nchildren; i++) {
                cpt_node_t *node;
                node = *(cpt_node_t**)(nst_array_get_elt_at(node->children, i));
                up_results[nup] = cpt_internal_eval(node, request);
                if(up_results[nup].score <= CPT_SCORE_MAX
                   && up_results[nup].score >= CPT_SCORE_MIN)
                    nup++;
            }
            break;
        }
        default:
            break;
        };
        break;
    case CPT_NODE_TYPE_MAPPED_CPC:
    case CPT_NODE_TYPE_FORCE_CPC:
    case CPT_NODE_TYPE_CACHE:
    case CPT_NODE_TYPE_SPC:
    case CPT_NODE_TYPE_INTERMEDIATE_SPC:
    case CPT_NODE_TYPE_OS: {
        int i;
        for(i = 0; i < request->ntried; i++) {
            if(node == request->last_tried_nodes[i]) {
                cpt_result_t result = { node, CPT_SCORE_DOWN };
                return result;
            }
        }
        if(cpt_implicit_filter(node, request)) {
            cpt_result_t result = { node, CPT_SCORE_FILTERED };
            return result;
        } else {
            cpt_result_t result = { node, cpt_node_score(node) };
            return result;
        }
    }
    defalt:
        break;
    };
        

    if(nup == 0) {
        cpt_result_t result = { NULL, CPT_SCORE_DOWN };
        return result;
    }

    if(node->sel_type == CPT_SEL_TYPE_SCORE) {
        qsort(up_results, nup,
              sizeof(cpt_result_t), cpt_result_compare);
        return up_results[0];
    } else if(node->sel_type == CPT_SEL_TYPE_FIRST) {
        return up_results[0];
    } else {
        return up_results[random() % nup];
    }
}

#if 0
static void cpt_debug_log_indent(const cpt_request_t *request,
                                 cpt_debug_log_level_e level)
{
    int i;
    if(cpt_log->debug_log_level == CPT_DEBUG_LOG_LEVEL_OFF
       || cpt_log->debug_log_level < level)
        return;

    for(i = 0; i < request->current_depth; i++)
        cpt_log.debug_log("%s", "  ");

    return;
}

static void cpt_regular_log_indent(cpt_regular_log_level_e level)
{
    int i;
    if(cpt_log->regular_log_level < level)
        return;

    for(i = 0; i < request->current_depth; i++)
        cpt_log.regular_log("%s", "  ");

    return;
}

static void cpt_regular_log(cpt_regular_log_level_e level,
                            const char *fmt, ...)
{
    va_list va;
    int saved_errno;

    if(cpt_log.regular_log_level < level)
        return;

    saved_errno = errno;

    va_start(va, fmt);
    cpt_log.regular_log(fmt, ap);
    va_end(ap);

    errno = saved_errno;

    return;
}

static void cpt_debug_log(const char *fmt, ...)
{
    if(cpt_log.debug_log_level == CPT_DEBUG_LOG_LEVEL_OFF
       || cpt_log.debug_log_level < level)
        return;

    saved_errno = errno;

    va_start(va, fmt);
    cpt_log.debug_log(fmt, ap);
    va_end(ap);

    errno = saved_errno;

    return;
}

static const char *cpt_debuge_log_node(const cpt_node_t *node)
{

}
#endif
