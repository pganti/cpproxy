#include "nst_cpt_eval.h"

#include "nst_cpt_request.h"
#include "nst_cpt_node.h"

#include <nst_sockaddr.h>
#include <nst_vector.h>
#include <nst_assert.h>
#include <nst_log.h>

#include <stdlib.h>
#include <alloca.h>

typedef struct nst_cpt_result_s nst_cpt_result_t;

struct nst_cpt_result_s
{
    const nst_cpt_node_t *node;
    nst_cpt_node_score_t score;
};

static int
nst_cpt_result_compare(const void *a, const void *b);

static nst_cpt_result_t
nst_cpt_internal_eval(const nst_cpt_node_t *node,
                      nst_cpt_request_t *request,
                      size_t depth);

const nst_cpt_node_t *
nst_cpt_find_nh(const nst_cpt_node_t *node,
                nst_cpt_request_t *request)
{
    nst_cpt_result_t result;

    if(request->ntried > NST_CPT_MAX_NUM_TRIES)
        return NULL;

    result = nst_cpt_internal_eval(node, request, 0);

    if(result.node) 
        request->last_tried_nodes[request->ntried++] = result.node;

    return result.node;
}

static int
nst_cpt_result_compare(const void *a, const void *b)
{
    nst_cpt_result_t *result_a;
    nst_cpt_node_score_t score_a;
    nst_cpt_result_t *result_b;
    nst_cpt_node_score_t score_b;

    result_a = (nst_cpt_result_t *)a;
    score_a = result_a->score;
    result_b = (nst_cpt_result_t *)b;
    score_b = result_b->score;

    if(score_a < score_b)
        return -1;
    else if(score_a > score_b)
        return 1;
    else
        return 0;
}

static nst_cpt_result_t
nst_cpt_internal_eval(const nst_cpt_node_t *node,
                      nst_cpt_request_t *request,
                      size_t depth)
{
    nst_cpt_result_t *up_results;
    nst_cpt_result_t *all_results;
    nst_cpt_result_t result;
    nst_cpt_node_type_e node_type;
    nst_cpt_node_sel_type_e node_sel_type;
    size_t nup = 0;
    size_t nchildren = 0;

    /* TODO: log the request */
    /*
    if(request->debug_log_level > NST_CPT_DEBUG_LOG_LEVEL_3) {
        if(request->current_depth == 0)
            request->debug_log(request);

        nst_cpt_debug_log_node(request->debug_log_level,
                           node);
    }
    */

    node_type = nst_cpt_node_get_type(node);
    node_sel_type = nst_cpt_node_get_sel_type(node);
    switch(node_type) {
    case NST_CPT_NODE_TYPE_OSITE:
    case NST_CPT_NODE_TYPE_INTERNAL:
        switch(node_sel_type) {
        case NST_CPT_NODE_SEL_TYPE_SCORE:
        case NST_CPT_NODE_SEL_TYPE_FIRST:
        case NST_CPT_NODE_SEL_TYPE_RANDOM: 
        case NST_CPT_NODE_SEL_TYPE_END_USER_IP_HASH: {
            size_t  i;
            nchildren = nst_vector_get_nelts(node->children);
            up_results = alloca(nchildren * sizeof(nst_cpt_result_t));
            all_results = alloca(nchildren * sizeof(nst_cpt_result_t));
            if(!up_results || !all_results) {
                result.node = NULL;
                result.score = 1;
                goto DONE;
            }

            for(i = 0; i < nchildren; i++) {
                nst_cpt_node_t *child_node;
                child_node = 
                    *(nst_cpt_node_t**)(nst_vector_get_elt_at(node->children, i));
                all_results[i] = nst_cpt_internal_eval(child_node, request,
                                                       depth + 1);
                if(all_results[i].score >= NST_CPT_NODE_SCORE_MIN
                   && all_results[i].score <= NST_CPT_NODE_SCORE_MAX)
                    up_results[nup++] = all_results[i];

            } /* for(i = 0.... */
            break;
        }
        default:
            nst_assert(0 && "unhandled nst_cpt_sel_type_e");
        }; /* switch(node->sel_type) */

        break;
    case NST_CPT_NODE_TYPE_MAPPED_CPC:
    case NST_CPT_NODE_TYPE_FORCE_CPC:
    case NST_CPT_NODE_TYPE_CACHE:
    case NST_CPT_NODE_TYPE_SPC:
    case NST_CPT_NODE_TYPE_INTERMEDIATE_SPC:
    case NST_CPT_NODE_TYPE_OSRV: {
        size_t i;
        result.node = node;
        for(i = 0; i < request->ntried; i++) {
            if(node == request->last_tried_nodes[i]) {
                result.score = NST_CPT_NODE_SCORE_DOWN_BY_TRIED;
                goto DONE;
            }
        }

        if(request->app_filter
           && request->app_filter(node, request)) {
            result.score = NST_CPT_NODE_SCORE_DOWN_BY_APP_FILTERED;
        } else if(request->score_ovr) {
            result.score = request->score_ovr(node, request);
        } else {
            result.score = nst_cpt_node_get_score(node);
        }

        goto DONE;

/*
        if(nst_cpt_implicit_filter_by_request(node, request)) {
            return { node, NST_CPT_NODE_SCORE_FILTERED };
        } else {
            return { node, nst_cpt_node_get_score(node) };
        }
*/
        
        nst_assert(0 && "a node result should have been returned by this point");
    }
    case NST_CPT_NODE_TYPE_UNKNOWN:
    case _NST_CPT_NODE_TYPE_NUM:
    default:
        nst_assert(0 && "unexpected nst_cpt_node_type_e");
    };
        
    /* only NST_CPT_NODE_TYPE_INTERNAL or OSITE should reach here */
    nst_assert(node->type == NST_CPT_NODE_TYPE_INTERNAL
               || node->type == NST_CPT_NODE_TYPE_OSITE);

    if(nup == 0) {
        /* none of my children is UP */
        result.node = NULL;
        result.score = NST_CPT_NODE_SCORE_DOWN_BY_NO_CHILD;
        goto DONE;
    }

    if(node->sel_type == NST_CPT_NODE_SEL_TYPE_SCORE) {
        qsort(up_results, nup,
              sizeof(nst_cpt_result_t), nst_cpt_result_compare);
        result = up_results[0];
    } else if(node->sel_type == NST_CPT_NODE_SEL_TYPE_FIRST) {
        result = up_results[0];
    } else if(node->sel_type == NST_CPT_NODE_SEL_TYPE_RANDOM) {
        result = up_results[random() % nup];
    } else if(node->sel_type == NST_CPT_NODE_SEL_TYPE_END_USER_IP_HASH) {
        uint32_t key;
        size_t index;

        nst_assert(nchildren > 0);

        if(request->end_user_ip) {
            key = nst_genhash_sockaddr_ip(request->end_user_ip);
        } else {
            key = 0;
        }
        index = key % nchildren;

        if(all_results[index].score >= NST_CPT_NODE_SCORE_MIN
           && all_results[index].score <= NST_CPT_NODE_SCORE_MAX) {
            /* we wanna stick an end-user to a particular machine and not
             * affected by another down machine.
             * e.g. end-user X sticks to osrv A.
             *      if osrv B goes down, end-user X should still stick
             *      to osrv A.
             */
            return all_results[index];
        } else {
            /* end-user who stick to a down machine will be hashed
             * to another up machine
             */
            index = key % nup;
            return up_results[index];
        }

    } else {
        nst_assert(0 && "unhandled nst_cpt_node_sel_type_e");
    }

 DONE:
    if(nst_noc_log_level_test_ml(request->noc_log_lvl, request->msg_log_lvl)) {
        nst_cpt_node_eval_reg_log(node,
                                  result.node,
                                  result.score,
                                  request->noc_log_lvl,
                                  request->msg_log_lvl,
                                  depth);
    }

    return result;
}
