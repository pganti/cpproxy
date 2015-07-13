/* always include myself first */
#include "nst_http_cpt_score_ovr.h"

/* local includes */
#include "nst_http_cpt_request.h"
#include "nst_http_request.h"

/* libnstcpt includes */
#include <nst_cpt_osrv_node.h>
#include <nst_cpt_node.h>
#include <nst_cpt_request.h>

/* libnstcfg includes */
#include <nst_cfg_domain.h>

#define BASE_RANDOM_OSRV_SCORE (NST_CPT_NODE_SCORE_MAX - 1023)
#define NRANDOM_SCORE    (1024)

nst_cpt_node_score_t
nst_http_cpt_score_ovr(const nst_cpt_node_t *node,
                       const nst_cpt_request_t *cpt_request)

{
    const nst_http_cpt_request_t *http_cpt_request;
    const nst_http_request_t *r;
    nst_cpt_node_score_t random_score;

    http_cpt_request = (const nst_http_cpt_request_t *)cpt_request;
    r = http_cpt_request->http_request;
    nst_assert(r->domain_cfg);

    if(node->type != NST_CPT_NODE_TYPE_OSRV)
        return nst_cpt_node_get_score(node);

    /* it is a NST_CPT_NODE_TYPE_OSRV */

    if(nst_cfg_domain_am_i_spc(r->domain_cfg)
       && !nst_cpt_osrv_node_am_i_responsible(node)) {
        return nst_cpt_node_get_score(node);
    }

    random_score = random() % NRANDOM_SCORE;
    random_score += BASE_RANDOM_OSRV_SCORE;
    
    return random_score;
}
