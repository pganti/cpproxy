#ifndef _NST_HTTP_CPT_SCORE_OVR_H_
#define _NST_HTTP_CPT_SCORE_OVR_H_

#include <nst_config.h>

#include <nst_cpt_node.h>

struct nst_cpt_request_s;

nst_cpt_node_score_t
nst_http_cpt_score_ovr(const nst_cpt_node_t *node,
                       const struct nst_cpt_request_s *cpt_request);

#endif
