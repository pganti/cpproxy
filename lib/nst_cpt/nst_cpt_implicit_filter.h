#ifndef _NST_CPT_ITPLICIT_FILTER_H
#define _NST_CPT_ITPLICIT_FILTER_H

struct nst_cpt_node_s;
struct nst_cpt_request_s;

int nst_cpt_implicit_filter_by_request(const struct nst_cpt_node_s *node,
                                       const struct nst_cpt_request_s *request);


#endif
