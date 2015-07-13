#ifndef _NST_CPT_EVAL_H_
#define _NST_CPT_EVAL_H_

#include <nst_config.h>
#include <nst_types.h>

struct nst_cpt_node_s;
struct nst_cpt_request_s;

const struct nst_cpt_node_s *
nst_cpt_find_nh(const struct nst_cpt_node_s *node,
                struct nst_cpt_request_s *request);

#endif
