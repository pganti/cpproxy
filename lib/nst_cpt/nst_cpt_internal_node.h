#ifndef _NST_CPT_INTERNAL_NODE_H_
#define _NST_CPT_INTERNAL_NODE_H_

#include <nst_config.h>

struct nst_cpt_node_s;

extern struct nst_cpt_node_ops_s nst_cpt_internal_node_ops;

int nst_cpt_internal_node_add_child(struct nst_cpt_node_s *node,
                                    struct nst_cpt_node_s *child);

#endif
