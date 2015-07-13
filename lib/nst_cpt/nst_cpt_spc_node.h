#ifndef _NST_CPT_SPC_NODE_H_
#define _NST_CPT_SPC_NODE_H_

struct nst_cpt_node_s;

extern struct nst_cpt_node_ops_s nst_cpt_spc_node_ops;

void nst_cpt_spc_node_set_dc_name(struct nst_cpt_node_s *node, const char *dc_name);

const char *nst_cpt_spc_node_get_dc_name(const struct nst_cpt_node_s *node);
char * nst_cpt_spc_node_alloc_spc_health_vec (int scount, const struct nst_cpt_node_s *node);
int nst_cpt_spc_node_get_health_vec_size (const struct nst_cpt_node_s *node);
char * nst_cpt_spc_node_get_health_vec (const struct nst_cpt_node_s *node);

#endif
