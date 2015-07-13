#ifndef _NST_CPT_OSITE_NODE_H_
#define _NST_CPT_OSITE_NODE_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_vector_s;
struct nst_cpt_node_s;

typedef struct nst_cpt_osite_node_data_s nst_cpt_osite_node_data_t;
struct nst_cpt_osite_node_data_s
{
    struct nst_vector_s *responsible_spc_names;

    struct {
        unsigned int am_i_responsible:1;
    } flags;
};

extern struct nst_cpt_node_ops_s nst_cpt_osite_node_ops;

void nst_cpt_osite_node_set_responsible(struct nst_cpt_node_s *node);
bool nst_cpt_osite_node_am_i_responsible(const struct nst_cpt_node_s *node);
nst_status_e nst_cpt_osite_node_add_child(struct nst_cpt_node_s *node,
                                          struct nst_cpt_node_s *child);
nst_status_e nst_cpt_osite_node_add_dc(struct nst_cpt_node_s *node,
                                       const char *dc_name,
                                       size_t dc_name_len);

#endif
