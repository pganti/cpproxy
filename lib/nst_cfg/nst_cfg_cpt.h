#ifndef _NST_CFG_CPT_H_
#define _NST_CFG_CPT_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

#define NEXT_HOP_TREE_TAG          "next-hop-tree"
#define CPT_NODE_NAME_TAG          "name"
#define CPT_NODE_SELECTION_TAG     "selection"
#define CPT_NODE_SCORE_TAG         "score"


struct nst_cpt_node_s;
struct nst_vector_s;
struct nst_cfg_tag_action_s;
struct nst_expat_stack_frame_s;

nst_status_e nst_cfg_cpt_capture(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs,
                                 struct nst_cpt_node_s **nst_cpt_node,
                                 const struct nst_vector_s *origin_sites);

nst_status_e
nst_cfg_tag_action_set_cpt_node_name(void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t vl);

nst_status_e
nst_cfg_tag_action_set_cpt_node_selection(void *cfg_obj,
                                          const struct nst_cfg_tag_action_s *action,
                                          struct nst_expat_stack_frame_s *current,
                                          const char *value, size_t value_len);

nst_status_e
nst_cfg_tag_action_set_cpt_node_score(void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t value_len);


#endif
