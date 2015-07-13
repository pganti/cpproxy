#ifndef _NST_CPT_WALK_H_
#define _NST_CPT_WALK_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_cpt_node_s;

typedef nst_status_e (*nst_cpt_walk_f)(struct nst_cpt_node_s *node, void *data);

nst_status_e nst_cpt_walk(struct nst_cpt_node_s *node,
                          nst_cpt_walk_f walk,
                          void *data);

#endif
