#include <nst_config.h>
#include <nst_types.h>

struct nst_cpt_node_s;
struct nst_cpt_request_s;

bool
nst_http_cpt_filter(const struct nst_cpt_node_s *node,
                    const struct nst_cpt_request_s *cpt_request);
