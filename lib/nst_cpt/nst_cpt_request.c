#include "nst_cpt_request.h"

#include <nst_string.h>
#include <nst_assert.h>

void
nst_cpt_request_init(nst_cpt_request_t *cpt_request,
                     nst_cpt_request_type_e type,
                     const struct nst_sockaddr_s *end_user_ip,
                     nst_log_level_t noc_log_lvl,
                     nst_cpt_app_filter_f app_filter,
                     nst_cpt_score_ovr_f score_ovr)
{
    nst_assert(end_user_ip);

    cpt_request->type = type;
    cpt_request->end_user_ip = end_user_ip;
    nst_memzero(cpt_request->last_tried_nodes,
                sizeof(cpt_request->last_tried_nodes));
    cpt_request->ntried = 0;
    cpt_request->noc_log_lvl = noc_log_lvl;
    cpt_request->msg_log_lvl = NST_LOG_LEVEL_DEBUG;
    cpt_request->app_filter = app_filter;
    cpt_request->score_ovr = score_ovr;
}
