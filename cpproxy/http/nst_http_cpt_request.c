#include "nst_http_cpt_request.h"

#include "nst_http_cpt_filter.h"
#include "nst_http_request.h"

#include <nst_cpt_request.h>

void
nst_http_cpt_request_init(nst_http_cpt_request_t *http_cpt_request,
                          const nst_http_request_t *r)
{
    nst_cpt_request_init(&http_cpt_request->cpt_request,
                         NST_CPT_REQ_TYPE_HTTP,
                         nst_http_request_get_end_user_ip(r),
                         r->noc_log_lvl,
                         nst_http_cpt_filter,
                         NULL);

    http_cpt_request->http_request = r;
}
