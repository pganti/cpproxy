/* always include myself first */
#include "nst_http.h"

/* local includes */
#include "nst_http_downstream_vars.h"
#include "nst_http_upstream_vars.h"
#include "nst_http_req_header.h"
#include "nst_http_access_log.h"
#include "nst_http_variables.h"

#include <nst_types.h>

nst_status_e
nst_http_init(void)
{
    if(nst_http_req_header_hash_init())
        return NST_ERROR;

    if(nst_http_downstream_add_vars())
        return NST_ERROR;

    if(nst_http_upstream_add_vars())
        return NST_ERROR;

    if(nst_http_access_log_init())
        return NST_ERROR;

    return NST_OK;
}

void
nst_http_reset(void)
{
    nst_http_access_log_reset();
}
