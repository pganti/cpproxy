#ifndef _NST_HTTP_CPT_REQUEST_H_
#define _NST_HTTP_CPT_REQUEST_H_

#include <nst_config.h>

#include <nst_cpt_request.h>

struct nst_http_request_s;

typedef struct nst_http_cpt_request_s nst_http_cpt_request_t;

struct nst_http_cpt_request_s
{
    nst_cpt_request_t cpt_request; /* it must be the very first member */

    const struct nst_http_request_s *http_request;
};

void nst_http_cpt_request_init(nst_http_cpt_request_t *http_cpt_request,
                               const struct nst_http_request_s *r);

#endif
