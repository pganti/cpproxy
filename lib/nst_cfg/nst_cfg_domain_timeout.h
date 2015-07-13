#ifndef _NST_CFG_DOMAIN_TIMEOUT_H_
#define _NST_CFG_DOMAIN_TIMEOUT_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

/* libcore includes */
#include <nst_times.h>
#include <nst_refcount.h>
#include <nst_types.h>

/* sys and 3rd party includes */
#include <expat.h>

#define NST_TUNNEL_READ_TIMEOUT_MS       (300000) /* 5 mins    */
#define NST_UPSTREAM_CONNECT_TIMEOUT_MS  (5000)   /* 5 s       */
#define NST_HTTP_RESPONSE_TIMEOUT_MS     (10000)  /* 10 s      */
#define NST_READ_TIMEOUT_MS              (5000)   /* 5 s       */
#define NST_WRITE_TIMEOUT_MS             (5000)   /* 5 s       */
#define NST_END_USER_PCONN_TIMEOUT_MS    (60000)  /* 60 s      */

#define DOMAIN_TIMEOUT_TAG "timeout"

typedef struct nst_cfg_domain_timeout_s nst_cfg_domain_timeout_t;

struct nst_cfg_domain_timeout_s
{
    nst_msec_t tunnel_read_ms;
    nst_msec_t upstream_connect_ms;
    nst_msec_t http_response_ms;
    nst_msec_t read_ms;
    nst_msec_t write_ms;
    nst_msec_t end_user_pconn_ms;
};

nst_status_e nst_cfg_domain_timeout_capture(void *udata,
                                            const XML_Char *name,
                                            const XML_Char **attrs,
                                            void **pdomain_timeout, void **unused,
                                            void **unused2, void **unused3);
void nst_cfg_domain_timeout_init(nst_cfg_domain_timeout_t *domain_timeout);

#endif
