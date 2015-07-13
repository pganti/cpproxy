#ifndef _NST_CPPROXY_CFG_LISTEN_H_
#define _NST_CPPROXY_CFG_LISTEN_H_

#include <nst_config.h>
#include <nst_types.h>

#include <nst_cfg_common.h>

#include <expat.h>

#define LISTEN_TAG          "listen"
#define ALL_PUBLIC_HTTP_TAG "all-public-http"
#define ALL_VIP_HTTP_TAG    "all-vip-http"
#define REF_SERVICE_TAG     "ref-service"

struct nst_genhash_s;

typedef struct nst_cpproxy_cfg_listen_s nst_cpproxy_cfg_listen_t;

struct nst_cpproxy_cfg_listen_s
{
    struct nst_genhash_s *ref_name_ghash;
    bool all_public_http;
    bool all_vip_http;
};

nst_status_e nst_cpproxy_cfg_listen_init(nst_cpproxy_cfg_listen_t *listen_cfg);

void nst_cpproxy_cfg_listen_reset(nst_cpproxy_cfg_listen_t *listen_cfg);

nst_status_e nst_cpproxy_cfg_listen_capture(void *udate,
                                            const XML_Char *name,
                                            const XML_Char **attrs,
                                            void **ret_listen, void **unused1,
                                            void **unused2, void **unused3);

nst_cfg_reload_status_e
nst_cpproxy_cfg_listen_apply_modified(nst_cpproxy_cfg_listen_t *listen,
                                      nst_cpproxy_cfg_listen_t *new_listen,
                                      bool *relisten);

#endif
