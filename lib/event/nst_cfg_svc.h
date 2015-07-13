#ifndef _NST_SVC_CFG_H_
#define _NST_SVC_CFG_H_

#include <nst_config.h>

#include "nst_connection.h"

#include <nst_cfg_common.h>

#include <nst_sockaddr.h>
#include <nst_queue.h>
#include <nst_times.h>
#include <nst_types.h>
#include <nst_limits.h>
#include <nst_log.h>
#include <nst_refcount.h>

#include <expat.h>

#define SERVICE_TAG "service"

struct nst_genhash_s;
struct nst_listener_s;

/* typedef struct nst_cfg_svcs_s nst_cfg_svcs_t; */
typedef struct nst_cfg_svc_s nst_cfg_svc_t;
typedef enum nst_svc_type_e nst_svc_type_e;

enum nst_svc_type_e
{
    NST_SVC_TYPE_UNKNOWN = 0,
    NST_SVC_TYPE_TUNNEL = 1,
    NST_SVC_TYPE_HTTP = 2,
    NST_SVC_TYPE_TP = 3,
    NST_SVC_TYPE_QUICK_HTTP_TRIAL = 4,
    NST_SVC_TYPE_TCP = 5,
    _NUM_NST_SVC_TYPE = 6,
};

struct nst_cfg_svc_s
{
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    nst_svc_type_e type;
    uint32_t vip_index;
    nst_sockaddr_t listen_sockaddr;
    char edomain_name[NST_MAX_DOMAIN_NAME_BUF_SIZE]; /* effective domain name */
    size_t edomain_name_len;

    bool  public_ip;
    bool  ssl;
    bool  deferred_accept;

    int tcp_ext;
    int backlog;
    size_t new_conn_mpool_size;
    nst_msec_t post_accept_timeout_ms;
    nst_uint_t naccepts_per_loop;

    nst_log_level_t dbg_log_lvl;
    nst_log_level_t noc_log_lvl;

    nst_connection_handler_f handler;

    struct nst_listener_s *listener;

    NST_REFC_CTX_DEF
};

nst_status_e
nst_cfg_svc_capture(void *udata,
                    const XML_Char *name,
                    const XML_Char **attrs,
                    void **ret_svc, void **unused1,
                    void **unused2, void **unused3);

void nst_cfg_svc_free(void *data);

bool nst_cfg_svc_is_http_like(const nst_cfg_svc_t *svc);

nst_svc_type_e nst_cfg_svc_type_from_str(const char *buf);

const char *nst_cfg_svc_type_to_str(nst_svc_type_e type);

nst_cfg_reload_status_e nst_cfg_svc_apply_modified(nst_cfg_svc_t *svc,
                                                   nst_cfg_svc_t *new_svc,
                                                   bool test_only_mode);

static inline bool
nst_cfg_svc_is_up(const nst_cfg_svc_t *svc)
{
    /* TODO: also consider SSL cert/key validity later */
    return (svc->listener == NULL ? FALSE : TRUE);
}

NST_REFC_GENHASH_COPY_FUNC_DCL(nst_cfg_svc_s)

#endif
