#ifndef _NST_CPPROXY_CFG_BOX_H_
#define _NST_CPPROXY_CFG_BOX_H_

#include <nst_config.h>

#include "nst_cpproxy_cfg.h"

#include <nst_cfg_box.h>
#include <nst_cfg_common.h>

#include <nst_sockaddr.h>
#include <nst_types.h>

#include <string.h>

typedef struct nst_cpproxy_cfg_box_s nst_cpproxy_cfg_box_t;

struct nst_cfg_log_fac_s;

struct nst_cpproxy_cfg_box_s
{
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    nst_cfg_box_type_e type;
    nst_sockaddr_t natted_frontend_ip;
    nst_sockaddr_t frontend_ip;
    nst_sockaddr_t backend_ip;
};

static inline
void nst_cpproxy_cfg_box_reset(nst_cpproxy_cfg_box_t *box)
{
    memset(box, 0, sizeof(nst_cpproxy_cfg_box_t));
}

static inline const nst_sockaddr_t *
nst_cpproxy_cfg_box_get_natted_frontend_ip(const nst_cpproxy_cfg_box_t *box)
{
    if(nst_sockaddr_get_family(&box->natted_frontend_ip) != AF_UNSPEC)
        return &box->natted_frontend_ip;
    else
        return &box->frontend_ip;
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_box_apply_modified(nst_cpproxy_cfg_box_t *box,
                                   nst_cpproxy_cfg_box_t *new_box,
                                   bool *ip_changed);
#endif
