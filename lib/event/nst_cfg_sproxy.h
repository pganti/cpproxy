#ifndef _NST_CFG_SPROXY_H_
#define _NST_CFG_SPROXY_H_

#include <nst_config.h>

#include <queue.h>
#include <nst_refcount.h>
#include <nst_sockaddr.h>

struct nst_tp_connection_s;

typedef struct nst_cfg_sproxy_s nst_cfg_sproxy_t;

TAILQ_HEAD(nst_tp_conn_queue_s, nst_tp_connection_s);

struct nst_cfg_sproxy_s
{
    char sysid[NST_MAX_SYSID_BUF_SIZE];  /* cmd@box-name@dc-name */

    nst_sockaddr_t mp_listen_sockaddr;
    /* nst_sockaddr_t ssl_tp_listen_sockaddr; */

    struct nst_tp_conn_queue_s active_queue;
    /* struct nst_tp_conn_queue_s passive_queue; */

    /* void *dc;  */ /* parent remote data-center */

    struct {
        unsigned destroyed:1;
    } flags;
    /* bool    up; */ /* Liveliness Status */

    NST_REFC_CTX_DEF
};

void nst_cfg_sproxy_init(nst_cfg_sproxy_t *sproxy,
                         const char *sysid,
                         const nst_sockaddr_t *ip_sockaddr,
                         in_port_t portn);
                         
nst_cfg_sproxy_t *nst_cfg_sproxy_new(void);

void nst_cfg_sproxy_free(nst_cfg_sproxy_t *sproxy);
void nst_cfg_sproxy_vec_free(void *);
void nst_cfg_sproxy_remove_all_tp_conn(nst_cfg_sproxy_t *sproxy);

NST_REFC_GENHASH_COPY_FUNC_DCL(nst_cfg_sproxy_s)

#endif
