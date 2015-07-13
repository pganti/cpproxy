#include "nst_cfg_sproxy.h"

#include "nst_tp_connection.h"

#include <nst_cfg_common.h>

#include <nst_sockaddr.h>
#include <nst_allocator.h>

#include <string.h>

static void nst_cfg_sproxy_do_free(void *data)
{
    /* nst_cfg_sproxy_t *sproxy; */

    nst_allocator_free(&nst_cfg_allocator, data);
}

void nst_cfg_sproxy_init(nst_cfg_sproxy_t *sproxy,
                         const char *sysid,
                         const nst_sockaddr_t *ip_sockaddr,
                         in_port_t portn)
{
    memcpy(sproxy->sysid, sysid, NST_MAX_SYSID_BUF_SIZE);
    sproxy->sysid[NST_MAX_SYSID_BUF_SIZE - 1] = '\0';
    memcpy(&sproxy->mp_listen_sockaddr, ip_sockaddr,
           sizeof(nst_sockaddr_t));
    nst_sockaddr_set_port(&sproxy->mp_listen_sockaddr, portn);
    /* sproxy->dc = dc; */
}

nst_cfg_sproxy_t *
nst_cfg_sproxy_new(void)
{
    nst_cfg_sproxy_t *new_sproxy;

    new_sproxy = nst_allocator_calloc(&nst_cfg_allocator, 1,
                                      sizeof(nst_cfg_sproxy_t));
    if(!new_sproxy)
        return NULL;

    TAILQ_INIT(&new_sproxy->active_queue);
    /* TAILQ_INIT(&new_sproxy->passive_queue); */
    
    NST_REFC_INIT(new_sproxy, nst_cfg_sproxy_do_free);
    return new_sproxy;
}

void nst_cfg_sproxy_vec_free(void *data)
{
    nst_cfg_sproxy_free(*(nst_cfg_sproxy_t **)data);
}

void nst_cfg_sproxy_free(nst_cfg_sproxy_t *sproxy)
{
    NST_REFC_PUT(sproxy);
}

void
nst_cfg_sproxy_remove_all_tp_conn(nst_cfg_sproxy_t *sproxy)
{
    nst_tp_connection_t *tp_conn;
    nst_tp_connection_t *tmp_tp_conn;

    TAILQ_FOREACH_SAFE(tp_conn,
                       &sproxy->active_queue,
                       queue_entry,
                       tmp_tp_conn) {
        nst_tp_conn_free(tp_conn);
    }

    sproxy->flags.destroyed = 1;
}

NST_REFC_GENHASH_COPY_FUNC_DEF(nst_cfg_sproxy_s)
