#include "nst_http_upstream_connect.h"

/* local includes */
#include "nst_http_upstream.h"
#include "nst_http_request.h"
#include "nst_http_transaction.h"
#include "nst_http_tcp_ext.h"

/* libcpproxy_cfg includes */
#include <nst_cpproxy_cfg.h>
#include <nst_cpproxy_cfg_remote_dc.h>
#include <nst_cpproxy_cfg_box.h>

/* libnst_cpt includes */
#include <nst_cpt_spc_node.h>
#include <nst_cpt_osrv_node.h>
#include <nst_cpt_node.h>

/* libevent includes */
#include <nst_unix_connect.h>
#include <nst_tp_connection.h>
#include <nst_cfg_sproxy.h>

/* libcore includes */
#include <nst_genhash.h>
#include <nst_types.h>

static int
nst_http_upstream_get_tcp_ext(const nst_cpt_node_t *node)
{
    switch(node->type) {
    case NST_CPT_NODE_TYPE_SPC:
        return NST_HTTP_TCP_EXT_ACTIVE_TP;
    case NST_CPT_NODE_TYPE_OSRV:
        return NST_HTTP_TCP_EXT_ACTIVE_ORIGIN;
    default:
        nst_assert(0 && "unhandled u->cpt_node->type");
    }
}

static nst_status_e
nst_http_spc_connect(const nst_cpt_node_t *node,
                     struct nst_http_upstream_s *u)
{
    const nst_cpproxy_cfg_remote_dc_t *remote_dc;
    const char             *name;
    nst_http_request_t     *r;
    nst_cfg_sproxy_t       *sproxy;
    nst_genhash_key_t       ip_hash;
    size_t                  nsproxies;
    size_t                  sproxy_index;
    const nst_sockaddr_t   *end_user_ip;

    r = u->request;
    name = nst_cpt_spc_node_get_dc_name(node);
    remote_dc = nst_genhash_find(cpproxy_cfg.remote_dc_ghash, name);
    if(!remote_dc) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui cannot connect to SPC %s.  not found in config",
                    r->id, name);
        return NST_ERROR;
    }

    nsproxies = nst_vector_get_nelts(remote_dc->sproxy_vec);
    if(!nsproxies) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui data-center %s has no sproxy",
                    r->id, name);
        return NST_ERROR;
    }

    end_user_ip = nst_http_request_get_end_user_ip(r);
    nst_assert(end_user_ip);
    ip_hash = nst_genhash_sockaddr_ip(end_user_ip);
    
    sproxy_index = ip_hash % nsproxies;


    nst_assert(sproxy_index < nsproxies);
    sproxy = *(nst_cfg_sproxy_t **)nst_vector_get_elt_at(remote_dc->sproxy_vec,
                                                         sproxy_index);

    if(nst_tp_connect(&u->connection,
                      &((cpproxy_cfg.my_box)->frontend_ip),
                      nst_http_upstream_get_tcp_ext(node),
                      r->id,
                      r->noc_log_lvl,
                      r->dbg_log_lvl,
                      sproxy,
                      FALSE) == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui cannot connect to SPC %s. %s(%d)",
                    r->id, sproxy->sysid,
                    nst_strerror(errno), errno);
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static nst_status_e
nst_http_ip_connect(const nst_cpt_node_t *node,
                    struct nst_http_upstream_s *u)
{
    nst_sockaddr_t peer_sockaddr;
    nst_sockaddr_t *local_sockaddr;
    nst_http_request_t *r;
    nst_status_e ret;

    r = u->request;

    local_sockaddr = &(cpproxy_cfg.my_box)->frontend_ip;
    nst_sockaddr_init_by_sockaddr(&peer_sockaddr,
                                  nst_cpt_osrv_node_get_sockaddr(node));
    nst_sockaddr_set_port(&peer_sockaddr, 
                          nst_http_request_get_os_dst_port(r));

    ret = nst_unix_connect(&u->connection,
                           &peer_sockaddr,
                           local_sockaddr,
                           nst_http_upstream_get_tcp_ext(node),
                           r->id,
                           r->noc_log_lvl,
                           r->dbg_log_lvl);
    if(ret == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui cannot connect to os-ip %s:%s. %s(%d)",
                    r->id,
                    nst_sockaddr_get_ip_str(&peer_sockaddr),
                    nst_sockaddr_get_port_str(&peer_sockaddr),
                    nst_strerror(errno), errno);
        return NST_ERROR;
    } else {
        return ret;
    }
}

nst_status_e
nst_http_upstream_connect(const nst_cpt_node_t *node,
                          struct nst_http_upstream_s *u)
{
    nst_status_e ret = NST_OK;
    nst_http_request_t *r = u->request;
    nst_connection_t *upstream;
    nst_http_upstream_stats_t *stats;

    nst_assert(!u->connection);

    r->state = NST_HTTP_REQ_STATE_CONNECT_UPSTREAM;

    stats = u->current_stats = NULL;
    if(!u->stats_array)  {
        u->stats_array = nst_array_create(u->pool, 1,
                                      sizeof(nst_http_upstream_stats_t));
    }
    if(u->stats_array) {
        stats = u->current_stats = nst_array_push(u->stats_array);
    }
    if(!stats) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui cannot allocate memory for "
                    "nst_http_upstream_stats_t object",
                    r->id);
        return NST_ERROR;
    }

    switch(node->type) {
    case NST_CPT_NODE_TYPE_SPC:
        ret = nst_http_spc_connect(node, u);
        break;
    case NST_CPT_NODE_TYPE_OSRV:
        if(nst_cpt_osrv_node_is_hostname(node))
            nst_assert(0 && "TODO: hostname origin server connect");
        else
            ret = nst_http_ip_connect(node, u);

        break;
    default:
        nst_assert(0 && "not handled CPT node type");
    }

    nst_http_upstream_stats_init(stats, r, node);

    if(ret == NST_ERROR) {
        stats->connect_result_ms = nst_current_msec;
        stats->connect_failed = 1;
        return ret;
    } else {
        if(ret == NST_OK) 
            stats->connect_result_ms = nst_current_msec;

        upstream = u->connection;
        nst_assert(upstream);
    }
    
    upstream->write->handler = nst_http_upstream_handler;
    upstream->read->handler = nst_http_upstream_handler;
    upstream->pool = r->pool;
    upstream->tid = r->id;
    upstream->data = u;

    u->flags.request_sent = 0;

    return ret;
}
