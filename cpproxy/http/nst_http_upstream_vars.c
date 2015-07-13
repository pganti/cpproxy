#include "nst_http_upstream_vars.h"

#include "nst_http_downstream_vars.h"
#include "nst_http_var.h"
#include "nst_http_request.h"
#include "nst_http_upstream.h"

#include <nst_cfg_domain.h>

#include <nst_cpt_node.h>

#define NST_HTTP_VAR_UPSTREAM_PREFIX "ups_"
#define NST_HTTP_VAR_UPSTREAM_RESPONSE_PREFIX \
    NST_HTTP_VAR_UPSTREAM_PREFIX "resp_"

static inline u_char *
nst_http_var_ip_write(const nst_sockaddr_t *sockaddr,
                      u_char *buf,
                      size_t buf_size,
                      const nst_http_var_t *var)

{
    size_t len;
    const u_char *ip_str;

    if(sockaddr) {
        ip_str = (u_char *)nst_sockaddr_get_ip_str(sockaddr);
        len = nst_sockaddr_get_ip_strlen(sockaddr);
    } else {
        ip_str = (u_char *)"0.0.0.0";
        len = static_strlen("0.0.0.0");
    }

    return nst_cpymem(buf, ip_str, min(len, buf_size));
}

static inline u_char *
nst_http_var_port_write(const nst_sockaddr_t *sockaddr,
                        u_char *buf,
                        size_t buf_size,
                        const nst_http_var_t *var)
{
    size_t len;
    const u_char *port_str;

    if(sockaddr) {
        port_str = (u_char *)nst_sockaddr_get_port_str(sockaddr);
        len = nst_sockaddr_get_port_strlen(sockaddr);
    } else {
        port_str = (u_char *)"0";
        len = 1;
    }

    return nst_cpymem(buf, port_str, min(len, buf_size));
}


static u_char *
nst_http_var_upstream_remote_ip_write(nst_http_request_t *r,
                                      u_char *buf,
                                      size_t buf_size,
                                      const nst_http_var_t *var)
{
    nst_sockaddr_t *sockaddr = r->upstream ?
        &r->upstream->connection_backup.peer_sockaddr : NULL;

    return nst_http_var_ip_write(sockaddr, buf, buf_size, var);
}

static u_char *
nst_http_var_upstream_remote_port_write(nst_http_request_t *r,
                                        u_char *buf,
                                        size_t buf_size,
                                        const nst_http_var_t *var)
{
    nst_sockaddr_t *sockaddr = r->upstream ?
        &r->upstream->connection_backup.peer_sockaddr : NULL;

    return nst_http_var_port_write(sockaddr, buf, buf_size, var);
}

static u_char *
nst_http_var_upstream_local_ip_write(nst_http_request_t *r,
                                       u_char *buf,
                                       size_t buf_size,
                                       const nst_http_var_t *var)
{
    nst_sockaddr_t *sockaddr = r->upstream ?
        &r->upstream->connection_backup.local_sockaddr : NULL;

    return nst_http_var_ip_write(sockaddr, buf, buf_size, var);
}

static u_char *
nst_http_var_upstream_local_port_write(nst_http_request_t *r,
                                         u_char *buf,
                                         size_t buf_size,
                                         const nst_http_var_t *var)
{
    nst_sockaddr_t *sockaddr = r->upstream ?
        &r->upstream->connection_backup.local_sockaddr : NULL;

    return nst_http_var_port_write(sockaddr, buf, buf_size, var);

}

static u_char *
nst_http_var_upstream_bytes_sent_write(nst_http_request_t *r,
                                         u_char *buf,
                                         size_t buf_size,
                                         const nst_http_var_t *var)
{
    size_t nsent = r->upstream ? r->upstream->connection_backup.nsent : 0;
    return nst_snprintf(buf, buf_size, "%uz", nsent);
}

static u_char *
nst_http_var_upstream_bytes_received_write(nst_http_request_t *r,
                                           u_char *buf,
                                           size_t buf_size,
                                           const nst_http_var_t *var)
{
    size_t nread = r->upstream ? r->upstream->connection_backup.nread : 0;
    return nst_snprintf(buf, buf_size, "%uz", nread);
}

static u_char *
nst_http_var_upstream_stats_write(nst_http_request_t *r,
                                  u_char *buf,
                                  size_t buf_size,
                                  const nst_http_var_t *var)
{
    nst_msec_t req_start_ms;
    nst_uint_t nstats;
    nst_http_upstream_stats_t *stats;
    size_t i;
    u_char *p;
    u_char *last;
    nst_http_upstream_t *u = r->upstream;

    if(!u || !u->stats_array || !(nstats = u->stats_array->nelts))
        return nst_snprintf(buf, buf_size, "-");

    req_start_ms = r->downstream_stats.start_ms;

    p = buf;
    last = buf + buf_size;
    stats = u->stats_array->elts;
    for(i = 0; i < nstats && p < last; i++) {
        nst_msec_t connect_result_lapsed;
        nst_msec_t last_byte_sent_lapsed;
        nst_msec_t first_byte_received_lapsed;
        nst_msec_t last_byte_received_lapsed;

        connect_result_lapsed = stats[i].connect_result_ms ? 
            stats[i].connect_result_ms - req_start_ms : 0;
        if(i == nstats - 1) {
            last_byte_sent_lapsed = stats[i].last_byte_sent_ms ?
                (stats[i].last_byte_sent_ms - req_start_ms) : 0;
            first_byte_received_lapsed = stats[i].first_byte_received_ms ?
                (stats[i].first_byte_received_ms - req_start_ms) : 0;
            last_byte_received_lapsed = stats[i].last_byte_received_ms ?
                (stats[i].last_byte_received_ms - req_start_ms) : 0;

            p = nst_snprintf(p, last - p,
                             "(%s +%T.%03M +%T.%03M +%T.%03M +%T.%03M)",
                             stats[i].node && stats[i].node->name && strlen(stats[i].node->name) ?
                             stats[i].node->name : "-",
                             connect_result_lapsed / 1000,
                             connect_result_lapsed % 1000,
                             last_byte_sent_lapsed / 1000,
                             last_byte_sent_lapsed % 1000,
                             first_byte_received_lapsed / 1000,
                             first_byte_received_lapsed % 1000,
                             last_byte_received_lapsed / 1000,
                             last_byte_received_lapsed % 1000);
        } else {
            p = nst_snprintf(p, last - p,
                             "(%s +%T.%03M)",
                             stats[i].node && stats[i].node->name && strlen(stats[i].node->name) ?
                             stats[i].node->name : "-",
                             connect_result_lapsed / 1000,
                             connect_result_lapsed % 1000);
        }
    }

    return p;
}

static u_char *
nst_http_var_upstream_tcp_info(nst_http_request_t *r,
                               u_char *buf,
                               size_t buf_size,
                               const nst_http_var_t *var)
{
    struct tcp_info  *info = NULL;
    
    if(r->upstream) {
        nst_assert(r->domain_cfg);
        nst_assert(r->domain_cfg->var_flags.upstream_tcp_info == 1);
        info = r->upstream->connection_backup.tcp_info;
    }
    return nst_http_var_do_tcp_info(info, buf, buf_size, var);
}

static void
nst_http_var_upstream_tcp_info_domain_cfg(nst_cfg_domain_t *domain)
{
    domain->var_flags.upstream_tcp_info = 1;
}

static nst_http_var_t nst_http_upstream_vars[] = {
    /* remote IP */
    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "remote_ip"),
      NST_MAX_IP_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_upstream_remote_ip_write,
      NULL,
      0 },

    /* remote port */
    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "remote_port"),
      NST_MAX_PORT_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_upstream_remote_port_write,
      NULL,
      0 },

    /* local IP */
    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "local_ip"),
      NST_MAX_IP_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_upstream_local_ip_write,
      NULL,
      0 },

    /* local Port */
    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "local_port"),
      NST_MAX_PORT_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_upstream_local_port_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "bytes_sent"),
      NST_OFF_T_LEN,
      NULL,
      nst_http_var_upstream_bytes_sent_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "bytes_received"),
      NST_OFF_T_LEN,
      NULL,
      nst_http_var_upstream_bytes_received_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "stats"),
      static_strlen("( +.999 +.999 +.999 +.999)")
      + NST_MAX_CFG_NAME_ELT_BUF_SIZE + (NST_TIME_T_LEN * 4),
      NULL,
      nst_http_var_upstream_stats_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_UPSTREAM_PREFIX "tcp_info"),
      0,
      NULL,
      nst_http_var_upstream_tcp_info,
      nst_http_var_upstream_tcp_info_domain_cfg,
      0 },

};

nst_status_e
nst_http_upstream_add_vars(void)
{
    return nst_http_var_add(nst_http_upstream_vars,
                            sizeof(nst_http_upstream_vars)
                            / sizeof(nst_http_upstream_vars[0]));
}
