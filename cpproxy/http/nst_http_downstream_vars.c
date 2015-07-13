#include "nst_http_downstream_vars.h"

#include "nst_http_var.h"
#include "nst_http_request.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>

#define NST_HTTP_VAR_DOWNSTREAM_PREFIX "ds_"
#define NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX \
    NST_HTTP_VAR_DOWNSTREAM_PREFIX "req_"

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

static size_t
nst_http_var_downstream_request_host_getlen(nst_http_request_t *r,
                                            const nst_http_var_t *var)
{
    nst_connection_t *cli_c = r->htran->cli_connection;

    nst_assert(cli_c);

    if (r->parsed_req_hdr.server.len) {
        return r->parsed_req_hdr.server.len;
    } else if(cli_c->svc && cli_c->svc->edomain_name_len) {
        return cli_c->svc->edomain_name_len;
    } else {
        return 1;
    }
}

static u_char *
nst_http_var_downstream_request_host_write(nst_http_request_t *r,
                                           u_char *buf,
                                           size_t buf_size,
                                           const nst_http_var_t *var)
{
    nst_connection_t *cli_c = r->htran->cli_connection;
    const u_char *host;
    size_t len;

    if (r->parsed_req_hdr.server.len) {
        len = r->parsed_req_hdr.server.len;
        host = r->parsed_req_hdr.server.data;
    } else if(cli_c->svc && cli_c->svc->edomain_name_len) {
        len = cli_c->svc->edomain_name_len;
        host = (const u_char *)cli_c->svc->edomain_name;
    } else {
        len = 1;
        host = (u_char *)"-";
    }

    return nst_cpymem(buf, host, min(len, buf_size));
}

static size_t
nst_http_var_downstream_request_method_getlen(nst_http_request_t *r,
                                             const nst_http_var_t *var)
{
    return r->req_ln.method_name.data ? r->req_ln.method_name.len : 1;
}

static u_char *
nst_http_var_downstream_request_method_write(nst_http_request_t *r,
                                             u_char *buf,
                                             size_t buf_size,
                                             const nst_http_var_t *var)
{
    size_t len;
    u_char *method;

    if (r->req_ln.method_name.data) {
        len = r->req_ln.method_name.len;
        method = r->req_ln.method_name.data;
    } else {
        len = 1;
        method = (u_char *)"-";
    }

    return nst_cpymem(buf, method, min(len, buf_size));
}

static u_char *
nst_http_var_downstream_request_x_nst_rid_write(nst_http_request_t *r,
                                                u_char *buf,
                                                size_t buf_size,
                                                const nst_http_var_t *var)
{
    if(r->parsed_req_hdr.rid) {
        return nst_snprintf(buf, buf_size, "%ui", r->parsed_req_hdr.rid);
    } else {
        return nst_cpymem(buf, "-", static_strlen("-"));
    }
}

static u_char *
nst_http_var_downstream_request_x_nst_real_ip_write(nst_http_request_t *r,
                                                    u_char *buf,
                                                    size_t buf_size,
                                                    const nst_http_var_t *var)
{
    if(r->parsed_req_hdr.end_user_ip) {
        return nst_http_var_ip_write(r->parsed_req_hdr.end_user_ip,
                                        buf,
                                        buf_size,
                                        var);
    } else {
        return nst_cpymem(buf, "-", static_strlen("-"));
    }
}

static u_char *
nst_http_var_downstream_remote_ip_write(nst_http_request_t *r,
                                          u_char *buf,
                                          size_t buf_size,
                                          const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_http_var_ip_write(&downstream->peer_sockaddr,
                                 buf, buf_size, var);
}

static u_char *
nst_http_var_downstream_remote_port_write(nst_http_request_t *r,
                                          u_char *buf,
                                          size_t buf_size,
                                          const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_http_var_port_write(&downstream->peer_sockaddr,
                                   buf, buf_size, var);

}

static u_char *
nst_http_var_downstream_local_ip_write(nst_http_request_t *r,
                                       u_char *buf,
                                       size_t buf_size,
                                       const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_http_var_ip_write(&downstream->local_sockaddr,
                                 buf, buf_size, var);
}

static u_char *
nst_http_var_downstream_local_port_write(nst_http_request_t *r,
                                         u_char *buf,
                                         size_t buf_size,
                                         const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_http_var_port_write(&downstream->local_sockaddr,
                                   buf, buf_size, var);

}

static u_char *
nst_http_var_downstream_bytes_sent_write(nst_http_request_t *r,
                                         u_char *buf,
                                         size_t buf_size,
                                         const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_snprintf(buf, buf_size, "%uz", downstream->nsent);
}

static u_char *
nst_http_var_downstream_bytes_received_write(nst_http_request_t *r,
                                             u_char *buf,
                                             size_t buf_size,
                                             const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;

    nst_assert(downstream);

    return nst_snprintf(buf, buf_size, "%uz", downstream->nread);
}

u_char *
nst_http_var_do_tcp_info(const struct tcp_info *info,
                         u_char *buf,
                         size_t buf_size,
                         const nst_http_var_t *var)
{
    if(!info) {
        return nst_snprintf(buf, buf_size, "-");
    }

    return nst_snprintf(buf, buf_size,
                        "state=%ud ca_state=%ud retransmits=%ud probes=%ud "
                        "backoff=%ud options=%ud snd_wscale=%ud rcv_wscale=%ud "

                        "rto=%ud us ato=%ud us snd_mss=%ud rcv_mss=%ud "

                        "unacked=%ud sacked=%ud lost=%ud retrans=%ud "
                        "fackets=%ud "

                        "last_data_sent=%ud ms-ago last_ack_sent=%ud ms-ago"
                        "last_data_recv=%ud ms-ago last_ack_recv=%ud ms-ago"

                        "pmtu=%ud rcv_ssthresh=%ud rtt=%ud rttvar=%ud "
                        "snd_ssthresh=%ud snd_cwnd=%ud advmss=%ud "
                        "reordering=%ud "

                        "rcv_rtt=%ud rcv_space=%ud "

                        "total_retrans=%ud",

                        info->tcpi_state, info->tcpi_ca_state,
                        info->tcpi_retransmits, info->tcpi_probes,
                        info->tcpi_backoff, info->tcpi_options,
                        info->tcpi_snd_wscale, info->tcpi_rcv_wscale,

                        info->tcpi_rto, info->tcpi_ato,
                        info->tcpi_snd_mss, info->tcpi_rcv_mss,

                        info->tcpi_unacked, info->tcpi_sacked,
                        info->tcpi_lost, info->tcpi_retrans, info->tcpi_fackets,

                        info->tcpi_last_data_sent, info->tcpi_last_ack_sent,
                        info->tcpi_last_data_recv, info->tcpi_last_ack_recv,

                        info->tcpi_pmtu, info->tcpi_rcv_ssthresh,
                        info->tcpi_rtt, info->tcpi_rttvar,
                        info->tcpi_snd_ssthresh, info->tcpi_snd_cwnd,
                        info->tcpi_advmss, info->tcpi_reordering,

                        info->tcpi_rcv_rtt, info->tcpi_rcv_space,

                        info->tcpi_total_retrans);
}

static u_char *
nst_http_var_downstream_tcp_info(nst_http_request_t *r,
                                 u_char *buf,
                                 size_t buf_size,
                                 const nst_http_var_t *var)
{
    nst_connection_t *downstream = r->htran->cli_connection;
    struct tcp_info   info;
    struct tcp_info  *pinfo = NULL;
    socklen_t         optlen = sizeof(struct tcp_info);

    nst_assert(downstream);

    if(downstream->fd != -1) {
        if(getsockopt(downstream->fd, IPPROTO_TCP, TCP_INFO,
                      &info, &optlen) == 0) {
            pinfo = &info;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot get TCO_INFO for %s. %s(%d)",
                        nst_connection_get_brief_str(downstream),
                        nst_strerror(errno), errno);
        }
    }


    return nst_http_var_do_tcp_info(pinfo, buf, buf_size, var);
}

static u_char *
nst_http_var_downstream_stats_write(nst_http_request_t *r,
                                    u_char *buf,
                                    size_t buf_size,
                                    const nst_http_var_t *var)
{
    nst_msec_t req_lapsed = nst_current_msec - r->downstream_stats.start_ms;

    return nst_snprintf(buf, buf_size, "(+%M.%03M)",
                        req_lapsed / 1000,
                        req_lapsed % 1000);
}


static nst_http_var_t nst_http_downstream_vars[] = {
    /* Host in request header or svc->edomain_name */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "host"),
      0,
      nst_http_var_downstream_request_host_getlen,
      nst_http_var_downstream_request_host_write,
      NULL,
      0 },

    /* HTTP request method in downstream request header */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "method"),
      0,
      nst_http_var_downstream_request_method_getlen,
      nst_http_var_downstream_request_method_write,
      NULL,
      0 },

    /* HTTP request method in downstream request header */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "x_nst_rid"),
      NST_UINT_LEN,
      NULL,
      nst_http_var_downstream_request_x_nst_rid_write,
      NULL,
      0 },

    /* HTTP request method in downstream request header */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_REQUEST_PREFIX "x_nst_real_ip"),
      NST_MAX_IP_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_downstream_request_x_nst_real_ip_write,
      NULL,
      0 },

    /* remote IP */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "remote_ip"),
      NST_MAX_IP_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_downstream_remote_ip_write,
      NULL,
      0 },

    /* remote port */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "remote_port"),
      NST_MAX_PORT_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_downstream_remote_port_write,
      NULL,
      0,
    },

    /* local IP */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "local_ip"),
      NST_MAX_IP_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_downstream_local_ip_write,
      NULL,
      0 },

    /* local Port */
    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "local_port"),
      NST_MAX_PORT_STR_BUF_SIZE - 1,
      NULL,
      nst_http_var_downstream_local_port_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "bytes_sent"),
      NST_OFF_T_LEN,
      NULL,
      nst_http_var_downstream_bytes_sent_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "bytes_received"),
      NST_OFF_T_LEN,
      NULL,
      nst_http_var_downstream_bytes_received_write,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "tcp_info"),
      0,
      NULL,
      nst_http_var_downstream_tcp_info,
      NULL,
      0 },

    { nst_string(NST_HTTP_VAR_DOWNSTREAM_PREFIX "stats"),
      static_strlen("(+.999)") + NST_TIME_T_LEN,
      NULL,
      nst_http_var_downstream_stats_write,
      NULL,
      0 },
};

nst_status_e
nst_http_downstream_add_vars(void)
{
    return nst_http_var_add(nst_http_downstream_vars,
                            sizeof(nst_http_downstream_vars)
                            / sizeof(nst_http_downstream_vars[0]));
}
