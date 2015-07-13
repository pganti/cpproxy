#ifndef _NST_CPPROXY_CFG_H_
#define _NST_CPPROXY_CFG_H_

#include <nst_config.h>

#include <nst_cfg_diff.h>
#include <nst_cfg_common.h>

#include <nst_types.h>
#include <nst_limits.h>
#include <nst_defaults.h>

#define NST_CPPROXY_CFG_CMD_NAME   NST_PROXY_NAME
#define NST_CPPROXY_CFG_AGENT_NAME NST_CPPROXY_CFG_CMD_NAME

struct nst_genhash_s;
struct nst_cpproxy_cfg_locaL_dc_s;
struct nst_cpproxy_cfg_local_proc_s;
struct nst_cpproxy_cfg_box_s;
struct nst_pool_s;
struct nst_connection_s;

typedef struct nst_cpproxy_cfg_s nst_cpproxy_cfg_t;
typedef struct nst_cpproxy_cfg_dir_names_s nst_cpproxy_cfg_dir_names_t;

#if 0
struct nst_cfg_svcs_s
{
    struct nst_genhash_s *vip_port_ghash;
    struct nst_genhash_s *vip_index_port_ghash;
    struct nst_genhash_s *public_ip_port_ghash;
};
#endif

struct nst_cpproxy_cfg_dir_names_s
{
    char cfg[NST_MAX_DIR_NAME_BUF_SIZE];
    char base[NST_MAX_DIR_NAME_BUF_SIZE];
    char services[NST_MAX_DIR_NAME_BUF_SIZE];
    char dcs[NST_MAX_DIR_NAME_BUF_SIZE];
    char applications[NST_MAX_DIR_NAME_BUF_SIZE];

};

struct nst_cpproxy_cfg_s
{
    nst_uint_t version;

    nst_uint_t nerrors;

    nst_cpproxy_cfg_dir_names_t dir_names;

    char my_box_name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    char my_dc_name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];

    nst_uint_t current_version;

    struct nst_cpproxy_cfg_local_dc_s   *my_dc;    /* my cluster */
    struct nst_cpproxy_cfg_local_proc_s *my_proc;
    struct nst_cpproxy_cfg_box_s        *my_box;

    /* -start- service related cfg */
    struct nst_genhash_s *listening_svc_ghash; /* key is (ip:port) */

    /* All svc under the services_dir_name[] but
     * it only contains the nst_cfg_svc_is_http_like() service
     *
     * For services changes type from http-like to non-http-like or vice-versa,
     * we need to reflect it to add/del action accordingly.
     */
    struct nst_genhash_s *svc_ghash;   /* key is svc name */

    /* -end- service related cfg */

    /* -start- remote cluster */
    struct nst_genhash_s *remote_dc_ghash;  /* remote cluster
                                             * keyed by name
                                             */
    struct nst_genhash_s *sproxy_ip_ghash;   /* remote sproxies
                                              * keyed by <frontend-ip>
                                              * note: port is not in the key!
                                              */
    /* -end - remote cluster */

    /* -start- application */
    struct nst_genhash_s *application_ghash; /* key: application name
                                           * value: nst_cfg_application_t *
                                           */
    struct nst_genhash_s *domain_ghash;   /* key: domain name
                                           * value: nst_cfg_domain_t *
                                           */
    /* -end- application */

    struct {
        struct nst_cpproxy_cfg_local_dc_s   *my_new_dc; /* my new but not
                                                         * active cluster
                                                         */
        nst_cpproxy_cfg_dir_names_t dir_names;
        nst_uint_t version;
        bool relisten;
        bool reset_log_cfg;
    } reload;

    nst_cfg_diff_t diff;

    bool test_only_mode;

#if 0
    nst_genhash_t *deleting_svc_fn_ghash;
    nst_genhash_t *changing_svc_fn_ghash;

    nst_genhash_t *adding_dc;
    nst_genhash_t *deleting_dc;
    nst_genhash_t *changing_dc;

    nst_genhash_t *adding_application;
    nst_genhash_t *changing_application;
    nst_genhash_t *deleting_application;
#endif
};

extern nst_cpproxy_cfg_t cpproxy_cfg;
extern struct nst_pool_s *cpproxy_cfg_sticky_pool; /* a nst_pool_t memory pool
                                                    * for cold stat cfg/init 
                                                    *
                                                    * (i.e. it will not be
                                                    *  changed due to config
                                                    *  reload)
                                                    *
                                                    * (e.g. req_header_hash@
                                                    *  nst_http_req_header.c)
                                                    */

nst_status_e nst_cpproxy_cfg_init(const char *cfg_dir_name, 
                                  const char *sys_id,
                                  bool test_mode,
                                  bool latest_cfg);

void nst_cpproxy_cfg_reset(void);

nst_status_e nst_cpproxy_cfg_cold_start_part1(void);

nst_status_e nst_cpproxy_cfg_cold_start_part2(void);

nst_cfg_reload_status_e nst_cpproxy_cfg_reload_part1(void);

nst_cfg_reload_status_e nst_cpproxy_cfg_reload_part2(void);

void nst_cpproxy_cfg_reload_reset(void);

bool nst_cpproxy_cfg_am_i_private_spc(void);

bool nst_cpproxy_cfg_tp_conn_acl(const struct nst_connection_s *c);

#endif
