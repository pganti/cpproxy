#ifndef _NST_CFG_DOMAIN_H_
#define _NST_CFG_DOMAIN_H_

/* always include nst_config.h in .h file */
#include <nst_config.h>

/* local includes */
#include "nst_cfg_domain_timeout.h"
#include "nst_cfg_domain_monitor.h"

/* libcore includes */
#include <nst_vector.h>
#include <nst_string.h>
#include <nst_time.h>
#include <nst_limits.h>
#include <nst_timer.h>
#include <nst_log.h>

/* 3rd party includes */
#include <expat.h>

struct nst_str_s;
struct nst_genhash_s;
struct nst_vector_s;
struct nst_cpt_node_s;
struct nst_cfg_application_s;

typedef struct nst_cfg_domain_s nst_cfg_domain_t;

struct nst_cfg_domain_s
{
    struct nst_vector_s       *aliases; /*!< a vector of nst_str_t.
                                         *   the first one is the domain
                                         *   name that matches the
                                         *   domain cfg file name
                                         */

    struct nst_vector_s       *services; /*!< a vector of char *.
                                          *   what <service> should this
                                          *   domain services?
                                          *   this vector contains the names
                                          *   of services.
                                          *   the domain score should be
                                          *   down if any of its services
                                          *   is down.
                                          */

    nst_cfg_domain_timeout_t   timeout;

    struct nst_cpt_node_s     *cpt;

    struct nst_cfg_application_s *application; /*!< back reference to application.
                                          *   it is only used for refcount
                                          */
    u32                        score;
    u32                        origin_score;

    nst_cfg_domain_monitor_t   dmon;
    struct nst_vector_s       *dmon_sites;

    nst_str_t                  http_access_log_format;
    struct nst_vector_s       *http_access_log_vars;

    nst_log_level_t            noc_log_lvl;
    nst_log_level_t            dbg_log_lvl;

    struct {
        unsigned upstream_tcp_info:1;
    } var_flags;
};

nst_status_e nst_cfg_domain_capture(void *udata,
                                    const XML_Char *name,
                                    const XML_Char **attrs,
                                    void **papplication, void **unused1,
                                    void **unused2, void **unused3);
const struct nst_str_s *nst_cfg_domain_get_name(const nst_cfg_domain_t *domain);
nst_cfg_domain_t *nst_cfg_domain_get_by_str(const struct nst_str_s *domain_name);
void nst_cfg_domain_free(nst_cfg_domain_t *domain);
void nst_cfg_domain_do_free(nst_cfg_domain_t *domain);
void nst_cfg_domain_do_vec_free(nst_cfg_domain_t **ppdomain);
void nst_cfg_domain_get(nst_cfg_domain_t *domain);
const char * nst_cfg_domain_get_name_as_just_plain_string (const nst_cfg_domain_t *domain);
nst_status_e nst_cfg_domain_add_dmon_site(nst_cfg_domain_t *domain,
                                          struct nst_cpt_node_s *osite);

static inline nst_msec_t
nst_cfg_domain_get_tunnel_read_timeout(const nst_cfg_domain_t *domain)
{
    return domain->timeout.tunnel_read_ms;
}

static inline nst_msec_t
nst_cfg_domain_get_upstream_connect_timeout(const nst_cfg_domain_t *domain)
{
    return domain->timeout.upstream_connect_ms;
}

static inline nst_msec_t
nst_cfg_domain_get_http_response_timeout(const nst_cfg_domain_t *domain)
{
    return domain->timeout.http_response_ms;
}

static inline nst_msec_t
nst_cfg_domain_get_read_timeout(const nst_cfg_domain_t *domain)
{
    return domain ? domain->timeout.read_ms : NST_READ_TIMEOUT_MS;
}

static inline nst_msec_t
nst_cfg_domain_get_write_timeout(const nst_cfg_domain_t *domain)
{
    return domain ? domain->timeout.write_ms : NST_WRITE_TIMEOUT_MS;
}

static inline nst_msec_t
nst_cfg_domain_get_end_user_pconn_timeout(const nst_cfg_domain_t *domain)
{
    return domain->timeout.end_user_pconn_ms;
}

static inline bool
nst_cfg_domain_am_i_spc(const nst_cfg_domain_t *domain)
{
    return (domain->dmon_sites ? TRUE : FALSE);
}

static inline bool
nst_cfg_domain_am_i_responsible(const nst_cfg_domain_t *domain)
{
    return (domain->dmon_sites == NULL ? FALSE : TRUE);
}

#endif
