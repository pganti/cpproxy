#ifndef _NST_CPT_OSRV_NODE_H_
#define _NST_CPT_OSRV_NODE_H_

#include <nst_config.h>

#include "nst_cpt_node.h"

#include <nst_sockaddr.h>

#include <sys/types.h>

struct nst_vector_s;
struct nst_cpt_node_s;

typedef struct nst_cpt_osrv_node_data_s nst_cpt_osrv_node_data_t;
struct nst_cpt_osrv_node_data_s
{
    bool is_hostname;
    nst_sockaddr_t sockaddr;
    char *hostname;

    int                        hc_success;
    int                        hc_failures;
    u32                        rtt;

    struct {
        unsigned int           health:1;
        unsigned int           am_i_responsible:1;
    } flags;
};

extern struct nst_cpt_node_ops_s nst_cpt_osrv_node_ops;

static inline bool
nst_cpt_osrv_node_is_hostname(const struct nst_cpt_node_s *node)
{
    return ((nst_cpt_osrv_node_data_t *)node->data)->is_hostname;
}

static inline const nst_sockaddr_t *
nst_cpt_osrv_node_get_sockaddr(const struct nst_cpt_node_s *node)
{
    return (&((nst_cpt_osrv_node_data_t *)node->data)->sockaddr);
}

static inline const char *
nst_cpt_osrv_node_get_hostname(const struct nst_cpt_node_s *node)
{
    return ((nst_cpt_osrv_node_data_t *)node->data)->hostname;
}

nst_status_e
nst_cpt_osrv_node_set_hostname(struct nst_cpt_node_s *node,
                               const char *hostname,
                               size_t hostname_len);

nst_status_e nst_cpt_osrv_node_set_ip_by_str(struct nst_cpt_node_s *node,
                                             const char *ip_str,
                                             sa_family_t family);

bool nst_cpt_osrv_node_am_i_responsible(const struct nst_cpt_node_s *node);

void
nst_cpt_osrv_node_set_responsible(struct nst_cpt_node_s *node);

bool nst_cpt_osrv_node_is_equal(struct nst_cpt_node_s *osrv0,
                                struct nst_cpt_node_s *osrv1);

#endif
