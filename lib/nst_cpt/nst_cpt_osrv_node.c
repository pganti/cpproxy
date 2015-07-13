#include "nst_cpt_osrv_node.h"

#include "nst_cpt_common.h"
#include "nst_cpt_node.h"

#include <nst_log.h>
#include <nst_allocator.h>
#include <nst_sockaddr.h>
#include <nst_assert.h>

#include <string.h>
#include <unistd.h>

static int nst_cpt_osrv_node_set_data(nst_cpt_node_t *node);

static void nst_cpt_osrv_node_free_data(nst_cpt_node_t *node);
static nst_status_e
nst_cpt_osrv_node_copy_cstor(nst_cpt_node_t *dst_node,
                              const nst_cpt_node_t *src_node);
static void nst_cpt_osrv_node_reg_log(const nst_cpt_node_t *node,
                                       nst_log_level_t ovr_lvl,
                                       nst_log_level_t msg_lvl,
                                       size_t tree_depth);
static void nst_cpt_osrv_node_eval_reg_log(const nst_cpt_node_t *node,
                                           const nst_cpt_node_t *picked_node,
                                           nst_cpt_node_score_t score,
                                           nst_log_level_t ovr_lvl,
                                           nst_log_level_t msg_lvl,
                                           size_t tree_depth);
static nst_cpt_node_score_t nst_cpt_osrv_node_get_score(const nst_cpt_node_t *node);
static bool nst_cpt_osrv_node_is_valid(const nst_cpt_node_t *node);

nst_cpt_node_ops_t nst_cpt_osrv_node_ops = {
    .set_data = nst_cpt_osrv_node_set_data,
    .free_data = nst_cpt_osrv_node_free_data,
    .copy_cstor = nst_cpt_osrv_node_copy_cstor,
    .reg_log = nst_cpt_osrv_node_reg_log,
    .eval_reg_log = nst_cpt_osrv_node_eval_reg_log,
    .get_score = nst_cpt_osrv_node_get_score,
    .is_valid = nst_cpt_osrv_node_is_valid,
};

static nst_cpt_osrv_node_data_t *
node_data_new(void)
{
    return nst_allocator_calloc(&nst_cpt_allocator,
                                1,
                                sizeof(nst_cpt_osrv_node_data_t));
}

static void
node_data_free(nst_cpt_osrv_node_data_t *node_data)
{
    if(!node_data)
        return;

    nst_allocator_free(&nst_cpt_allocator, node_data->hostname);
    nst_allocator_free(&nst_cpt_allocator, node_data);
}

static nst_cpt_osrv_node_data_t *
node_data_copy(const nst_cpt_osrv_node_data_t *src_node_data)
{
    nst_cpt_osrv_node_data_t *new_node_data;

    new_node_data = nst_allocator_calloc(&nst_cpt_allocator,
                                         1,
                                         sizeof(nst_cpt_osrv_node_data_t));
    if(!new_node_data)
        return NULL;

    if(src_node_data->hostname) {
        size_t hostname_len = strlen(src_node_data->hostname);
        nst_assert(src_node_data->is_hostname);
        new_node_data->is_hostname = TRUE;
        new_node_data->hostname
            = nst_allocator_malloc(&nst_cpt_allocator,
                                   hostname_len + 1);
        if(!new_node_data->hostname) {
            node_data_free(new_node_data);
            return NULL;
        } else {
            memcpy(new_node_data->hostname, src_node_data->hostname,
                   hostname_len + 1);
        }
    } else {
        new_node_data->is_hostname = FALSE;
        memcpy(&new_node_data->sockaddr,
               &src_node_data->sockaddr,
               sizeof(src_node_data->sockaddr));
    }

    memcpy(&new_node_data->flags,
           &src_node_data->flags,
           sizeof(new_node_data->flags));

    return new_node_data;
}
                                
static int
nst_cpt_osrv_node_set_data(nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    node->data = node_data_new();
    ((nst_cpt_osrv_node_data_t *)node->data)->rtt
        = NST_CPT_NODE_SCORE_DOWN_BY_RTT;

    if(!node->data)
        return -1;
    
    return 0;
}

static void
nst_cpt_osrv_node_free_data(nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    node_data_free((nst_cpt_osrv_node_data_t *)node->data);
}

static void
nst_cpt_osrv_node_reg_log(const nst_cpt_node_t *node,
                           nst_log_level_t ovr_lvl,
                           nst_log_level_t msg_lvl,
                           size_t tree_depth)
{
    char score_str[16];
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);

    nst_cpt_node_get_score_str(node, score_str, sizeof(score_str));
    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=%s name=%s score=%s %s=%s%s]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   node->name,
                   score_str,
                   node_data->is_hostname ? "hostname" : "ip",
                   node_data->is_hostname ?
                   node_data->hostname : nst_sockaddr_get_ip_str(&node_data->sockaddr),
                   node_data->flags.am_i_responsible == 1 ?
                   " i-am-responsible" : "");
}

static void
nst_cpt_osrv_node_eval_reg_log(const nst_cpt_node_t *node,
                               const nst_cpt_node_t *picked_node,
                               nst_cpt_node_score_t score,
                               nst_log_level_t ovr_lvl,
                               nst_log_level_t msg_lvl,
                               size_t tree_depth)
{
    char score_str[16];
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;
    const char *indent = nst_cpt_node_get_indent_str(tree_depth);

    nst_cpt_node_score_to_str(score, score_str, sizeof(score_str));
    NST_NOC_LOG_OV(ovr_lvl,msg_lvl,
                   "%s[type=%s name=%s %s=%s score=%s my-id=%p picked-child-id=%p]",
                   indent,
                   nst_cpt_node_type_to_str(node->type),
                   node->name,
                   node_data->is_hostname ? "hostname" : "ip",
                   node_data->is_hostname ?
                   node_data->hostname : nst_sockaddr_get_ip_str(&node_data->sockaddr),
                   score_str,
                   node,
                   picked_node);
}

static nst_cpt_node_score_t
nst_cpt_osrv_node_get_score(const nst_cpt_node_t *node)
{
    return node->score;
}

static bool
nst_cpt_osrv_node_is_valid(const nst_cpt_node_t *node)
{
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;

    if(node_data->is_hostname)
        return node_data->hostname[0] != '\0';
    else
        return (nst_sockaddr_get_family(&node_data->sockaddr) == AF_INET
                || nst_sockaddr_get_family(&node_data->sockaddr) == AF_INET6);
}

nst_status_e
nst_cpt_osrv_node_set_hostname(nst_cpt_node_t *node,
                               const char *hostname,
                               size_t hostname_len)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;

    if(node_data->hostname)
        nst_allocator_free(&nst_cpt_allocator, node_data->hostname);

    node_data->hostname = nst_allocator_malloc(&nst_cpt_allocator,
                                               hostname_len + 1);
    if(!node_data->hostname)
        return NST_ERROR;

    memcpy(node_data->hostname, hostname, hostname_len + 1);
    node_data->is_hostname = TRUE;
    return NST_OK;
    
}

nst_status_e
nst_cpt_osrv_node_set_ip_by_str(nst_cpt_node_t *node,
                                const char *ip_str,
                                sa_family_t family)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;

    
    if(nst_sockaddr_init(&node_data->sockaddr,
                         ip_str,
                         0,
                         family) == NST_ERROR)
        return NST_ERROR;

    if(node_data->hostname) {
        nst_allocator_free(&nst_cpt_allocator, node_data->hostname);
        node_data->hostname = NULL;
    }
    
    node_data->is_hostname = FALSE;

    return NST_OK;
}

bool
nst_cpt_osrv_node_am_i_responsible(const struct nst_cpt_node_s *node)
{
    nst_cpt_osrv_node_data_t *node_data;

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    node_data = (nst_cpt_osrv_node_data_t *)node->data;

    return (node_data->flags.am_i_responsible == 1);
}

void
nst_cpt_osrv_node_set_responsible(nst_cpt_node_t *node)
{
    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);
    nst_cpt_osrv_node_data_t *node_data
        = (nst_cpt_osrv_node_data_t *)node->data;

    node_data->flags.am_i_responsible = 1;
}

bool
nst_cpt_osrv_node_is_equal(nst_cpt_node_t *osrv0, nst_cpt_node_t *osrv1)
{
    nst_cpt_osrv_node_data_t *osrv0_data;
    nst_cpt_osrv_node_data_t *osrv1_data;

    nst_assert(osrv0->type == NST_CPT_NODE_TYPE_OSRV);
    nst_assert(osrv1->type == NST_CPT_NODE_TYPE_OSRV);

    osrv0_data = (nst_cpt_osrv_node_data_t *)osrv0->data;
    osrv1_data = (nst_cpt_osrv_node_data_t *)osrv1->data;

    if((osrv0_data->hostname ? 0 : 1) != (osrv1_data->hostname ? 0 : 1))
        return FALSE;

    if(osrv0_data->hostname)
        return (strcmp(osrv0_data->hostname, osrv1_data->hostname) == 0 ? TRUE : FALSE);

    return nst_sockaddr_is_equal(&osrv0_data->sockaddr, &osrv1_data->sockaddr);
}

static nst_status_e
nst_cpt_osrv_node_copy_cstor(nst_cpt_node_t *dst_node,
                              const nst_cpt_node_t *src_node)
{
    nst_assert(dst_node->type == NST_CPT_NODE_TYPE_OSRV);
    nst_assert(dst_node->data == NULL);
    nst_assert(src_node->type == NST_CPT_NODE_TYPE_OSRV);
    nst_assert(src_node->data);

    dst_node->data = node_data_copy(src_node->data);
    if(dst_node->data)
        return NST_OK;
    else
        return NST_ERROR;
}
