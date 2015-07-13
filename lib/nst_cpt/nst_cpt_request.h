#ifndef _NST_CPT_REQUEST_H_
#define _NST_CPT_REQUEST_H_

#include <nst_log.h>

#include "nst_cpt_node.h"

#include <unistd.h>

struct nst_cpt_node_s;
struct nst_sockaddr_s;

typedef struct nst_cpt_request_s nst_cpt_request_t;
typedef enum nst_cpt_request_type_e nst_cpt_request_type_e;

typedef bool (*nst_cpt_app_filter_f)(const struct nst_cpt_node_s *node,
                                     const struct nst_cpt_request_s *request);
typedef nst_cpt_node_score_t (*nst_cpt_score_ovr_f)(const struct nst_cpt_node_s *node,
                                                    const struct nst_cpt_request_s *request);

#define NST_CPT_MAX_NUM_TRIES (4)

enum nst_cpt_request_type_e
{
    NST_CPT_REQ_TYPE_UNKNOWN = 0,
    NST_CPT_REQ_TYPE_DNS = 1,
    NST_CPT_REQ_TYPE_HTTP = 2,
    _NST_CPT_REQ_TYPE_NUM = 3,
};

struct nst_cpt_request_s
{
    nst_cpt_request_type_e type;
    const struct nst_sockaddr_s *end_user_ip;
    const struct nst_cpt_node_s *last_tried_nodes[NST_CPT_MAX_NUM_TRIES];
    size_t ntried;
    nst_log_level_t noc_log_lvl;
    nst_log_level_t msg_log_lvl;

    nst_cpt_app_filter_f app_filter;
    nst_cpt_score_ovr_f score_ovr;
};

void nst_cpt_request_init(nst_cpt_request_t *cpt_request,
                          nst_cpt_request_type_e type,
                          const struct nst_sockaddr_s *end_user_ip,
                          nst_log_level_t noc_log_lvl,
                          nst_cpt_app_filter_f app_filter,
                          nst_cpt_score_ovr_f score_ovr);

#endif
