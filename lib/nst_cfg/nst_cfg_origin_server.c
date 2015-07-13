#include "nst_cfg_origin_server.h"

#include "nst_limits.h"
#include "nst_sockaddr.h"

#include "nst_cpt_node.h"
#include "nst_cpt_osrv_node.h"
#include "nst_cpt_osite_node.h"

#include "nst_cfg_common.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_cpt.h"
#include "nst_cfg_ip.h"

#include <nst_assert.h>
#include <string.h>

#define IP_TAG       "ip"
#define HOSTNAME_TAG "hostname"
typedef struct origin_server_frame_data_s origin_server_frame_data_t;

struct origin_server_frame_data_s
{
    nst_cpt_node_t *osite_node;
    nst_cpt_node_t *new_osrv_node;
    char tmp_elt_data[NST_MAX_HOSTNAME_BUF_SIZE];
};

static void origin_server_start_handler (void *udata, const XML_Char *name,
                                         const XML_Char **attrs);
static void origin_server_end_handler(void *udata, const XML_Char *name);

static void
origin_server_extra_free(origin_server_frame_data_t * frame_data)
{
    nst_cpt_node_free(frame_data->new_osrv_node);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(origin_server, origin_server_extra_free);

nst_status_e
nst_cfg_origin_server_capture(void *udata,
                              const XML_Char *name,
                              const XML_Char **attrs,
                              void **posite_node, void **unused1,
                              void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(origin_server);

    nst_assert(posite_node);
    origin_server_frame_data->osite_node = (nst_cpt_node_t *)posite_node;
    origin_server_frame_data->new_osrv_node =
        nst_cpt_node_new();
    if(!origin_server_frame_data->new_osrv_node
       || nst_cpt_node_set_type(origin_server_frame_data->new_osrv_node,
                                NST_CPT_NODE_TYPE_OSRV) == NST_ERROR) {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return -1;
    }

    return 0;
}

static nst_status_e
nst_cfg_tag_action_set_osrv_ip(void *cfg_obj,
                               const struct nst_cfg_tag_action_s *action,
                               nst_expat_stack_frame_t *current,
                               const char *value, size_t vl)
{
    nst_cpt_node_t *node 
        = (nst_cpt_node_t *) (
                              ((char *)(cfg_obj) + action->offset0)
                              );

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);

    return nst_cpt_osrv_node_set_ip_by_str(node, value, AF_INET);
}

static nst_status_e
nst_cfg_tag_action_set_osrv_hostname(void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            nst_expat_stack_frame_t *current,
                            const char *value, size_t vl)
{
    nst_cpt_node_t *node 
        = (nst_cpt_node_t *) (
                              ((char *)(cfg_obj) + action->offset0)
                              );

    nst_assert(node->type == NST_CPT_NODE_TYPE_OSRV);

    return nst_cpt_osrv_node_set_hostname(node, value, vl);
}

static nst_cfg_tag_action_t origin_server_tag_actions[] = {
    { CPT_NODE_NAME_TAG,
      nst_cfg_tag_action_set_cpt_node_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },

    { CPT_NODE_SCORE_TAG,
      nst_cfg_tag_action_set_cpt_node_score,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpt_node_t, score_from_cfg),
      0,
      0,
      0,
    },


    { IP_TAG,
      nst_cfg_tag_action_set_osrv_ip,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },


    { HOSTNAME_TAG,
      nst_cfg_tag_action_set_osrv_hostname,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_HOSTNAME_BUF_SIZE,
      0,
      0,
      0,
      0,
    },
};

static void
origin_server_start_handler(void *udata,
                            const XML_Char *name,
                            const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(origin_server, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   origin_server_tag_actions,
                   sizeof(origin_server_tag_actions)/sizeof(origin_server_tag_actions[0]),
                   current, udata,
                   origin_server_frame_data->tmp_elt_data,
                   sizeof(origin_server_frame_data->tmp_elt_data),
                   origin_server_frame_data->new_osrv_node, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
origin_server_end_handler(void *udata,
                            const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(origin_server);
    ret = nst_cfg_tag_action_end_handler(
                   origin_server_tag_actions,
                   sizeof(origin_server_tag_actions)/sizeof(origin_server_tag_actions[0]),
                   current, 
                   origin_server_frame_data->tmp_elt_data, current->child_ret,
                   origin_server_frame_data->new_osrv_node,
                   name);

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else if(!nst_cpt_node_is_valid(origin_server_frame_data->new_osrv_node)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "origin-server \"%s\" is invalid at around line %ud",
                    nst_cpt_node_get_name(origin_server_frame_data->new_osrv_node),
                    line_num);
        parent->child_ret = NST_ERROR;
    } else {
        if(nst_cpt_osite_node_add_child(origin_server_frame_data->osite_node,
                                        origin_server_frame_data->new_osrv_node)
           == NST_ERROR) {
            parent->child_ret = NST_ERROR;
        } else {
            origin_server_frame_data->new_osrv_node = NULL;
            parent->child_ret = NST_OK;
        }
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
