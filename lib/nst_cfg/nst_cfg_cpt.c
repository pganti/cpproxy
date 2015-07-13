#include "nst_cfg_cpt.h"

#include "nst_cfg_origin_site.h"

#include "nst_cpt_node.h"
#include "nst_cpt_osrv_node.h"
#include "nst_cpt_osite_node.h"
#include "nst_cpt_internal_node.h"
#include "nst_cpt_spc_node.h"

#include "nst_cfg_common.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_ip.h"
#include "nst_cfg_tag_action.h"

#include <nst_limits.h>
#include <nst_sockaddr.h>
#include <nst_vector.h>
#include <nst_log.h>
#include <nst_assert.h>
#include <nst_errno.h>

#include <string.h>
#include <errno.h>
#include <stddef.h>

#define TYPE_TAG              "type" 
#define REF_DATA_CENTER_TAG   "ref-cluster"
#define REF_ORIGIN_SITE_TAG   "ref-origin-site"

typedef struct cpt_node_frame_data_s cpt_node_frame_data_t;
typedef struct origin_site_search_result_s origin_site_search_result_t;

struct cpt_node_frame_data_s
{
    nst_cpt_node_t **root_node;
    const nst_vector_t *origin_sites;
    nst_cpt_node_t *new_node;
    size_t nuncaptured_nodes;
};

struct origin_site_search_result_s {
    const char *search_name;
    nst_cpt_node_t *node;
};

static void cpt_node_frame_data_free(void *data);
static void nst_cfg_cpt_node_start_handler(void *udata,
                                           const XML_Char *name,
                                           const XML_Char **attrs);

static void nst_cfg_cpt_node_end_handler(void *udata,
                                         const XML_Char *name);

static cpt_node_frame_data_t *
cpt_node_frame_data_new(void)
{
    cpt_node_frame_data_t *new_frame_data =
        (cpt_node_frame_data_t *)nst_allocator_calloc(&nst_cfg_allocator,
                         1,
                         sizeof(cpt_node_frame_data_t));

    if(!new_frame_data)
        return NULL;

    new_frame_data->new_node = nst_cpt_node_new();
    if(new_frame_data->new_node) {
        return new_frame_data;
    } else {
        cpt_node_frame_data_free(new_frame_data);
        return NULL;
    }

}

static void
cpt_node_frame_data_free(void *data)
{
    cpt_node_frame_data_t *cpt_node_frame_data;

    if(!data)
        return;

    cpt_node_frame_data = (cpt_node_frame_data_t *)data;

    nst_cpt_node_free(cpt_node_frame_data->new_node);
    nst_allocator_free(&nst_cfg_allocator, data);
}

nst_status_e
nst_cfg_tag_action_set_cpt_node_selection(void *cfg_obj,
                                          const nst_cfg_tag_action_t *action,
                                          nst_expat_stack_frame_t *current,
                                          const char *value,
                                          size_t value_len)
{
    nst_cpt_node_t *node 
        = (nst_cpt_node_t *) (
                              ((char *)(cfg_obj) + action->offset0)
                              );

    node->sel_type = nst_cpt_node_sel_type_from_str(value);
    if(node->sel_type == NST_CPT_NODE_SEL_TYPE_UNKNOWN) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static nst_status_e
nst_cfg_tag_action_set_cpt_type(void *cfg_obj,
                                const nst_cfg_tag_action_t *action,
                                nst_expat_stack_frame_t *current,
                                const char *value,
                                size_t value_len)
{
    nst_cpt_node_t *node = 
        (nst_cpt_node_t *)((char*)cfg_obj + action->offset0);
    nst_cpt_node_type_e type =  nst_cpt_node_type_from_str(value);

    if(type == NST_CPT_NODE_TYPE_UNKNOWN) {
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    } else {
        return nst_cpt_node_set_type(node, type);
    }
}

static int find_origin_site(void *vec_elt, void *data)
{
    nst_cpt_node_t *os_node = *(nst_cpt_node_t **)vec_elt;
    origin_site_search_result_t *ret = (origin_site_search_result_t *)data;

    const char *os_name = nst_cpt_node_get_name(os_node);

    if(!strcmp(os_name, ret->search_name)) {
        ret->node = os_node;
        return 1;
    } else {
        ret->node = NULL;
        return 0;
    }
}

static void
ref_origin_site_end_elt_handler(nst_expat_stack_frame_t *current)
{
    nst_cpt_node_t *new_node;
    cpt_node_frame_data_t *current_frame_data;
    origin_site_search_result_t osite_search_result;

    current_frame_data = (cpt_node_frame_data_t *)current->data;
    new_node = current_frame_data->new_node;

    if(new_node == NULL
       || nst_cpt_node_get_type(new_node) != NST_CPT_NODE_TYPE_OSITE) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<ref-origin-site> can only be used with "
                    "origin-site CPT node");
        current->skip_on_error = 1;
        return;
    }

    osite_search_result.search_name = current->tmp_elt_data;
    osite_search_result.node = NULL;
    nst_vector_for_each_till((nst_vector_t *)current_frame_data->origin_sites,
                             find_origin_site,
                             &osite_search_result);
    if(osite_search_result.node) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "found ref-origin-site %s",
                    osite_search_result.search_name);
        nst_cpt_node_free(current_frame_data->new_node);
        current_frame_data->new_node
            = nst_cpt_node_copy_cstor(osite_search_result.node);
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot found ref-origin-site %s",
                    osite_search_result.search_name);
        current->skip_on_error = 1;
        return;
    }
    return;
}

static nst_status_e
nst_cfg_cpt_node_capture(void *udata,
                         const XML_Char *name,
                         const XML_Char **attrs,
                         const nst_vector_t *origin_sites)
{
    nst_expat_stack_frame_t *current;
    cpt_node_frame_data_t *current_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    current_frame_data = (cpt_node_frame_data_t *)current->data;

    nst_assert(current_frame_data->new_node);

    current_frame_data = cpt_node_frame_data_new();
    if(current_frame_data) {
        current_frame_data->root_node = NULL;
        current_frame_data->origin_sites = origin_sites;
    } else {
        return -1;
    }

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current) {
        cpt_node_frame_data_free(current_frame_data);
        return -1;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cfg_cpt_node_start_handler,
                               nst_cfg_cpt_node_end_handler,
                               NULL,
                               current_frame_data,
                               cpt_node_frame_data_free);
    return 0;
}
                         
nst_status_e
nst_cfg_cpt_capture(void *udata,
                    const XML_Char *name,
                    const XML_Char **attrs,
                    nst_cpt_node_t **root_node,
                    const nst_vector_t *origin_sites)
{
    nst_expat_stack_frame_t *current;
    cpt_node_frame_data_t *current_frame_data;

    current_frame_data = cpt_node_frame_data_new();
    if(current_frame_data) {
        current_frame_data->root_node = root_node;
        current_frame_data->origin_sites = origin_sites;
    } else {
        /* TODO: log CRITICAL error */
        return NST_ERROR;
    }

    if(nst_cpt_node_set_type(current_frame_data->new_node,
                             NST_CPT_NODE_TYPE_INTERNAL)
       == NST_ERROR) {
        cpt_node_frame_data_free(current_frame_data);
        return NST_ERROR;
    }
        

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current) {
        /* TODO: log CRITICAL error */
        cpt_node_frame_data_free(current_frame_data);
        return NST_ERROR;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cfg_cpt_node_start_handler,
                               nst_cfg_cpt_node_end_handler,
                               NULL,
                               current_frame_data,
                               cpt_node_frame_data_free);
    return NST_OK;
}

static nst_cfg_tag_action_t node_tag_actions[] = {
    { CPT_NODE_SELECTION_TAG,
      nst_cfg_tag_action_set_cpt_node_selection,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      0,
      0,
      0,
      0,
    },

    { TYPE_TAG,
      nst_cfg_tag_action_set_cpt_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
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


    { REF_DATA_CENTER_TAG,
      NULL,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      0,
      0,
      0,
      0,
    },


    { REF_ORIGIN_SITE_TAG,
      NULL,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      0,
      0,
      0,
      0,
    },


};
      
static void
nst_cfg_cpt_node_start_handler(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;
    cpt_node_frame_data_t *current_frame_data;
    nst_status_e ret = NST_OK;
    nst_uint_t line_num;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    current_frame_data = (cpt_node_frame_data_t *)current->data;
    line_num = XML_GetCurrentLineNumber(current->parser);

    if(current->child_ret == -1) {
        current->skip_on_error = 1;
        current->child_ret = 0;
    }

    if(!strcmp(name, "node")) {
        nst_cpt_node_t *new_node = current_frame_data->new_node;

        if(current->skip_on_error || current->skip_on_ignore) {
            current->nskipped_capture_tags++;
            /* fall through to call nst_cfg_ignore */
        } else if(nst_cpt_node_get_type(new_node) != NST_CPT_NODE_TYPE_INTERNAL
                  && 
                  nst_cpt_node_set_type(new_node, NST_CPT_NODE_TYPE_INTERNAL)
                  == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "error setting to CPT node type to internal at "
                        "arround line nume %ud",
                        line_num);
        } else if(nst_cfg_cpt_node_capture(udata, name, attrs,
                            current_frame_data->origin_sites) == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "error capturing CPT node at around line %ud. %s(%d)",
                        line_num,
                        strerror(errno), errno);
            current->skip_on_error = 1;
            current->nskipped_capture_tags++;
            /* fall through to call nst_cfg_ignore */
        } else {
            /* successfully called nst_cfg_cpt_node_capture */
            return;
        }
    } else {
        nst_assert(current_frame_data->new_node);
    }

    if(current->skip_on_error || current->skip_on_ignore) {
        nst_cfg_ignore(udata, name, attrs, NULL);
        return;
    }

    ret = nst_cfg_tag_action_start_handler(
                   node_tag_actions,
                   sizeof(node_tag_actions)/sizeof(node_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   current_frame_data->new_node, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
nst_cfg_cpt_node_end_handler(void *udata,
                             const XML_Char *name)
{
    nst_expat_stack_frame_t *parent;
    nst_expat_stack_frame_t *current;
    cpt_node_frame_data_t *current_frame_data;
    int end_nst_cpt_node = 0;
    int end_nst_cpt = 0;
    nst_uint_t line_num;
    nst_status_e ret = NST_OK;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    current_frame_data = (cpt_node_frame_data_t *)current->data;

    line_num = XML_GetCurrentLineNumber(current->parser);
    if(current->child_ret == -1) {
        current->skip_on_error = 1;
        current->child_ret = 0;
    }

    if(!strcmp(name, "node")) {
        end_nst_cpt_node = 1;
        goto RET_TO_PARENT;
    } else if(!strcmp(name, "next-hop-tree")) {
        end_nst_cpt = 1;
        nst_assert(!strcmp(current->name, "next-hop-tree"));
        goto RET_TO_PARENT;
    }

    if(current->skip_on_error || current->skip_on_ignore)
        return;

    ret = nst_cfg_tag_action_end_handler(
                   node_tag_actions,
                   sizeof(node_tag_actions)/sizeof(node_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   current_frame_data->new_node, name);

    if(ret == NST_ERROR) {
        if(errno == EPROTONOSUPPORT) {
            current->skip_on_ignore = TRUE;
        } else if(errno != ENOENT) {
            current->skip_on_error = TRUE;
        }
        return;
    }

    if(!strcmp(name, REF_DATA_CENTER_TAG)) {
        if(nst_cpt_node_get_type(current_frame_data->new_node)
           != NST_CPT_NODE_TYPE_SPC) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "<%s> parsing error: <%s> can only be used in %s "
                        "CPT node at round line %ud",
                        current->name,
                        REF_DATA_CENTER_TAG,
                        nst_cpt_node_type_to_str(NST_CPT_NODE_TYPE_SPC),
                        line_num);
            current->skip_on_error = TRUE;
            return;
        } else if(current->child_ret == 0) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "<%s> parsing error: invalid <%s> \"%s\" "
                        "CPT node at round line %ud",
                        current->name,
                        REF_DATA_CENTER_TAG,
                        current->tmp_elt_data,
                        line_num);
            current->skip_on_error = TRUE;
            return;
        } else {
            nst_cpt_spc_node_set_dc_name(current_frame_data->new_node,
                                         current->tmp_elt_data);
        }
    } else if(!strcmp(name, REF_ORIGIN_SITE_TAG)) {
        ref_origin_site_end_elt_handler(current);
    } else {
        /* TODO: log INFO message */
    }

    return;

 RET_TO_PARENT:
    
    if(!current->skip_on_error && !current->skip_on_ignore) {
        if(current_frame_data->new_node == NULL
           || !nst_cpt_node_is_valid(current_frame_data->new_node)) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "invalid CPT node at around line %ud",
                        line_num);
            current->skip_on_error = 1;
        }
    }

    if(end_nst_cpt_node) {
        /* we are done capturing the <node> */

        if(current->nskipped_capture_tags) {
            /* we have skipping pushing frame data due to error(s) */
            current->nskipped_capture_tags--;
            return;
        }
    
        if(current->skip_on_error) {
            parent->child_ret = -1;
        } else if(current->skip_on_ignore) {
            parent->child_ret = 0;
        } else {
            cpt_node_frame_data_t *parent_frame_data =
                (cpt_node_frame_data_t *)parent->data;
            if(nst_cpt_internal_node_add_child(parent_frame_data->new_node,
                                               current_frame_data->new_node)) {
                parent->child_ret = -1;
            } else  {
                /* ownership has been taken */
                current_frame_data->new_node = NULL;
                parent->child_ret = 0;
            }
        }
        NST_EXPAT_STACK_FRAME_POP(udata);
        /* we don't need to make parent->end_handler() callback */
    } else {
        nst_assert(end_nst_cpt);
        if(current->skip_on_error) {
            *(current_frame_data->root_node) = NULL;
            parent->child_ret = -1;
        } else {
            nst_cpt_node_reg_log(current_frame_data->new_node,
                                 NST_LOG_LEVEL_CRITICAL,
                                 NST_LOG_LEVEL_DEBUG,
                                 0);
            *(current_frame_data->root_node) = current_frame_data->new_node;
            /* ownhership has been taken */
            current_frame_data->new_node = NULL;
            parent->child_ret = 0;
        }
        NST_EXPAT_STACK_FRAME_POP(udata);
        parent->end_handler(udata, name);
    }

    return;
}

nst_status_e
nst_cfg_tag_action_set_cpt_node_name(void *cfg_obj,
                            const struct nst_cfg_tag_action_s *action,
                            nst_expat_stack_frame_t *current,
                            const char *value, size_t vl)
{
    nst_cpt_node_t *node 
        = (nst_cpt_node_t *) (
                              ((char *)(cfg_obj) + action->offset0)
                              );
    if(nst_cpt_node_set_name(node, value, vl))
        return NST_ERROR;
    else
        return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_cpt_node_score(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              nst_expat_stack_frame_t *current,
                              const char *value,
                              size_t value_len)
{
    nst_cpt_node_score_t *score_from_cfg = 
        (nst_cpt_node_score_t *)( 
                     ((char *)(cfg_obj)) + action->offset0
                    );

    nst_cpt_node_score_t tmp_score = atoi(value);

    if(tmp_score < NST_CPT_NODE_SCORE_MIN)
        tmp_score = NST_CPT_NODE_SCORE_MIN;
    else if(tmp_score > NST_CPT_NODE_SCORE_MAX)
        tmp_score = NST_CPT_NODE_SCORE_DOWN_BY_CFG_SCORE;

    *score_from_cfg = tmp_score;

    return NST_OK;
}

