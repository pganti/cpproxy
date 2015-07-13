/* its own header file */
#include "nst_cfg_origin_site.h"

/* nst_cfg headers */
#include "nst_cfg_application.h"
#include "nst_cfg_origin_server.h"
#include "nst_cfg_cpt.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_common.h"

/* libnst_cpt headers */
#include <nst_cpt_node.h>
#include <nst_cpt_osite_node.h>

/* libcore headers */
#include <nst_genhash.h>
#include <nst_string.h>
#include <nst_log.h>
#include <nst_vector.h>
#include <nst_limits.h>
#include <nst_errno.h>
#include <nst_types.h>

/* std library and 3rd party library header files */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>

#define OSITE_NAME_TAG                       "name"
#define OSITE_REFERENCE_DATA_CENTER_TAG      "ref-cluster"

struct origin_site_frame_data_s
{
    nst_cpt_node_t            *new_osite_node;
    nst_cfg_application_t        *application;
    const char                *my_dc_name;
};
typedef struct origin_site_frame_data_s origin_site_frame_data_t;


static void origin_site_start_handler(void *udata, const XML_Char *name,
                                      const XML_Char **attrs);
static void origin_site_end_handler(void *udata, const XML_Char *name);
static nst_status_e
nst_cfg_tag_action_set_ref_dc(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              nst_expat_stack_frame_t *current,
                              const char *value, size_t vl);

static void
origin_site_extra_free(origin_site_frame_data_t * frame_data)
{
    nst_cpt_node_free(frame_data->new_osite_node);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(origin_site, origin_site_extra_free)


nst_status_e
nst_cfg_origin_site_capture(void *udata, const XML_Char *name,
                            const XML_Char **attrs,
                            void ** papplication, void **my_dc_name,
                            void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(origin_site);

    nst_assert(papplication);
    nst_assert(my_dc_name);
    origin_site_frame_data->application = (nst_cfg_application_t *)papplication;
    origin_site_frame_data->my_dc_name = (char *)my_dc_name;
    origin_site_frame_data->new_osite_node = nst_cpt_node_new();
    if(!origin_site_frame_data->new_osite_node
       || nst_cpt_node_set_type(origin_site_frame_data->new_osite_node,
                                NST_CPT_NODE_TYPE_OSITE) == NST_ERROR) {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }        

    return NST_OK;
}

static nst_cfg_tag_action_t origin_site_tag_actions[] = {
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

    { OSITE_REFERENCE_DATA_CENTER_TAG,
      nst_cfg_tag_action_set_ref_dc,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },


    { ORIGIN_SERVER_TAG,
      NULL,
      nst_cfg_origin_server_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },
    
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

};


static nst_status_e
nst_cfg_tag_action_set_ref_dc(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              nst_expat_stack_frame_t *current,
                              const char *value, size_t vl)
{
    nst_cpt_node_t *node;
    origin_site_frame_data_t *origin_site_frame_data;

    if(vl + 1 > action->text_buf_size) {
        errno = ENOMEM;
        return NST_ERROR;
    }

    origin_site_frame_data = (origin_site_frame_data_t *)current->data;
    node = (nst_cpt_node_t *)((char *)cfg_obj + action->offset0);
    
    if(nst_cpt_osite_node_add_dc(node, value, vl) == NST_ERROR)
        return NST_ERROR;
    

    if(!strcmp(origin_site_frame_data->my_dc_name, value))
        nst_cpt_osite_node_set_responsible(node);

    return NST_OK;
}

static void
origin_site_start_handler (void *udata,
                           const XML_Char *name,
                          const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(origin_site, TRUE);

    ret = nst_cfg_tag_action_start_handler(origin_site_tag_actions,
            sizeof(origin_site_tag_actions)/sizeof(origin_site_tag_actions[0]),
            current, udata,
            current->tmp_elt_data, sizeof(current->tmp_elt_data),
            origin_site_frame_data->new_osite_node, NULL,
            NULL, NULL,
            name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
origin_site_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(origin_site);

    ret = nst_cfg_tag_action_end_handler(
                   origin_site_tag_actions,
                   sizeof(origin_site_tag_actions)/sizeof(origin_site_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   origin_site_frame_data->new_osite_node,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    /* TODO: final check on origin_site object */

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else if(!nst_cpt_node_is_valid(origin_site_frame_data->new_osite_node)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "origin-site \"%s\" is not valid at around line %ud",
                    nst_cpt_node_get_name(origin_site_frame_data->new_osite_node),
                    line_num);
        parent->child_ret = NST_ERROR;
    } else {
        if(nst_vector_append (origin_site_frame_data->application->origin_sites,
                              &origin_site_frame_data->new_osite_node,
                              1)
           == NST_ERROR) {
            parent->child_ret = NST_ERROR;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "under application \"%s\", captured origin site:",
                        origin_site_frame_data->application->name);
            nst_cpt_node_reg_log(origin_site_frame_data->new_osite_node,
                                 NST_LOG_LEVEL_DEFAULT,
                                 NST_LOG_LEVEL_INFO,
                                 0);

            origin_site_frame_data->new_osite_node = NULL;
            parent->child_ret = NST_OK;
        }
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
