/* its own header file */
#include "nst_cfg_domain.h"

/* nst_cfg headers */
#include "nst_cfg_application.h"
#include "nst_cfg_origin_server.h"
#include "nst_cfg_cpt.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_common.h"

/* libnst_cpt headers */
#include <nst_cpt_node.h>

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

#define URL_TAG          "url"
#define PROTO_TAG        "proto"
#define EXPECT_TAG       "expect"
#define INTERVAL_TAG     "interval-s"
#define PORT_TAG         "port"

static void
dmon_start_handler (void *udata, const XML_Char *name, const XML_Char **attrs);
static void dmon_end_handler(void *udata, const XML_Char *name);

static nst_status_e
nst_cfg_set_url (void *cfg_obj, const nst_cfg_tag_action_t *action,
                 nst_expat_stack_frame_t *current,
                 const char *value, size_t vl);

struct dmon_frame_data_s
{
    nst_cfg_domain_monitor_t * dmon;
};
typedef struct dmon_frame_data_s dmon_frame_data_t;

static void
dmon_extra_free(dmon_frame_data_t  *frame_data)
{
    if(!frame_data || !frame_data->dmon)
        return;

    nst_allocator_free(&nst_cfg_allocator,
                           frame_data->dmon->url);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(dmon, dmon_extra_free)

nst_status_e
nst_cfg_domain_monitor_capture(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs,
                               void ** pdmon, void **unused1,
                               void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(dmon);
    
    dmon_frame_data->dmon = (nst_cfg_domain_monitor_t *)pdmon;

    dmon_frame_data->dmon->success_count = NST_CFG_HC_SUCCESS_COUNT;
    dmon_frame_data->dmon->failure_count = NST_CFG_HC_FAILURE_COUNT;

    return NST_OK;
}

static nst_cfg_tag_action_t dmon_tag_actions[] = {
    { PROTO_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_CFG_PROTO_NAME_LEN,
      offsetof(nst_cfg_domain_monitor_t, proto),
      0,
      0,
      0,
    },

    { URL_TAG,
      nst_cfg_set_url,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_monitor_t, url),
      0,
      0,
      0,
    },
    
    { EXPECT_TAG,
      nst_cfg_tag_action_set_uint32,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_monitor_t, success_code),
      0,
      0,
      0,
    },
 
    { PORT_TAG,
      nst_cfg_tag_action_set_uint16,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_monitor_t, port),
      0,
      0,
      0,
    },

    { INTERVAL_TAG,
      nst_cfg_tag_action_set_uint32,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_monitor_t, interval),
      0,
      0,
      0,
    },
};

static nst_status_e
nst_cfg_set_url (void *cfg_obj, const nst_cfg_tag_action_t *action,
                 nst_expat_stack_frame_t *current,
                 const char *value, size_t vl)
{
    int                        len;
    nst_cfg_domain_monitor_t  * dmon;

    dmon = (nst_cfg_domain_monitor_t *)cfg_obj;
    len = strlen (value);
    dmon->url = nst_allocator_malloc (&nst_cfg_allocator, len + 1);
    if (dmon->url) {
        strncpy (dmon->url, value, len);
        dmon->url[len] = '\0';
    }
    else {
        nst_assert (0 && "Failed to allocate memroy");
    }

    return NST_OK;
}


static void
dmon_start_handler (void *udata, const XML_Char *name, const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(dmon, TRUE);


    ret = nst_cfg_tag_action_start_handler(
                   dmon_tag_actions,
                   sizeof(dmon_tag_actions)/sizeof(dmon_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data,
                   sizeof(current->tmp_elt_data),
                   dmon_frame_data->dmon, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
dmon_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(dmon);

    ret = nst_cfg_tag_action_end_handler(
                   dmon_tag_actions,
                   sizeof(dmon_tag_actions)/sizeof(dmon_tag_actions[0]),
                   current,
                   current->tmp_elt_data,
                   current->child_ret,
                   dmon_frame_data->dmon,
                   name);

    return;

 RET_TO_PARENT:

    /* TODO: final check on dmon object */

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        dmon_frame_data->dmon = NULL;
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

void
nst_cfg_domain_monitor_reset(nst_cfg_domain_monitor_t *dmon)
{
    nst_allocator_free(&nst_cfg_allocator, dmon->url);
}
