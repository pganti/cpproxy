#include "nst_cfg_domain_timeout.h"
#include <errno.h>
/* local includes */
#include "nst_cfg_common.h"
#include "nst_cfg_tag_action.h"

#include <nst_gen_func.h>

#define TUNNEL_READ_TIMEOUT_S_TAG      "tunnel-read-s"
#define UPSTREAM_CONNECT_TIMEOUT_S_TAG "upstream-connect-s"
#define HTTP_RESPONSE_TIMEOUT_S_TAG    "http-response-s"
#define READ_TIMEOUT_S_TAG             "read-s"
#define WRITE_TIMEOUT_S_TAG            "write-s"
#define END_USER_PCONN_TIMEOUT_S_TAG   "end-user-pconn-timeout-s"

typedef struct domain_timeout_frame_data_s domain_timeout_frame_data_t;

struct domain_timeout_frame_data_s
{
    nst_cfg_domain_timeout_t *domain_timeout;
};

static void domain_timeout_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void domain_timeout_end_handler(void *udata,
                                 const XML_Char *name);

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(domain_timeout, nst_cfg_frame_data_empty_extra_free)

nst_status_e
nst_cfg_domain_timeout_capture(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs,
                               void **pdomain_timeout, void **unused1,
                               void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(domain_timeout);

    nst_assert(pdomain_timeout);
    domain_timeout_frame_data->domain_timeout 
        = (nst_cfg_domain_timeout_t *)pdomain_timeout;
    return NST_OK;

    return 0;
}

static nst_cfg_tag_action_t domain_timeout_tag_actions[] = {
    { TUNNEL_READ_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, tunnel_read_ms),
      0,
      0,
      0,
    },

    { UPSTREAM_CONNECT_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, upstream_connect_ms),
      0,
      0,
      0,
    },

    { HTTP_RESPONSE_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, http_response_ms),
      0,
      0,
      0,
    },

    { READ_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, read_ms),
      0,
      0,
      0,
    },

    { WRITE_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, write_ms),
      0,
      0,
      0,
    },

    { END_USER_PCONN_TIMEOUT_S_TAG,
      nst_cfg_tag_action_set_ms_from_sec,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_timeout_t, end_user_pconn_ms),
      0,
      0,
      0,
    },

};

static void
domain_timeout_start_handler(void *udata,
                             const XML_Char *name,
                             const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(domain_timeout, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   domain_timeout_tag_actions,
                   sizeof(domain_timeout_tag_actions)/sizeof(domain_timeout_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data,
                   sizeof(current->tmp_elt_data),
                   domain_timeout_frame_data->domain_timeout, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void domain_timeout_end_handler(void *udata, const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(domain_timeout);

    ret = nst_cfg_tag_action_end_handler(
                   domain_timeout_tag_actions,
                   sizeof(domain_timeout_tag_actions)/sizeof(domain_timeout_tag_actions[0]),
                   current,
                   current->tmp_elt_data, current->child_ret,
                   domain_timeout_frame_data->domain_timeout,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

void
nst_cfg_domain_timeout_init(nst_cfg_domain_timeout_t *domain_timeout)
{
    domain_timeout->tunnel_read_ms
        = NST_TUNNEL_READ_TIMEOUT_MS;

    domain_timeout->upstream_connect_ms
        = NST_UPSTREAM_CONNECT_TIMEOUT_MS;

    domain_timeout->http_response_ms
        = NST_HTTP_RESPONSE_TIMEOUT_MS;

    domain_timeout->read_ms
        = NST_READ_TIMEOUT_MS;
    domain_timeout->write_ms
        = NST_WRITE_TIMEOUT_MS;

    domain_timeout->end_user_pconn_ms
        = NST_END_USER_PCONN_TIMEOUT_MS;


    return;
}
