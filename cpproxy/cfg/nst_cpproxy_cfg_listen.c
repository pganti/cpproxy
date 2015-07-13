#include "nst_cpproxy_cfg_listen.h"

#include <nst_cfg_ref.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_common.h>

#include <nst_allocator.h>
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_limits.h>
#include <nst_assert.h>

#include <string.h>
#include <stddef.h>

typedef struct listen_frame_data_s listen_frame_data_t;
struct listen_frame_data_s
{
    nst_cpproxy_cfg_listen_t *listen;
    size_t nskipped_listen;
};

static listen_frame_data_t _listen_frame_data;
static listen_frame_data_t *_listen_frame_data_ptr = &_listen_frame_data;

static inline listen_frame_data_t *
listen_frame_data_new(void)
{
    nst_assert(_listen_frame_data_ptr);
    _listen_frame_data_ptr = NULL;
    memset(&_listen_frame_data, 0, sizeof(listen_frame_data_t));
    return &_listen_frame_data;
}

static inline void
listen_frame_data_free(void *data)
{
    if(!data)
        return;

    nst_assert(data == &_listen_frame_data);
    _listen_frame_data_ptr = &_listen_frame_data;
    return;
}

static void
nst_cpproxy_cfg_listen_start_handler(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **attrs);
static void
nst_cpproxy_cfg_listen_end_handler(void *udata,
                                   const XML_Char *name);

nst_status_e
nst_cpproxy_cfg_listen_init(nst_cpproxy_cfg_listen_t *listen_cfg)
{
    listen_cfg->ref_name_ghash =
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        8, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_cstr,
                        nst_genhash_cstr_cmp,
                        nst_cfg_cstr_free,
                        NULL,
                        NULL, NULL);

    if(!listen_cfg->ref_name_ghash)
        return NST_ERROR;

    listen_cfg->all_public_http = FALSE;
    listen_cfg->all_vip_http = FALSE;

    return NST_OK;
}

void
nst_cpproxy_cfg_listen_reset(nst_cpproxy_cfg_listen_t *listen_cfg)
{
    nst_genhash_free(listen_cfg->ref_name_ghash);
    listen_cfg->ref_name_ghash = NULL;
}

static bool
nst_cpproxy_cfg_listen_is_equal(const nst_cpproxy_cfg_listen_t *listen0,
                              const nst_cpproxy_cfg_listen_t *listen1)
{
    nst_genhash_iter_t iter;
    const char *name0;
    const char *name1;

    if(listen0->all_vip_http != listen1->all_vip_http)
        return FALSE;

    if(listen0->all_public_http != listen1->all_public_http)
        return FALSE;

    if(nst_genhash_get_nelts(listen0->ref_name_ghash)
       != nst_genhash_get_nelts(listen1->ref_name_ghash)) {
        return FALSE;
    }
        
    nst_genhash_iter_init(listen1->ref_name_ghash, &iter);
    while(nst_genhash_iter_next(&iter, (void *)&name1, NULL)) {
        name0 = nst_genhash_find(listen0->ref_name_ghash, name1);
        if(!name0) {
            return FALSE;
        }
    }

    return TRUE;
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_listen_apply_modified(nst_cpproxy_cfg_listen_t *listen,
                                      nst_cpproxy_cfg_listen_t *new_listen,
                                      bool *relisten)
{
    if(nst_cpproxy_cfg_listen_is_equal(listen, new_listen))
        return NST_CFG_RELOAD_STATUS_NO_CHANGE;

    listen->all_vip_http = new_listen->all_vip_http;
    listen->all_public_http = new_listen->all_public_http;

    nst_genhash_free(listen->ref_name_ghash);
    listen->ref_name_ghash = new_listen->ref_name_ghash;
    new_listen->ref_name_ghash = NULL;
    
    *relisten = TRUE;

    return NST_CFG_RELOAD_STATUS_CHANGED;
}

nst_cfg_tag_action_t listen_tag_actions[] = {
    { ALL_PUBLIC_HTTP_TAG,
      nst_cfg_tag_action_enable_bool,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_listen_t, all_public_http),
      0,
      0,
      0,
    },

    { ALL_VIP_HTTP_TAG,
      nst_cfg_tag_action_enable_bool,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_listen_t, all_vip_http),
      0,
      0,
      0,
    },

    { REF_SERVICE_TAG,
      NULL,
      nst_cfg_ref_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cpproxy_cfg_listen_t, ref_name_ghash),
      0,
      0,
      0,
    },

};

nst_status_e
nst_cpproxy_cfg_listen_capture(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs,
                               void **listen, void **unused1,
                               void **unused2, void **unused3)
{
    nst_expat_stack_frame_t *current;
    listen_frame_data_t *listen_frame_data = NULL;
    int ret = NST_OK;

    nst_assert(listen);
    listen_frame_data = listen_frame_data_new();

    if(!listen_frame_data)
        return NST_ERROR;

    listen_frame_data->listen = (nst_cpproxy_cfg_listen_t *)listen;

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current){
        ret = NST_ERROR;
        goto DONE;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cpproxy_cfg_listen_start_handler,
                               nst_cpproxy_cfg_listen_end_handler,
                               NULL,
                               listen_frame_data,
                               listen_frame_data_free);
    listen_frame_data = NULL; /* Ownership is taken by the stack */
    
 DONE:
    listen_frame_data_free(listen_frame_data);
    return ret;
}

static void
nst_cpproxy_cfg_listen_start_handler(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;
    listen_frame_data_t *listen_frame_data;
    nst_uint_t line_num;
    nst_status_e ret;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    listen_frame_data = (listen_frame_data_t *)current->data;

    line_num = XML_GetCurrentLineNumber(current->parser);
    if(!strcmp(name, LISTEN_TAG)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: nested <%s> is not "
                    "allowed at around line %u",
                    LISTEN_TAG,
                    LISTEN_TAG,
                    line_num);
        listen_frame_data->nskipped_listen++;
        current->skip_on_error = TRUE;
        return;
    }

    if(current->skip_on_error)
        return;

    ret = nst_cfg_tag_action_start_handler(
                   listen_tag_actions,
                   sizeof(listen_tag_actions)/sizeof(listen_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   listen_frame_data->listen, NULL,
                   NULL, NULL,
                   name, attrs);

    if(ret == NST_ERROR && errno != ENOENT) {
            current->skip_on_error = TRUE;
    }

    return;
}

static void
nst_cpproxy_cfg_listen_end_handler(void *udata,
                                   const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;
    listen_frame_data_t *listen_frame_data;
    nst_uint_t line_num;
    nst_status_e ret;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    listen_frame_data = (listen_frame_data_t *)current->data;

    line_num = XML_GetCurrentLineNumber(current->parser);

    if(!strcmp(name, LISTEN_TAG)) {
        goto RET_TO_PARENT;
    }

    if(current->child_ret == NST_ERROR) {
        nst_cfg_log_capture_error(LISTEN_TAG, name, TRUE, line_num);
        current->skip_on_error = 1;    /* just in case we will go any further */
        current->child_ret = NST_OK;   /* consumed the error code */
    }

    if(current->skip_on_error)
        return;
    
    ret = nst_cfg_tag_action_end_handler(
                  listen_tag_actions,
                  sizeof(listen_tag_actions)/sizeof(listen_tag_actions[0]),
                  current,
                  current->tmp_elt_data, current->child_ret,
                  listen_frame_data->listen,
                  name);

    if(ret == NST_ERROR && errno != ENOENT) {
           current->skip_on_error = TRUE;
    }

    return;
        
 RET_TO_PARENT:
    
    if(listen_frame_data->nskipped_listen) {
        listen_frame_data->nskipped_listen--;
        return;
    }

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        parent->child_ret = NST_OK;
    }

    NST_EXPAT_STACK_FRAME_POP(udata);
    parent->end_handler(udata, name);

    return;
}

