#include "nst_cfg_ip_block.h"

#include "nst_cfg_common.h"
#include "nst_cfg_tag_action.h"

#include <nst_log.h>
#include <nst_sockaddr.h>
#include <nst_limits.h>
#include <nst_errno.h>
#include <nst_assert.h>

#include <string.h>

typedef struct ip_block_frame_data_s ip_block_frame_data_t;
struct ip_block_frame_data_s
{
    nst_sockaddr_t *sockaddr;
    size_t nskipped_ip_block;
    const XML_Char *capturing_tag;
};

static ip_block_frame_data_t _ip_block_frame_data;
static ip_block_frame_data_t *_ip_block_frame_data_ptr = &_ip_block_frame_data;

static void ip_block_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void ip_block_end_handler(void *udata, const XML_Char *name);

static ip_block_frame_data_t *ip_block_frame_data_new(void);
static void ip_block_frame_data_free(void *data);

static inline ip_block_frame_data_t *
ip_block_frame_data_new(void)
{
    nst_assert(_ip_block_frame_data_ptr);
    _ip_block_frame_data_ptr = NULL;
    memset(&_ip_block_frame_data, 0, sizeof(ip_block_frame_data_t));
    return &_ip_block_frame_data;
}

static inline void
ip_block_frame_data_free(void *data)
{
    if(!data)
        return;

    nst_assert(data == &_ip_block_frame_data);
    _ip_block_frame_data.sockaddr = NULL;

    _ip_block_frame_data_ptr = &_ip_block_frame_data;
    return;
}

nst_status_e
nst_cfg_tag_action_set_ip_type(void *cfg_obj,
                               const struct nst_cfg_tag_action_s *action,
                               nst_expat_stack_frame_t *current,
                               const char *value,
                               size_t value_len)
{
    nst_sockaddr_t *sockaddr;
    if(strcmp(value, "ipv4")) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: unsupported <ip><type> %s at around line %ud",
                    current->name,
                    value, 
                    XML_GetCurrentLineNumber(current->parser));
        errno = EPROTONOSUPPORT;
        return NST_ERROR;
    }
    
    sockaddr = (nst_sockaddr_t *)cfg_obj;
    sockaddr->addr.inet.sin_family = AF_INET;
    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_ip(void *cfg_obj,
                          const struct nst_cfg_tag_action_s *action,
                          nst_expat_stack_frame_t *current,
                          const char *value,
                          size_t value_len)
{
    nst_sockaddr_t *sockaddr;
    
    sockaddr = (nst_sockaddr_t *)cfg_obj;

    if(nst_sockaddr_init(sockaddr, value, 0, sockaddr->addr.inet.sin_family)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: invalid IP address %s at around line %ud",
                    current->name,
                    value,
                    XML_GetCurrentLineNumber(current->parser));

        errno = EINVAL;
        return NST_ERROR;
    }
    return NST_OK;
}

static nst_cfg_tag_action_t ip_block_tag_actions[] = {
    { IP_TYPE_TAG,
      nst_cfg_tag_action_set_ip_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },

    { IP_TAG,
      nst_cfg_tag_action_set_ip,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },
};

nst_status_e
nst_cfg_ip_block_capture(void *udata,
                         const XML_Char *name,
                         const XML_Char **attrs,
                         void **nst_sockaddr, void **unused1,
                         void **unused2, void **unused3)
{
    nst_expat_stack_frame_t *current;
    ip_block_frame_data_t *ip_block_frame_data = NULL;
    int ret = NST_OK;

    ip_block_frame_data = ip_block_frame_data_new();
    if(!ip_block_frame_data)
        return NST_ERROR;

    ip_block_frame_data->capturing_tag = name;

    ip_block_frame_data->sockaddr = (nst_sockaddr_t *)nst_sockaddr;
    nst_sockaddr_reset(ip_block_frame_data->sockaddr);

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current) {
        ret = NST_ERROR;
        goto DONE;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               ip_block_start_handler,
                               ip_block_end_handler,
                               NULL,
                               ip_block_frame_data,
                               ip_block_frame_data_free);
    ip_block_frame_data = NULL; /* Ownership is taken by the stack */
    
 DONE:
    ip_block_frame_data_free(ip_block_frame_data);
    return ret;

}


static void
ip_block_start_handler(void *udata,
                       const XML_Char *name,
                       const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;
    ip_block_frame_data_t *ip_block_frame_data;
    nst_uint_t line_num;
    nst_status_e ret;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    ip_block_frame_data = (ip_block_frame_data_t *)current->data;
    line_num = XML_GetCurrentLineNumber(current->parser);

    if(!strcmp(name, ip_block_frame_data->capturing_tag)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: nested <%s> is not "
                    "allowed at around line %u",
                    ip_block_frame_data->capturing_tag,
                    ip_block_frame_data->capturing_tag,
                    line_num);
        (ip_block_frame_data->nskipped_ip_block)++;
        current->skip_on_error = TRUE;
        return;
    }

    if(current->skip_on_error)
        return;

    ret = nst_cfg_tag_action_start_handler(
                   ip_block_tag_actions,
                   sizeof(ip_block_tag_actions)/sizeof(ip_block_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   ip_block_frame_data->sockaddr, NULL,
                   NULL, NULL,
                   name, attrs);

    if(ret == NST_ERROR) {
        current->skip_on_error = TRUE;
    }

    return;
}

static void 
ip_block_end_handler(void *udata, const XML_Char *name)
{
    nst_expat_stack_frame_t *parent;
    nst_expat_stack_frame_t *current;
    ip_block_frame_data_t *ip_block_frame_data;
    nst_uint_t line_num;
    nst_status_e ret;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    ip_block_frame_data = (ip_block_frame_data_t *)current->data;
    line_num = XML_GetCurrentLineNumber(current->parser);

    if(!strcmp(name, ip_block_frame_data->capturing_tag)) {
        goto RET_TO_PARENT;
    }

    if(current->child_ret == NST_ERROR) {
        nst_cfg_log_capture_error(ip_block_frame_data->capturing_tag,
                                  name, TRUE, line_num);
        current->skip_on_error = TRUE;
        current->child_ret = NST_OK;
    }

    if(current->skip_on_error)
        return;

    ret = nst_cfg_tag_action_end_handler(
                  ip_block_tag_actions,
                  sizeof(ip_block_tag_actions)/sizeof(ip_block_tag_actions[0]),
                  current,
                  current->tmp_elt_data, current->child_ret,
                  ip_block_frame_data->sockaddr,
                  name);

    if(ret == NST_ERROR && errno != ENOENT) {
            current->skip_on_error = TRUE;
    }

    return;

 RET_TO_PARENT:
    if(ip_block_frame_data->nskipped_ip_block) {
        ip_block_frame_data->nskipped_ip_block--;
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
