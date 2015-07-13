#include "nst_cfg_ip.h"

#include "nst_limits.h"
#include "nst_sockaddr.h"
#include "nst_cfg_common.h"
#include "nst_cfg_elt_data.h"

#include <assert.h>
#include <string.h>

static void nst_cfg_ip_start_handler(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **atts);

static void nst_cfg_ip_end_handler(void *udata,
                                   const XML_Char *name);
static inline void ip_frame_data_free(void *data);

typedef struct ip_frame_data_s ip_frame_data_t;

struct ip_frame_data_s
{
    nst_sockaddr_t *nst_sockaddr;
    char ip_str[NST_MAX_IP_STR_BUF_SIZE];
    sa_family_t family;
};

int
nst_cfg_ip_capture(void *udata,
                  const XML_Char *name,
                  const XML_Char **attrs,
                  nst_sockaddr_t *nst_sockaddr)
{
    nst_expat_stack_frame_t *current;
    ip_frame_data_t *ip_frame_data;
    sa_family_t family = AF_INET;
    size_t i;

    assert(nst_sockaddr);
    
    /* get the type attribute */
    for(i = 0; attrs[i]; i +=2) {
        if(!strcmp(attrs[i], "type")) {
            assert(attrs[i+1]);
            if(!strcmp(attrs[i+1], "ipv4")) {
                family = AF_INET;
                break;
            } else {
                assert(0 && "must be IPV4");
                /* TODO: log CRITICAL error */
                return -1;
            }
        }
    }

    ip_frame_data =
        (ip_frame_data_t *)nst_allocator_calloc(&nst_cfg_allocator,
                                                1,
                                                sizeof(ip_frame_data_t));
    if(!ip_frame_data) {
        /* TODO: log CRITICAL error */
        return -1;
    } else {
        ip_frame_data->nst_sockaddr = nst_sockaddr;
        ip_frame_data->family = family;
    }

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current) {
        ip_frame_data_free(ip_frame_data);
        return -1;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cfg_ip_start_handler,
                               nst_cfg_ip_end_handler,
                               NULL,
                               ip_frame_data,
                               ip_frame_data_free);

    if(nst_cfg_elt_data_capture(udata, name, attrs,
                                ip_frame_data->ip_str,
                                sizeof(ip_frame_data->ip_str),
                                TRUE)) {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return -1;
    }

    return 0;
}

void
nst_cfg_ip_start_handler(void *udata,
                         const XML_Char *name,
                         const XML_Char **atts)
{
    assert(0 && "nst_cfg_ip-start_handler() should never be called");
    return;
}

void
nst_cfg_ip_end_handler(void *udata, const XML_Char *name)
{
    nst_expat_stack_frame_t *parent;
    nst_expat_stack_frame_t *current;
    ip_frame_data_t *ip_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    ip_frame_data = (ip_frame_data_t *)current->data;

    if(current->child_ret == -1) {
        current->skip_on_error = 1;
        current->child_ret = 0;
    }

    if(current->skip_on_error)
        goto RET_TO_PARENT;

    if(nst_sockaddr_init(ip_frame_data->nst_sockaddr,
                         ip_frame_data->ip_str,
                         0,
                         AF_INET)) {
        /* TODO: log CRITICAL error */
        current->skip_on_error = 1;
    }

 RET_TO_PARENT:
        
    if(current->skip_on_error)
        parent->child_ret = -1;

    NST_EXPAT_STACK_FRAME_POP(udata);
    parent->end_handler(udata, name);
}

static inline void
ip_frame_data_free(void *data)
{
    nst_allocator_free(&nst_cfg_allocator, data);
}
