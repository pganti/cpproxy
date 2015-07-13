#include "nst_cfg_vips.h"

/* nst_cfg includes */
#include <nst_cfg_common.h>
#include <nst_cfg_ip.h>
#include <nst_cfg_elt_data.h>

/* core includes */
#include <nst_log.h>
#include <nst_types.h>
#include <nst_limits.h>
#include <nst_assert.h>
#include <nst_errno.h>
#include <nst_log.h>
#include <nst_cfg.h>

/* std includes */
#include <string.h>

#define NST_NVIPS_INIT         (2048)

#define CAPTURING_ENTITY_TAG   "vips"
#define START_TAG              "start"
#define END_TAG                "end"
#define START_INDEX_TAG        "start-index"
#define END_INDEX_TAG          "end-index"

typedef struct vips_frame_data_s vips_frame_data_t;

static void nst_cfg_vips_start_handler(void *udata,
                                       const XML_Char *name,
                                       const XML_Char **attrs);
static void nst_cfg_vips_end_handler(void *udata, const XML_Char *name);

static vips_frame_data_t _vips_frame_data;
static vips_frame_data_t *_vips_frame_data_ptr = &_vips_frame_data;

/* expat stack frame for capturing the <vip> tag */
struct vips_frame_data_s
{
    nst_sockaddr_t tmp_sockaddr;
    char tmp_elt_data[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    nst_sockaddr_t start_sockaddr;
    nst_sockaddr_t end_sockaddr;
    int32_t start_index;
    int32_t end_index;
    nst_cfg_vips_t **ret_vips;
    nst_cfg_vips_t *new_vips;
    nst_uint_t nskipped_vips;
};

static inline vips_frame_data_t *
vips_frame_data_new(void)
{
    nst_assert(_vips_frame_data_ptr == &_vips_frame_data);

    _vips_frame_data_ptr = NULL;
    memset(&_vips_frame_data, 0, sizeof(vips_frame_data_t));
    nst_sockaddr_reset(&_vips_frame_data.start_sockaddr);
    nst_sockaddr_reset(&_vips_frame_data.end_sockaddr); 

    return &_vips_frame_data;
}

static inline void
vips_frame_data_free(void *data)
{
    if(!data)
        return;

    nst_assert(data == &_vips_frame_data);
    nst_cfg_vips_free(_vips_frame_data.new_vips);
    _vips_frame_data.new_vips = NULL;

    _vips_frame_data_ptr = &_vips_frame_data;
    return;
}

static inline nst_cfg_vip_t *
nst_cfg_vip_new(void)
{
    return nst_allocator_malloc(&nst_cfg_allocator,
                                sizeof(nst_cfg_vip_t));
}

void
nst_cfg_vip_free(void *vip_elt)
{
    nst_allocator_free(&nst_cfg_allocator, vip_elt);
}

static nst_cfg_vips_t *
nst_cfg_vips_new(void)
{
    int ret = NST_OK;
    nst_cfg_vips_t *new_cfg_vips = NULL;

    new_cfg_vips = nst_allocator_malloc(&nst_cfg_allocator,
                                        sizeof(nst_cfg_vips_t));
    if(!new_cfg_vips)
        return NULL;

    new_cfg_vips->ip_ghash = nst_genhash_new(NST_GENHASH_MODE_NO_SHRINK,
                                             NST_NVIPS_INIT,
                                             0, 0,
                                             &nst_cfg_allocator,
                                             nst_genhash_sockaddr_ip,
                                             nst_sockaddr_cmp_ip,
                                             NULL, NULL,
                                             NULL, NULL);
    if(!new_cfg_vips->ip_ghash) {
        ret = NST_ERROR;
        goto DONE;
    }

    new_cfg_vips->index_ghash = nst_genhash_new(NST_GENHASH_MODE_NO_SHRINK,
                                                NST_NVIPS_INIT,
                                                0, 0,
                                                &nst_cfg_allocator,
                                                nst_genhash_uint32,
                                                nst_genhash_uint32_cmp,
                                                NULL, nst_cfg_vip_free,
                                                NULL, NULL);
    if(!new_cfg_vips->index_ghash) {
        ret = NST_ERROR;
        goto DONE;
    }

 DONE:
    if(ret == NST_OK) {
        return new_cfg_vips;
    } else {
        nst_cfg_vips_free(new_cfg_vips);
        return NULL;
    }
}

void nst_cfg_vips_free(void *data)
{
    nst_cfg_vips_t *vips = (nst_cfg_vips_t *)data;

    if(!data)
        return;

    nst_genhash_free(vips->ip_ghash);
    nst_genhash_free(vips->index_ghash);

    nst_allocator_free(&nst_cfg_allocator, vips);
}

bool
nst_cfg_vips_is_equal(const nst_cfg_vips_t *vips0,
                      const nst_cfg_vips_t *vips1)
{
    nst_genhash_iter_t iter;
    nst_cfg_vip_t *vip1;
    nst_cfg_vip_t *vip0;

    if(nst_genhash_get_nelts(vips0->index_ghash) 
       != nst_genhash_get_nelts(vips1->index_ghash)) {
        return FALSE;
    }

    nst_genhash_iter_init(vips1->index_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&vip1)) {
        
        if(!(vip0 = nst_genhash_find(vips0->index_ghash, &vip1->index))
           || 
           !nst_sockaddr_is_equal(&vip0->sockaddr, &vip1->sockaddr))
            return FALSE;
    }

    return TRUE;
}

nst_status_e
nst_cfg_vips_capture(void *udata,
                     const XML_Char *name,
                     const XML_Char **attrs,
                     void           **ret_data, void **unused1,
                     void **unused2, void **unused3)
{
    nst_expat_stack_frame_t *current;
    vips_frame_data_t *vips_frame_data;
    nst_status_e ret = NST_OK;
    nst_cfg_vips_t **ret_vips = (nst_cfg_vips_t **)ret_data;

    nst_assert(ret_vips);

    vips_frame_data = vips_frame_data_new();
    if(!vips_frame_data)
        return NST_ERROR;
    vips_frame_data->ret_vips = ret_vips;

    vips_frame_data->new_vips = nst_cfg_vips_new();
    if(!vips_frame_data->new_vips) {
        ret = NST_ERROR;
        goto DONE;
    }

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current){
        ret = NST_ERROR;
        goto DONE;
    }
    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cfg_vips_start_handler,
                               nst_cfg_vips_end_handler,
                               NULL,
                               vips_frame_data,
                               vips_frame_data_free);
    vips_frame_data = NULL;

 DONE:
    vips_frame_data_free(vips_frame_data);
    return ret;
}

static nst_status_e
verify_vips(nst_expat_stack_frame_t *current)
{
    vips_frame_data_t *vips_frame_data = (vips_frame_data_t *)current->data;

    if(nst_sockaddr_get_family(&vips_frame_data->start_sockaddr)
       == AF_UNSPEC) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: missing or invalid <%s> element "
                    "at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    START_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        return NST_ERROR;

    } else if (nst_sockaddr_get_family(&vips_frame_data->end_sockaddr)
               == AF_UNSPEC) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: missing or invalid <%s> element "
                    "at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    END_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        return NST_ERROR;

    } else if(vips_frame_data->start_index <= 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: missing or invalid <%> "
                    "element at around line %ui",
                    CAPTURING_ENTITY_TAG,
                    START_INDEX_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        return NST_ERROR;

    } else if(vips_frame_data->end_index <= 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: missing or invalid <%s> "
                    "element at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    END_INDEX_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        return NST_ERROR;

    } else if(vips_frame_data->start_index > vips_frame_data->end_index) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: <%s>%d</%s> is larger than "
                    "<%s>%d</%s> at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    START_INDEX_TAG,
                    vips_frame_data->start_index,
                    START_INDEX_TAG,
                    END_INDEX_TAG,
                    vips_frame_data->end_index,
                    END_INDEX_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        return NST_ERROR;

    } else {
        return NST_OK;
    }
}
               
static nst_status_e
populate_vips(nst_expat_stack_frame_t *current)
{
    vips_frame_data_t* vips_frame_data = (vips_frame_data_t *)current->data;
    nst_cfg_vips_t *vips = vips_frame_data->new_vips;
    uint32_t vip_index; /* use nst_uint_t so that we can use
                         * void * as the key to the genhash
                         */
    nst_uint_t nvips;
    nst_uint_t i;
    nst_cfg_vip_t *last_added_vip = NULL;
    nst_cfg_vip_t *new_vip = NULL;
    nst_status_e ret = NST_OK;

    vip_index = vips_frame_data->start_index;
    nvips = vips_frame_data->end_index - vips_frame_data->start_index + 1;

    for(i = 0; i < nvips; i++) {

        /* create a new vip_elt */
        new_vip = nst_cfg_vip_new();
        if(!new_vip) {
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "<%s> parsing error: cannot allocate nst_cfg_vip_t "
                        "object at around line %ud. %s(%d)",
                        CAPTURING_ENTITY_TAG,
                        XML_GetCurrentLineNumber(current->parser),
                        nst_strerror(errno), errno);
            ret = NST_ERROR;
            goto DONE;
        }
        new_vip->index = vip_index++;

        /* init the vip_elt->sockaddr */
        if(last_added_vip) {
            if(nst_sockaddr_next(&new_vip->sockaddr, 
                                 &last_added_vip->sockaddr)) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "<%s> parsing error: can't come up with "
                            "the next VIP after %s at around line %ud.",
                            CAPTURING_ENTITY_TAG,
                            nst_sockaddr_get_ip_str(&last_added_vip->sockaddr),
                            XML_GetCurrentLineNumber(current->parser));
                ret = NST_ERROR;
                goto DONE;
            }
        } else {
            memcpy(&new_vip->sockaddr, &vips_frame_data->start_sockaddr,
                   sizeof(new_vip->sockaddr));
        }
        nst_sockaddr_set_port(&new_vip->sockaddr, INADDR_ANY);

        /* add to vips->ip_ghash to ensure no duplicate VIP */
        if(nst_genhash_add(vips->ip_ghash,
                           &new_vip->sockaddr, new_vip)) {
            if(errno == EEXIST) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "<%s> parsing error: duplicate VIP %s detected "
                            "at around line %ud."
                            CAPTURING_ENTITY_TAG,
                            nst_sockaddr_get_ip_str(&new_vip->sockaddr),
                            XML_GetCurrentLineNumber(current->parser));
                ret = NST_ERROR;
                goto DONE;
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "<%s> parsing error: cannot add VIP %s "
                            "at around line %ud. %s(%d)",
                            CAPTURING_ENTITY_TAG,
                            nst_sockaddr_get_ip_str(&new_vip->sockaddr),
                            XML_GetCurrentLineNumber(current->parser),
                            nst_strerror(errno), errno);
                ret = NST_ERROR;
                goto DONE;
            }
        }

        /* add to vips->index_ghash to ensure no duplicate vip_index */
        if(nst_genhash_add(vips->index_ghash,
                         &new_vip->index, new_vip)) {
            if(errno == EEXIST) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "<%s> parsing error: duplicate "
                            "vip-index %ud detected."
                            CAPTURING_ENTITY_TAG,
                            new_vip->index);
                ret = NST_ERROR;
                goto DONE;
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "<%s> parsing error: cannot add "
                            "vip-index %ud at around line %ud. %s(%d)",
                            CAPTURING_ENTITY_TAG,
                            new_vip->index,
                            XML_GetCurrentLineNumber(current->parser),
                            nst_strerror(errno), errno);
                ret = NST_ERROR;
                goto DONE;
            }                
        } /* if(nst_ghash_add(&vip->index_ghash... */        

        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "<%s> captured VIP: %s with index: %ud "
                    "at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    nst_sockaddr_get_ip_str(&new_vip->sockaddr),
                    new_vip->index,
                    XML_GetCurrentLineNumber(current->parser));

        last_added_vip = new_vip;
        new_vip = NULL; /* vips->index_ghash took the ownerhsip */

    } /* for( ; start_iph <= end_iph */

    if(nst_sockaddr_cmp(&last_added_vip->sockaddr, &vips_frame_data->end_sockaddr)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: the last added VIP %s does not "
                    "match the <%s>%s</%s> at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    nst_sockaddr_get_ip_str(&last_added_vip->sockaddr),
                    END_TAG,
                    nst_sockaddr_get_ip_str(&vips_frame_data->end_sockaddr),
                    END_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        ret = NST_ERROR;
    }

 DONE:
    if(ret == NST_ERROR) {
        current->skip_on_error = 1;
        nst_cfg_vip_free(new_vip);
    }

    return ret;
}

static void
nst_cfg_vips_start_handler(void *udata,
                           const XML_Char *name,
                           const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;
    vips_frame_data_t *vips_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    vips_frame_data = (vips_frame_data_t *)current->data;

    if(!strcmp(name, CAPTURING_ENTITY_TAG)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "<%s> parsing error: nested <%s> is not "
                    "allowed at around line %ud",
                    CAPTURING_ENTITY_TAG,
                    CAPTURING_ENTITY_TAG,
                    XML_GetCurrentLineNumber(current->parser));
        vips_frame_data->nskipped_vips++;
        current->skip_on_error = TRUE;
        return;
    }

    if(current->skip_on_error)
        return;

    if(!strcmp(name, START_TAG) || !strcmp(name, END_TAG)) {
        if(nst_cfg_ip_capture(udata, name, attrs,
                              &vips_frame_data->tmp_sockaddr)) {
            nst_cfg_log_capture_error(CAPTURING_ENTITY_TAG,
                                      name, FALSE,
                                      XML_GetCurrentLineNumber(current->parser));
            current->skip_on_error = 1;
        }                                      

    } else if(!strcmp(name, START_INDEX_TAG)
              || !strcmp(name, END_INDEX_TAG)) {
        if(nst_cfg_elt_data_capture(udata, name, attrs,
                                    vips_frame_data->tmp_elt_data,
                                    sizeof(vips_frame_data->tmp_elt_data),
                                    FALSE)) {
            nst_cfg_log_capture_error(CAPTURING_ENTITY_TAG,
                                      name, FALSE,
                                      XML_GetCurrentLineNumber(current->parser));
            current->skip_on_error = 1;

        }

    } else {
        nst_cfg_log_ignore_tag(CAPTURING_ENTITY_TAG,
                               name, FALSE,
                               XML_GetCurrentLineNumber(current->parser),
                               NULL);
    }
}

static void
nst_cfg_vips_end_handler(void *udata, const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;
    vips_frame_data_t *vips_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    vips_frame_data = (vips_frame_data_t *)current->data;

    if(!strcmp(name, CAPTURING_ENTITY_TAG))
        goto RET_TO_PARENT;

    if(current->child_ret == NST_ERROR) {
        nst_cfg_log_capture_error(CAPTURING_ENTITY_TAG,
                                  name, TRUE,
                                  XML_GetCurrentLineNumber(current->parser));
        current->skip_on_error = 1;
        current->child_ret = NST_OK;
    }

    if(current->skip_on_error)
        return;

    if(!strcmp(name, START_TAG)) {
        memcpy(&vips_frame_data->start_sockaddr,
               &vips_frame_data->tmp_sockaddr,
               sizeof(vips_frame_data->tmp_sockaddr));

    } else if(!strcmp(name, END_TAG)) {
        memcpy(&vips_frame_data->end_sockaddr,
               &vips_frame_data->tmp_sockaddr,
               sizeof(vips_frame_data->tmp_sockaddr));

    } else if(!strcmp(name, START_INDEX_TAG)) {
        vips_frame_data->start_index = atoi(vips_frame_data->tmp_elt_data);
    } else if(!strcmp(name, END_INDEX_TAG)) {
        vips_frame_data->end_index = atoi(vips_frame_data->tmp_elt_data);
    }  else {
        nst_cfg_log_ignore_tag(CAPTURING_ENTITY_TAG,
                               name, TRUE,
                               XML_GetCurrentLineNumber(current->parser),
                               NULL);
    }

    return;

 RET_TO_PARENT:
    if(vips_frame_data->nskipped_vips) {
        vips_frame_data->nskipped_vips--;
        return;
    }

    if(!current->skip_on_error) {
        if(verify_vips(current) || populate_vips(current)) {
            current->skip_on_error = TRUE;
        }
    }

    if(!current->skip_on_error) {
        *(vips_frame_data->ret_vips) = vips_frame_data->new_vips;
        vips_frame_data->new_vips = NULL;
        parent->child_ret = NST_OK;
    } else {
        parent->child_ret = NST_ERROR;
    }

    NST_EXPAT_STACK_FRAME_POP(udata);
    parent->end_handler(udata, name);

    return;
}
