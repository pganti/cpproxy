#include "nst_cfg_ref.h"

#include "nst_cfg_elt_data.h"
#include "nst_cfg_common.h"

#include <nst_allocator.h>
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_limits.h>
#include <nst_assert.h>

#include <string.h>
#include <stddef.h>

#define LISTEN_TAG          "listen"
#define ALL_PUBLIC_HTTP_TAG "all-public-http"
#define ALL_VIP_HTTP_TAG    "all-vip-http"
#define REF_SERVICE_TAG     "ref-service"

typedef struct ref_frame_data_s ref_frame_data_t;
struct ref_frame_data_s
{
    char tmp_elt_data[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    nst_genhash_t *ref_ghash;
    const char *capture_tag;
};

static ref_frame_data_t _ref_frame_data;
static ref_frame_data_t *_ref_frame_data_ptr = &_ref_frame_data;

static inline ref_frame_data_t *
ref_frame_data_new(void)
{
    nst_assert(_ref_frame_data_ptr);
    _ref_frame_data_ptr = NULL;
    memset(&_ref_frame_data, 0, sizeof(ref_frame_data_t));
    return &_ref_frame_data;
}

static inline void
ref_frame_data_free(void *data)
{
    if(!data)
        return;

    nst_assert(data == &_ref_frame_data);
    _ref_frame_data_ptr = &_ref_frame_data;
    return;
}

static void
nst_cfg_ref_start_handler(void *udata,
                          const XML_Char *name,
                          const XML_Char **attrs);
static void
nst_cfg_ref_end_handler(void *udata,
                        const XML_Char *name);

nst_status_e
nst_cfg_ref_capture(void *udata,
                    const XML_Char *name,
                    const XML_Char **attrs,
                    void **ref_ghash, void **unused1,
                    void **unused2, void **unused3)
{
    nst_expat_stack_frame_t *current;
    ref_frame_data_t *ref_frame_data = NULL;
    int ret = NST_OK;

    nst_assert(ref_ghash);
    ref_frame_data = ref_frame_data_new();

    if(!ref_frame_data)
        return NST_ERROR;
    ref_frame_data->ref_ghash = *(nst_genhash_t **)ref_ghash;
    ref_frame_data->capture_tag = name;

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current){
        ret = NST_ERROR;
        goto DONE;
    }

    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, attrs,
                               nst_cfg_ref_start_handler,
                               nst_cfg_ref_end_handler,
                               NULL,
                               ref_frame_data,
                               ref_frame_data_free);
    
    if(nst_cfg_elt_data_capture(udata, name, attrs,
                                ref_frame_data->tmp_elt_data,
                                sizeof(ref_frame_data->tmp_elt_data),
                                TRUE) == NST_ERROR) {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }

    ref_frame_data = NULL; /* Ownership is taken by the stack */

 DONE:
    ref_frame_data_free(ref_frame_data);
    return ret;
}

static void
nst_cfg_ref_start_handler(void *udata,
                          const XML_Char *name,
                          const XML_Char **attrs)
{
    nst_assert(0 && "nst_cfg_ref_start_handler() should never be called");
}

static void
nst_cfg_ref_end_handler(void *udata,
                        const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;
    ref_frame_data_t *ref_frame_data;
    nst_uint_t line_num;
    char *ref_name;
    size_t ref_name_len;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    ref_frame_data = (ref_frame_data_t *)current->data;

    line_num = XML_GetCurrentLineNumber(current->parser);

    if(strcmp(name, ref_frame_data->capture_tag)
       || current->child_ret == NST_ERROR
       || current->child_ret == 0) {
        nst_cfg_log_capture_error(ref_frame_data->capture_tag,
                                  name, TRUE, line_num);
        current->skip_on_error = TRUE;
        return;
    }

    if(current->skip_on_error)
        return;
    
    ref_name_len = current->child_ret;
    ref_name = nst_allocator_malloc(&nst_cfg_allocator, ref_name_len + 1);
    if(!ref_name)
        goto RET_TO_PARENT;

    memcpy(ref_name, ref_frame_data->tmp_elt_data, ref_name_len + 1);
    if(nst_genhash_add(ref_frame_data->ref_ghash, ref_name, ref_name)
       == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error. cannot add to the ref ghash. %s(%d)",
                    ref_frame_data->capture_tag,
                    nst_strerror(errno), errno);
    }

 RET_TO_PARENT:
    NST_EXPAT_STACK_FRAME_POP(udata);
    parent->end_handler(udata, name);

    return;
}
