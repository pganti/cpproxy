#include "nst_cfg_tag_action.h"

#include "nst_cfg_elt_data.h"
#include "nst_cfg_common.h"

#include <nst_string.h>
#include <nst_times.h>
#include <nst_log.h>
#include <nst_limits.h>
#include <nst_errno.h>
#include <nst_assert.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

nst_status_e
nst_cfg_tag_action_set_mstr_with_alloc(void *cfg_obj,
                                       const nst_cfg_tag_action_t *action,
                                       nst_expat_stack_frame_t *current,
                                       const char *value, size_t value_len)
{
    nst_str_t * mstr = 
        (nst_str_t *)( 
                      (char *)(cfg_obj) + action->offset0
                       );

    if(value_len > action->text_buf_size - 1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: "
                    "the length of value <%s>%s</%s> is > %ud "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    value,
                    action->tag,
                    action->text_buf_size - 1,
                    XML_GetCurrentLineNumber(current->parser));
        return NST_ERROR;
    }

    mstr->data = nst_allocator_malloc(&nst_cfg_allocator, value_len + 1);
    if(!mstr->data) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot allocate memory for value <%s>%s</%s> "
                    "at around line %ud",
                    action->tag, value, action->tag,
                    XML_GetCurrentLineNumber(current->parser));
        return NST_ERROR;
    }
    nst_memcpy(mstr->data, value, value_len + 1);
    mstr->len = value_len;

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_name(void *cfg_obj,
                            const nst_cfg_tag_action_t *action,
                            nst_expat_stack_frame_t *current,
                            const char *value, size_t value_len)
{
    char *cfg_name;

    nst_assert(action->text_buf_size);

    if(value_len > action->text_buf_size - 1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: "
                    "the length of value <%s>%s</%s> is > %ud "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    value,
                    action->tag,
                    action->text_buf_size - 1,
                    XML_GetCurrentLineNumber(current->parser));
        return NST_ERROR;
    }

    cfg_name = ((char *)(cfg_obj)) + action->offset0;

    strncpy(cfg_name, value, action->text_buf_size);
    cfg_name[action->text_buf_size - 1] ='\0'; /* just in case */

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_enable_bool(void *cfg_obj,
                               const nst_cfg_tag_action_t *action,
                               nst_expat_stack_frame_t *current,
                               const char *value,
                               size_t value_len)
{
    bool *cfg_bool = 
        (bool *)( 
                 (char *)(cfg_obj) + action->offset0
                );

    *cfg_bool = TRUE;

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_uint(void *cfg_obj,
                            const nst_cfg_tag_action_t *action,
                            nst_expat_stack_frame_t *current,
                            const char *value,
                            size_t value_len)
{
    nst_uint_t *cfg_uint = 
        (nst_uint_t *)( 
                       ((char *)(cfg_obj)) + action->offset0
                      );
    nst_int_t tmp_int = atoi(value);

    if(tmp_int < 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: <%s> expect a >= 0 value "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    XML_GetCurrentLineNumber(current->parser));
        errno = EINVAL;
        return NST_ERROR;
    } else {
        *cfg_uint = tmp_int;
    }

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_uint16(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              nst_expat_stack_frame_t *current,
                              const char *value,
                              size_t value_len)
{
    uint16_t *cfg_uint = 
        (uint16_t *)( 
                     ((char *)(cfg_obj)) + action->offset0
                    );
    nst_int_t tmp_int = atoi(value);

    if(tmp_int < 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: <%s> expect a >= 0 value "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    XML_GetCurrentLineNumber(current->parser));
        errno = EINVAL;
        return NST_ERROR;
    } else if (tmp_int > UINT16_MAX) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: <%s> expect a <= %ud value "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    UINT16_MAX,
                    XML_GetCurrentLineNumber(current->parser));
    } else {
        *cfg_uint = (uint16_t)tmp_int;
    }

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_uint32(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              nst_expat_stack_frame_t *current,
                              const char *value,
                              size_t value_len)
{
    uint32_t *cfg_uint = 
        (uint32_t *)( 
                     ((char *)(cfg_obj)) + action->offset0
                    );
    nst_int_t tmp_int = atoi(value);

    *cfg_uint = (uint32_t)tmp_int;

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_int(void *cfg_obj,
                           const nst_cfg_tag_action_t *action,
                           nst_expat_stack_frame_t *current,
                           const char *value,
                           size_t value_len)
{
    int *cfg_int = 
        (int *)( 
                ((char *)(cfg_obj)) + action->offset0
                 );
    *cfg_int = atoi(value);

    return NST_OK;
}

nst_status_e
nst_cfg_tag_action_set_ms_from_sec(void *cfg_obj,
                                   const nst_cfg_tag_action_t *action,
                                   nst_expat_stack_frame_t *current,
                                   const char *value,
                                   size_t value_len)
{
    nst_msec_t *ms = 
        (nst_msec_t *)( 
                       ((char *)(cfg_obj)) + action->offset0
                      );

    *ms = atoi(value);

    *ms = (*ms) * 1000;

    return NST_OK;
}


nst_status_e
nst_cfg_tag_action_start_handler(nst_cfg_tag_action_t *actions,
                                 size_t nactions,
                                 nst_expat_stack_frame_t *current,
                                 void *udata,
                                 char *tmp_elt_data, size_t tmp_elt_data_size,
                                 void *data0, void *data1,
                                 void *data2, void *data3,
                                 const XML_Char *name,
                                 const XML_Char **attrs)
{
    size_t i;
    nst_status_e ret;
    for(i = 0; i < nactions; i++) {
        if(strcmp(actions[i].tag, name)) {
            continue;
        }

        errno = 0;
        if(actions[i].capture == NULL) {
            char * text;
            size_t text_buf_size;
            bool lower = actions[i].mode & NST_CFG_TAG_ACTION_MODE_LOWER_CASE;

            if(actions[i].mode & NST_CFG_TAG_ACTION_MODE_INLINE_TEXT) {
                text = (char *)(data0) + actions[i].offset0;
                text_buf_size = actions[i].text_buf_size;
            } else if(tmp_elt_data) {
                text  = tmp_elt_data;
                text_buf_size = tmp_elt_data_size;
            } else {
                text = current->tmp_elt_data;
                text_buf_size = sizeof(current->tmp_elt_data);
            }
                    
            ret = nst_cfg_elt_data_capture(udata, name, attrs,
                                           text, text_buf_size,
                                           lower);
        } else {
            void **off_data0 = (void **)((char *)(data0) + actions[i].offset0);
            void **off_data1 = (void **)((char *)(data1) + actions[i].offset1);
            void **off_data2 = (void **)((char *)(data2) + actions[i].offset2);
            void **off_data3 = (void **)((char *)(data3) + actions[i].offset3);
            ret = actions[i].capture(udata, name, attrs,
                                     off_data0, off_data1, off_data2, off_data3);
        }

        if(ret != NST_OK) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "<%s> parsing error: when capturing <%s> "
                        "at around line %ud",
                        current->name,
                        XML_GetCurrentLineNumber(current->parser));
            if(errno == 0) {
                errno = EINVAL;
            }
        }
        return ret;
    }

    errno = ENOENT;
    return NST_ERROR;
}

nst_status_e
nst_cfg_tag_action_end_handler(nst_cfg_tag_action_t *actions,
                               size_t nactions,
                               nst_expat_stack_frame_t *current,
                               char *tmp_elt_data,
                               size_t value_len,
                               void *cfg_obj,
                               const XML_Char *name)
{
    size_t i;

    for(i = 0; i < nactions; i++) {
        if(strcmp(actions[i].tag, name)) {
            continue;
        }

        if(actions[i].capture == NULL) {
            char *text;
            if(!actions[i].set)
                return NST_OK;

            if(tmp_elt_data == NULL
               || actions[i].mode & NST_CFG_TAG_ACTION_MODE_INLINE_TEXT) {
                text = (char *)(cfg_obj) + actions[i].offset0;
            } else {
                text = tmp_elt_data;
            }

            if(actions[i].set(cfg_obj,
                              &actions[i],
                              current,
                              tmp_elt_data,
                              value_len) == NST_ERROR) {
                if(errno != EPROTONOSUPPORT) {
                    NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                                "<%s> parsing error: when capturing </%s> "
                                "at around line %ud",
                                current->name,
                                name,
                                XML_GetCurrentLineNumber(current->parser));
                    /* the set function must have set the errno */
                }
                return NST_ERROR;
            } else {
                return NST_OK;
            }
        } else {
            return NST_OK;
        }
    }

    errno = ENOENT;
    return NST_ERROR;
}
