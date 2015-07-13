/* its own header file */
#include "nst_cfg_elt_data.h"

/* application header files */
#include "nst_cfg_common.h"

#include <nst_string.h>
#include <nst_assert.h>

/* std library and 3rd parth library header files */
#include <assert.h>
#include <memory.h>
#include <ctype.h>

typedef struct elt_frame_data_s elt_frame_data_t;

struct elt_frame_data_s
{
    char *buf;
    size_t len;
    size_t size;
    int found_first_non_whitespace;
    int is_last_whitespace;
    size_t nuncaptured_start_elts;
    bool always_to_lower;
};

static void
nst_cfg_elt_data_start_handler(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs);

static void 
nst_cfg_elt_data_end_handler(void *udata,
                             const XML_Char *name);
static inline void
elt_frame_data_free(void *data);

static void
nst_cfg_elt_data_char_handler(void *udata,
                              const XML_Char *s,
                              int len);

int
nst_cfg_elt_data_capture(void *udata,
                         const XML_Char *name, const XML_Char **atts,
                         char *buf, size_t buf_size, bool always_to_lower)
{
    nst_expat_stack_frame_t *current;
    elt_frame_data_t *elt_frame_data;

    elt_frame_data = 
        (elt_frame_data_t *)nst_allocator_calloc(&nst_cfg_allocator,
                                                 1,
                                                 sizeof(elt_frame_data_t));
    if(!elt_frame_data) {
        /* TODO: log CRITICAL message */
        return -1;
    } else {
        elt_frame_data->buf = buf;
        elt_frame_data->size = buf_size;
        elt_frame_data->always_to_lower = always_to_lower;
    }

    NST_EXPAT_STACK_FRAME_PUSH(udata, current);
    if(!current) {
        /* TODO: log CRITICAL message */
        elt_frame_data_free(elt_frame_data);
        return -1;
    }
    NST_EXPAT_STACK_FRAME_INIT(current,
                               name, atts,
                               nst_cfg_elt_data_start_handler,
                               nst_cfg_elt_data_end_handler,
                               nst_cfg_elt_data_char_handler,
                               elt_frame_data,
                               elt_frame_data_free);

    return 0;
}

void
nst_cfg_elt_data_start_handler(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;
    elt_frame_data_t *elt_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    elt_frame_data = (elt_frame_data_t *)current->data;

    current->skip_on_error = 1;
    elt_frame_data->nuncaptured_start_elts++;
}

void
nst_cfg_elt_data_end_handler(void *udata,
                             const XML_Char *name)
{
    nst_expat_stack_frame_t *parent;
    nst_expat_stack_frame_t *current;
    elt_frame_data_t *elt_frame_data;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);
    elt_frame_data = (elt_frame_data_t *)current->data;
    assert(parent->end_handler);

    if(current->skip_on_error)
        goto RET_TO_PARENT;

    if(elt_frame_data->is_last_whitespace) {
        assert(elt_frame_data->len > 0);
        elt_frame_data->len -= 1;
    }

    elt_frame_data->buf[elt_frame_data->len] = '\0';

 RET_TO_PARENT:
    if(elt_frame_data->nuncaptured_start_elts) {
        elt_frame_data->nuncaptured_start_elts--;
        return;
    }

    if(current->skip_on_error) {
        /* TODO: log CRITICAL error */
        parent->child_ret = -1;
    } else {
        parent->child_ret = elt_frame_data->len;
    }

    NST_EXPAT_STACK_FRAME_POP(udata);
    parent->end_handler(udata, name);
}

void
nst_cfg_elt_data_char_handler(void *udata,
                              const XML_Char *s,
                              int len)
{
    nst_expat_stack_frame_t *current;
    elt_frame_data_t *elt_frame_data;
    int i;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);
    elt_frame_data = (elt_frame_data_t *)current->data;

    if(current->skip_on_error)
        return;

    /* skipping leading whitespace */
    if(!elt_frame_data->found_first_non_whitespace) {
        for(i = 0; i < len; i++) {
            if(!isspace(s[i])) {
                elt_frame_data->found_first_non_whitespace = 1;
                break;
            }
        }
        if(i < len) {
            s += i;
            len -=i;
        } else {
            return;
        }
    }

    for(i = 0; i < len; i++) {
        if(elt_frame_data->len + 2 >= elt_frame_data->size) {
            /* TODO: log CRITICAL error */
            current->skip_on_error = 1;
            return;
        } else if(isspace(s[i])) {
            /* normalize whitespaces */
            if(elt_frame_data->is_last_whitespace) {
                /* condense consecutive whitespaces to a single ' ' */
                continue;
            } else {
                /* normalize all whitespaces to ' ' */
                elt_frame_data->buf[elt_frame_data->len] = ' ';
                elt_frame_data->is_last_whitespace = 1;
                elt_frame_data->len += 1;
            } 
        } else {
            if(elt_frame_data->always_to_lower) {
                elt_frame_data->buf[elt_frame_data->len] = 
                    (char)nst_tolower(s[i]);
            } else {
                elt_frame_data->buf[elt_frame_data->len] = s[i];
            }
            elt_frame_data->is_last_whitespace = 0;
            elt_frame_data->len += 1;
        }
    }
}

static inline void
elt_frame_data_free(void *data)
{
    nst_allocator_free(&nst_cfg_allocator, data);
}
