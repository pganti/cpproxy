#ifndef _NST_CFG_COMMON_H_
#define _NST_CFG_COMMON_H_

#include <nst_config.h>
#include <errno.h>
#include "nst_cfg_ignore.h"

#include <nst_log.h>
#include <nst_allocator.h>
#include <nst_types.h>
#include <nst_limits.h>
#include <nst_assert.h>

#include <string.h>

#include <expat.h>

#define NST_CFG_DIFF_FILENAME    "diff.xml"
#define NST_CFG_VERSION_FILENAME "version.xml"
#define NST_CFG_FILENAME_EXT     ".xml"
#define NST_CFG_FILENAME_EXT_LEN 4

extern nst_allocator_t nst_cfg_allocator;

typedef struct nst_expat_stack_frame_s nst_expat_stack_frame_t;
typedef void (*nst_expat_stack_frame_data_free_f)(void *);
typedef enum nst_cfg_reload_status_e nst_cfg_reload_status_e;

inline nst_expat_stack_frame_t * nst_expat_stack_frame_push(void *udata);
inline void nst_expat_stack_frame_pop(void *udata);

enum nst_cfg_reload_status_e
{
    NST_CFG_RELOAD_STATUS_NO_CHANGE      =  0,
    NST_CFG_RELOAD_STATUS_CHANGED        = (1 << 0),
    NST_CFG_RELOAD_STATUS_RESTART_NEEDED = (1 << 1),
    NST_CFG_RELOAD_STATUS_READD          = (1 << 2),
    NST_CFG_RELOAD_STATUS_ERROR_BIT      = (1 << 31),
    NST_CFG_RELOAD_STATUS_HARD_ERROR     = (1 << 31) | (1 << 29),
    NST_CFG_RELOAD_STATUS_SOFT_ERROR     = (1 << 31) | (1 << 30),
};

struct nst_expat_stack_frame_s
{
    XML_Parser parser;
    const XML_Char *name;              /* it is the capturing entity tag */
    const XML_Char **atts;
    XML_StartElementHandler start_handler;
    XML_EndElementHandler end_handler;
    XML_CharacterDataHandler char_handler;
    nst_status_e child_ret;
    bool skip_on_error;
    bool skip_on_ignore;
    nst_uint_t  nskipped_capture_tags; /* nested capturing tag is seen and
                                        * we wanna skip
                                        */
    char tmp_elt_data[NST_MAX_CFG_NAME_ELT_BUF_SIZE];

    void *data;
    nst_expat_stack_frame_data_free_f data_free;
    nst_expat_stack_frame_t *parent;
};

#define NST_EXPAT_STACK_FRAME_INIT(_frame,                              \
                                   _name, _atts,                        \
                                   _start_handler,                      \
                                   _end_handler,                        \
                                   _char_handler,                       \
                                   _data,                               \
                                   _data_free)                          \
    do {                                                                \
        (_frame)->parser = (_frame)->parent->parser;                    \
        (_frame)->name = (_name);                                       \
        (_frame)->atts = (_atts);                                       \
        (_frame)->start_handler = (_start_handler);                     \
        (_frame)->end_handler = (_end_handler);                         \
        (_frame)->char_handler = (_char_handler);                       \
        (_frame)->child_ret = 0;                                        \
        (_frame)->skip_on_error = 0;                                    \
        (_frame)->skip_on_ignore = 0;                                   \
        (_frame)->nskipped_capture_tags = 0;                            \
        (_frame)->data = _data;                                         \
        (_frame)->data_free = _data_free;                               \
    } while (0)

#define NST_EXPAT_STACK_FRAME_GET_CURRENT(_udata, _current)             \
    do {                                                                \
        (_current) = *(nst_expat_stack_frame_t **)(_udata);             \
    } while(0)

#define NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(_udata,            \
                                                     _current,          \
                                                     _parent)           \
    do {                                                                \
        (_current) = *(nst_expat_stack_frame_t **)(_udata);             \
        (_parent) = (_current)->parent;                                 \
    } while(0)

#define NST_EXPAT_STACK_FRAME_PUSH(_udata, _current)                        \
    do {                                                                    \
        (_current) =                                                        \
            (nst_expat_stack_frame_t *)nst_allocator_calloc(&nst_cfg_allocator,\
                                          1,          \
                                          sizeof(nst_expat_stack_frame_t)); \
        if((_current)) {                                                    \
            (_current)->parent = *(nst_expat_stack_frame_t **)(_udata);     \
            *(nst_expat_stack_frame_t **)(_udata) = (_current);             \
        } else {                                                            \
            _current = NULL;                                                \
        }                                                                   \
    } while(0)

#define NST_EXPAT_STACK_FRAME_POP(_udata)                               \
    do {                                                                \
        nst_expat_stack_frame_t *current =                              \
            *(nst_expat_stack_frame_t **)(_udata);                      \
        *(nst_expat_stack_frame_t **)(_udata) = current->parent;        \
        if(current->data_free)                                          \
            current->data_free(current->data);                          \
        nst_allocator_free(&nst_cfg_allocator, current);                \
    } while(0)

void nst_cfg_log_capture_error(const char *capturing_entity_tag,
                               const char *error_tag, bool is_end_tag,
                               nst_uint_t line_num);

void nst_cfg_log_ignore_tag(const char *capturing_entity_tag,
                            const char *error_tag, bool is_end_tag,
                            nst_uint_t line_num, const char *reason);

void nst_cfg_cstr_vec_free(void *elt);

void nst_cfg_cstr_free(void *data);


void nst_cfg_frame_data_empty_extra_free(void *data);

#define NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(sname, extra_free)        \
    static struct sname##_frame_data_s _##sname##_frame_data;           \
    static struct sname##_frame_data_s *_##sname##_frame_data_ptr = &_##sname##_frame_data; \
                                                                        \
    static inline struct sname##_frame_data_s *                         \
    sname##_frame_data_new(void)                                        \
    {                                                                   \
        nst_assert(_##sname##_frame_data_ptr);                          \
        _##sname##_frame_data_ptr = NULL;                               \
        memset(&_##sname##_frame_data, 0, sizeof(struct sname##_frame_data_s)); \
        return &_##sname##_frame_data;                                  \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    sname##_frame_data_free(void *data)                                 \
    {                                                                   \
        if(!data)                                                       \
            return;                                                     \
        nst_assert(data == &_##sname##_frame_data);                     \
        (extra_free)((struct sname##_frame_data_s*)data);               \
        _##sname##_frame_data_ptr = &_##sname##_frame_data;             \
        return;                                                         \
    }

#define NST_CFG_CAPTURE_PROLOGUE(sname)                         \
                                                                \
    nst_expat_stack_frame_t *current;                           \
    struct sname##_frame_data_s *sname##_frame_data = NULL;     \
                                                                \
    do {                                                        \
        sname##_frame_data = sname##_frame_data_new();          \
        if(!sname##_frame_data)                                 \
            return NST_ERROR;                                   \
                                                                \
        NST_EXPAT_STACK_FRAME_PUSH(udata, current);             \
        if(!current) {                                          \
            (sname##_frame_data_free)(sname##_frame_data);      \
            return NST_ERROR;                                   \
        }                                                       \
                                                                \
        NST_EXPAT_STACK_FRAME_INIT(current,                     \
                                   name, attrs,                 \
                                   sname##_start_handler,       \
                                   sname##_end_handler,         \
                                   NULL,                        \
                                   sname##_frame_data,          \
                                   sname##_frame_data_free);    \
    } while(0)

#define NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(sname, nested_as_err)  \
                                                                        \
    nst_status_e ret = NST_OK;                                          \
    nst_expat_stack_frame_t *current;                                   \
    struct sname##_frame_data_s *sname##_frame_data;                    \
    nst_uint_t line_num;                                                \
                                                                        \
    do {                                                                \
        NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);              \
        sname##_frame_data = (struct sname##_frame_data_s *)current->data; \
        line_num = XML_GetCurrentLineNumber(current->parser);           \
                                                                        \
        if(!strcmp(name, current->name)) {                              \
            if((nested_as_err)) {                                       \
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,                        \
                        "<%s> parsing error: nested <%s> is not "       \
                        "allowed at around line %u",                    \
                        current->name,                                  \
                        current->name,                                  \
                        line_num);                                      \
                current->skip_on_error = TRUE;                          \
            }                                                           \
            current->nskipped_capture_tags++;                           \
            return;                                                     \
        }                                                               \
                                                                        \
        if(current->skip_on_ignore || current->skip_on_error)           \
            return;                                                     \
                                                                        \
        current->tmp_elt_data[0] = '\0';                                \
    } while(0)

#define NST_CFG_UN_NESTED_START_HANDLER_FINALE()                        \
                                                                        \
    do {                                                                \
        if(ret == NST_ERROR) {                                          \
            if(errno == ENOENT) {                                       \
                nst_cfg_ignore(udata, name, attrs, NULL);               \
            } else {                                                    \
                current->skip_on_error = TRUE;                          \
            }                                                           \
        }                                                               \
        return;                                                         \
    } while(0)

#define NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(sname)                   \
                                                                        \
    nst_status_e ret = NST_OK;                                          \
    nst_expat_stack_frame_t *parent;                                    \
    nst_expat_stack_frame_t *current;                                   \
    struct sname##_frame_data_s *sname##_frame_data;                    \
    nst_uint_t line_num;                                                \
                                                                        \
    do {                                                                \
        NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent); \
        sname##_frame_data = (sname##_frame_data_t *)current->data;     \
        line_num = XML_GetCurrentLineNumber(current->parser);           \
                                                                        \
        if(!strcmp(name, current->name)) {                              \
            if(current->nskipped_capture_tags) {                        \
                current->nskipped_capture_tags--;                       \
                return;                                                 \
            } else {                                                    \
                goto RET_TO_PARENT;                                     \
            }                                                           \
        }                                                               \
                                                                        \
        if(current->child_ret == NST_ERROR) {                           \
            nst_cfg_log_capture_error(current->name, name, TRUE, line_num); \
            current->skip_on_error = 1; /* just in case we will         \
                                         *  go any further              \
                                         */                             \
            current->child_ret = NST_OK;/* consume the error code */    \
        }                                                               \
                                                                        \
        if(current->skip_on_ignore || current->skip_on_error)           \
            return;                                                     \
                                                                        \
    } while(0)

#define NST_CFG_UN_NESTED_END_HANDLER_FINALE()                          \
    do {                                                                \
        NST_EXPAT_STACK_FRAME_POP(udata);                               \
        parent->end_handler(udata, name);                               \
        return;                                                         \
    } while(0)


#endif
