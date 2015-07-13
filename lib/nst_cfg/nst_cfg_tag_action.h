#ifndef _NST_CFG_TAG_ACTION_H_
#define _NST_CFG_TAG_ACTION_H_

#include <nst_types.h>

#include <expat.h>

struct nst_expat_stack_frame_s;

typedef struct nst_cfg_tag_action_s nst_cfg_tag_action_t;
typedef enum nst_cfg_tag_action_mode_e nst_cfg_tag_action_mode_e;

enum nst_cfg_tag_action_mode_e {
    NST_CFG_TAG_ACTION_MODE_NONE        = 0,
    NST_CFG_TAG_ACTION_MODE_LOWER_CASE  = 1,
    NST_CFG_TAG_ACTION_MODE_INLINE_TEXT = 1 << 1,
};

struct nst_cfg_tag_action_s {
    const char    *tag;
    nst_status_e (*set)(void *cfg_obj,
                        const nst_cfg_tag_action_t *tag_action,
                        struct nst_expat_stack_frame_s *current,
                        const char *value,
                        size_t value_len);
    nst_status_e (*capture)(void *udata,
                            const XML_Char *name,
                            const XML_Char **attrs,
                            void **data0, void **data1,
                            void **data2, void **data3);
    nst_cfg_tag_action_mode_e mode;
    size_t       text_buf_size;
    nst_uint_t   offset0;
    nst_uint_t   offset1;
    nst_uint_t   offset2;
    nst_uint_t   offset3;
};

nst_status_e
nst_cfg_tag_action_start_handler(nst_cfg_tag_action_t *actions,
                                 size_t nactions,
                                 struct nst_expat_stack_frame_s *current,
                                 void *udata,
                                 char *tmp_elt_data, size_t tmp_elt_data_size,
                                 void *data0, void *data1,
                                 void *data2, void *data3,
                                 const XML_Char *name,
                                 const XML_Char **attrs);

nst_status_e
nst_cfg_tag_action_end_handler(nst_cfg_tag_action_t *actions,
                               size_t nactions,
                               struct nst_expat_stack_frame_s *current,
                               char *tmp_elt_data,
                               size_t value_len,
                               void *cfg_obj,
                               const XML_Char *name);


/* Some common set functions */

nst_status_e
nst_cfg_tag_action_set_mstr_with_alloc(void *cfg_obj,
                                       const nst_cfg_tag_action_t *action,
                                       struct nst_expat_stack_frame_s *current,
                                       const char *value, size_t value_len);

nst_status_e
nst_cfg_tag_action_set_name(void *cfg_obj,
                            const nst_cfg_tag_action_t *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value, size_t value_len);



nst_status_e
nst_cfg_tag_action_enable_bool(void *cfg_obj,
                               const nst_cfg_tag_action_t *action,
                               struct nst_expat_stack_frame_s *current,
                               const char *value,
                               size_t value_len);

nst_status_e
nst_cfg_tag_action_set_uint(void *cfg_obj,
                            const nst_cfg_tag_action_t *action,
                            struct nst_expat_stack_frame_s *current,
                            const char *value,
                            size_t value_len);

nst_status_e
nst_cfg_tag_action_set_uint16(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              struct nst_expat_stack_frame_s *current,
                              const char *value,
                              size_t value_len);

nst_status_e
nst_cfg_tag_action_set_uint32(void *cfg_obj,
                              const nst_cfg_tag_action_t *action,
                              struct nst_expat_stack_frame_s *current,
                              const char *value,
                              size_t value_len);

nst_status_e
nst_cfg_tag_action_set_int(void *cfg_obj,
                           const nst_cfg_tag_action_t *action,
                           struct nst_expat_stack_frame_s *current,
                           const char *value,
                           size_t value_len);

nst_status_e
nst_cfg_tag_action_set_ms_from_sec(void *cfg_obj,
                                   const nst_cfg_tag_action_t *action,
                                   struct nst_expat_stack_frame_s *current,
                                   const char *value,
                                   size_t value_len);


#endif
