#ifndef _NST_CFG_IP_BLOCK_H_
#define _NST_CFG_IP_BLOCK_H_

#include <nst_config.h>
#include <nst_types.h>

#include <expat.h>

#define IP_TYPE_TAG "type"
#define IP_TAG      "ip"

struct nst_cfg_tag_action_s;

nst_status_e nst_cfg_ip_block_capture(void *udata,
                                      const XML_Char *name,
                                      const XML_Char **attrs,
                                      void **nst_sockaddr, void **unused1,
                                      void **unused2, void **unused3);

#if 0
nst_status_e
nst_cfg_tag_action_set_ip_type(void *cfg_obj,
                               const struct nst_cfg_tag_action_s *action,
                               const char *value,
                               size_t value_len,
                               const char *capturing_entity_tag,
                               nst_uint_t line_num);

nst_status_e
nst_cfg_tag_action_set_ip(void *cfg_obj,
                          const struct nst_cfg_tag_action_s *action,
                          const char *value,
                          size_t value_len,
                          const char *capturing_entity_tag,
                          nst_uint_t line_num);
#endif

#endif
