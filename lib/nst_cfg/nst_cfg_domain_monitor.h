#ifndef _NST_CFG_DOMAIN_MONITOR_H_
#define _NST_CFG_DOMAIN_MONITOR_H_

#include <nst_config.h>

#include <nst_types.h>

#define NST_CFG_PROTO_NAME_LEN     (6)
#define NST_CFG_HC_SUCCESS_COUNT   (2)
#define NST_CFG_HC_FAILURE_COUNT   (2)

typedef struct nst_cfg_domain_monitor {
    u32                  success_count;
    u32                  failure_count;
    char                 proto [NST_CFG_PROTO_NAME_LEN+1];
    int                  success_code;
    int                  interval;
    short                port;
    char               * url;
} nst_cfg_domain_monitor_t;

nst_status_e
nst_cfg_domain_monitor_capture(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs,
                               void **ret_data, void **unused1,
                               void **unused2, void **unused3);

void nst_cfg_domain_monitor_reset(nst_cfg_domain_monitor_t *dmon);

#endif
