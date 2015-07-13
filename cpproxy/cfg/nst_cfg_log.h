#ifndef _NST_CFG_LOG_H_
#define _NST_CFG_LOG_H_

/* always include nst_config.h first */
#include <nst_config.h>

/* libnst_cfg includes */
#include <nst_cfg_common.h>

/* libcore includes */
#include <nst_log.h>
#include <nst_limits.h>
#include <nst_types.h>

/* 3rd party includes */
#include <expat.h>

#define LOG_TAG "log"

typedef struct nst_cfg_log_s nst_cfg_log_t;
struct nst_cfg_log_s
{
    char target[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    char dirname[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    char srv_ip[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
};

nst_status_e nst_cfg_log_capture(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs,
                                 void **plogcfg, void **unused1,
                                 void **unused2, void **unused3);

nst_cfg_reload_status_e nst_cfg_log_apply_modified(nst_cfg_log_t *log,
                                              const nst_cfg_log_t *new_log);
#endif
