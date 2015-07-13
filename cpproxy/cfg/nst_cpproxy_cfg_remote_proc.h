#ifndef _NST_CPPROXY_CFG_REMOTE_PROC_H_
#define _NST_CPPROXY_CFG_REMOTE_PROC_H_

#include <nst_config.h>

#include "nst_cpproxy_cfg_listen.h"
#include "nst_cpproxy_cfg_box.h"

#include <nst_cfg_proc.h>

#include <nst_types.h>

#include <expat.h>

typedef struct nst_cpproxy_cfg_remote_proc_s nst_cpproxy_cfg_remote_proc_t;

struct nst_cpproxy_cfg_remote_proc_s
{
    nst_cpproxy_cfg_box_t box;
    char cmd[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    char sysid[NST_MAX_SYSID_BUF_SIZE];

    struct nst_cpproxy_cfg_listen_s listen;
};

nst_cpproxy_cfg_remote_proc_t *nst_cpproxy_cfg_remote_proc_new(void);

void nst_cpproxy_cfg_remote_proc_free(void *data);

nst_status_e nst_cpproxy_cfg_remote_proc_capture(void *udata,
                                                 const XML_Char *name,
                                                 const XML_Char **attrs,
                                                 void **ppnew_proc, void **unused1,
                                                 void **unused2, void **unused3);
#endif
