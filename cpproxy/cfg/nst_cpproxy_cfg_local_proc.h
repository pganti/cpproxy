#ifndef _NST_CPPROXY_CFG_LOCAL_PROC_H_
#define _NST_CPPROXY_CFG_LOCAL_PROC_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

/* local includes */
#include "nst_cpproxy_cfg_listen.h"
#include "nst_cpproxy_cfg_box.h"
#include "nst_cpproxy_cfg.h"
#include "nst_cfg_log.h"

/* libnst_cfg includes */
#include <nst_cfg_proc.h>

/* libevent includes */
#include <nst_cfg_event.h>

/* libcore includes */
#include <nst_times.h>
#include <nst_types.h>
#include <nst_log.h>

/* sys and 3rd party includes */
#include <expat.h>

typedef struct nst_cpproxy_cfg_local_proc_s nst_cpproxy_cfg_local_proc_t;

struct nst_cpproxy_cfg_local_proc_s
{
    nst_cpproxy_cfg_box_t box;
    char cmd[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    char sysid[NST_MAX_SYSID_BUF_SIZE];

    struct nst_cpproxy_cfg_listen_s listen;

    struct nst_cfg_log_s log;

    nst_log_level_t noc_log_lvl;
    nst_log_level_t dbg_log_lvl;


    nst_msec_t timer_resolution_ms;

    nst_msec_t log_flush_interval_ms;

    nst_cfg_event_t event;
};

nst_cpproxy_cfg_local_proc_t *nst_cpproxy_cfg_local_proc_new(void);

void nst_cpproxy_cfg_local_proc_free(void *data);

nst_status_e nst_cpproxy_cfg_local_proc_capture(void *udata,
                                                const XML_Char *name,
                                                const XML_Char **attrs,
                                                void **ppnew_proc, void **unused1,
                                                void **unused2, void **unused3);

nst_cfg_reload_status_e
nst_cpproxy_cfg_local_proc_apply_modified(nst_cpproxy_cfg_local_proc_t *my_proc,
                                     nst_cpproxy_cfg_local_proc_t *my_new_proc,
                                     bool *relisten,
                                     bool *reset_log_cfg);
#endif
