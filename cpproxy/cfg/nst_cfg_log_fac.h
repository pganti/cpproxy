#ifndef _NST_CFG_LOG_FAC_H_
#define _NST_CFG_LOG_FAC_H_

/* always include nst_config.h first */
#include <nst_config.h>

/* libcore includes */
#include <nst_log.h>
#include <nst_limits.h>
#include <nst_types.h>

/* 3rd party includes */
#include <expat.h>

#define LOG_FAC_TAG        "log-facility"

nst_status_e nst_cfg_log_fac_capture(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **attrs,
                                     void **pmyproc, void **unused1,
                                     void **unused2, void **unused3);


#endif
