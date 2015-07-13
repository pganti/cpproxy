#ifndef _NST_CFG_VERSION_H_
#define _NST_CFG_VERSION_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

#define NST_CFG_VERSION_TAG  "version"

nst_status_e nst_cfg_version_capture(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **attrs,
                                     void **pversion, void **unused1,
                                     void **unused2, void **unused3);

#endif
