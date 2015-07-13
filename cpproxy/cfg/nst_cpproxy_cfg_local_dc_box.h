#ifndef _NST_CPPROXY_CFG_LOCAL_DC_BOX_H_
#define _NST_CPPROXY_CFG_LOCAL_DC_BOX_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

nst_status_e
nst_cpproxy_cfg_local_dc_box_capture(void *udata,
                                     const XML_Char *name,
                                     const XML_Char **attrs,
                                     void **local_dc_cfg, void **unused1,
                                     void **unused2, void **unused3);

#endif
