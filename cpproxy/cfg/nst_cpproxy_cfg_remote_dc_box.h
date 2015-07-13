#ifndef _NST_CPPROXY_CFG_REMOTE_DC_BOX_H_
#define _NST_CPPROXY_CFG_REMOTE_DC_BOX_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

nst_status_e
nst_cpproxy_cfg_remote_dc_box_capture(void *udata,
                                      const XML_Char *name,
                                      const XML_Char **attrs,
                                      void **premote_dc, void **unused1,
                                      void **unused2, void **unused3);
#endif
