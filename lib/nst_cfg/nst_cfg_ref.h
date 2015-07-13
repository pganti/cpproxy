#ifndef _NST_CFG_REF_H_
#define _NST_CFG_REF_H_

#include <nst_config.h>
#include <nst_types.h>

#include <expat.h>

nst_status_e nst_cfg_ref_capture(void *udate,
                                 const XML_Char *name,
                                 const XML_Char **attrs,
                                 void **ref_ghash, void **unused1,
                                 void **unused2, void **unused3);

#endif
