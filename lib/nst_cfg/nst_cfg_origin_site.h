#ifndef _NST_CFG_ORIGIN_SITE_H_
#define _NST_CFG_ORIGIN_SITE_H_

#include <nst_config.h>

#include <expat.h>

#define ORIGIN_SITE_TAG "origin-site"

struct nst_cfg_application_s;

int nst_cfg_origin_site_capture (void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs,
                                 void **papplication, void **my_dc_name,
                                 void **unused2, void **unused3);

#endif /*__NST_CFG_ORIGIN_SITE_H__*/
