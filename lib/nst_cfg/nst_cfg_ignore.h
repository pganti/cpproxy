#ifndef _NST_CFG_IGNORE_H_
#define _NST_CFG_IGNORE_H_

#include <nst_config.h>

#include <nst_types.h>

#include <expat.h>

nst_status_e nst_cfg_ignore(void *udata, const XML_Char *name,
                            const XML_Char **attrs, void **not_used_data);

#endif
