#ifndef _NST_CFG_NAME_H
#define _NST_CFG_NAME_H

#include <expat.h>

void nst_cfg_name_capture(void *udata,
                          const XML_Char *name,
                          const XML_Char **attrs,
                          char *name);

#endif
