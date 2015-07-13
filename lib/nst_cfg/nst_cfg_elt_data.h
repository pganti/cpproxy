#ifndef _NST_CFG_ELT_DATA_H
#define _NST_CFG_ELT_DATA_H

#include <nst_types.h>

#include <expat.h>

int nst_cfg_elt_data_capture(void *udata,
                             const XML_Char *name,
                             const XML_Char **atts,
                             char *buf,
                             size_t buf_size,
                             bool always_to_lower);

#endif
