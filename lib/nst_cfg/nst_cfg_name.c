#include "nst_cfg_name.h"

void nst_cfg_name_capture(void *udata,
                          const XML_Char *name,
                          const XML_Char **atts,
                          char *buf,
                          size_t buf_size)
{
    nst_conf_elt_data_capture(udata, name, atts, buf, buf_size);
}
