#ifndef _NST_CPPROXY_CFG_MYPROC_H_
#define _NST_CPPROXY_CFG_MYPROC_H_

/* always include nst_config.h first in .h file */
#include <nst_config.h>

#include <nst_types.h>

struct nst_cpproxy_cfg_s;
nst_status_e nst_cpproxy_cfg_myproc(const struct nst_cpproxy_cfg_s *cpproxy_cfg);


#endif
