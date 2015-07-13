#ifndef _NST_CORELIB_H_
#define _NST_CORELIB_H_

#include "nst_config.h"

struct nst_log_s;

struct nst_log_s * nst_corelib_init (const char *agent);

void nst_corelib_reset(void);

#endif
