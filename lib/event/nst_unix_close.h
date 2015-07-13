#ifndef _NST_UNIX_CLOSE_H_
#define _NST_UNIX_CLOSE_H_

#include <nst_config.h>

#include "nst_io_ops.h"

#include <nst_types.h>

struct nst_connection_s;

nst_status_e
nst_unix_close(struct nst_connection_s *c, nst_io_close_reason_e reason);

#endif
