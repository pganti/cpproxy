#ifndef _NST_RECVMSG_H_
#define _NST_RECVMSG_H_

#include <nst_config.h>

#include <nst_types.h>

struct nst_connection_s;

ssize_t nst_unix_recvmsg(struct nst_connection_s *c,
                         struct msghdr *msghdr,
                         size_t total_buf_size,
                         int flags);

#endif
