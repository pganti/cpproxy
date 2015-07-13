#ifndef _NST_INIT_SOCKFD_H_
#define _NST_INIT_SOCKFD_H_

#include <nst_config.h>

#include <nst_log.h>
#include <nst_types.h>

int nst_nonblocking(int fd);

nst_status_e nst_init_sockfd(int fd, int tcp_ext);

nst_status_e nst_init_tp_sockfd(int fd);

#endif
