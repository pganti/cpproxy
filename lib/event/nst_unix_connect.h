#ifndef _NST_UNIX_CONNECT_H_
#define _NST_UNIX_CONNECT_H_

#include <nst_config.h>

#include <nst_types.h>
#include <nst_log.h>

struct nst_connection_s;
struct nst_sockaddr_s;

nst_status_e nst_unix_connect(struct nst_connection_s **new_c,
                              struct nst_sockaddr_s *peer_sockaddr,
                              struct nst_sockaddr_s *local_sockaddr,
                              int tcp_ext,
                              nst_uint_t rid,
                              nst_log_level_t noc_log_lvl,
                              nst_log_level_t dbg_log_lvl);

#endif
