#ifndef _NST_EPOLL_H_
#define _NST_EPOLL_H_

#include <nst_config.h>
#include <nst_types.h>
#define EPOLLRDHUP 0x2000
struct nst_cfg_event_s;

nst_status_e nst_epoll_init(const struct nst_cfg_event_s *event_cfg);

#endif
