#ifndef __NST_CFG_IP_H
#define __NST_CFG_IP_H

#include <expat.h>

struct nst_sockaddr_s;

int nst_cfg_ip_capture(void *udata,
                       const XML_Char *name,
                       const XML_Char **atts,
                       struct nst_sockaddr_s *nst_sockaddr);

#endif
