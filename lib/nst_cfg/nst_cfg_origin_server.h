#ifndef _NST_CFG_ORIGIN_SERVER_H_
#define _NST_CFG_ORIGIN_SERVER_H_

#include <nst_config.h>
#include <errno.h>
#include <nst_types.h>

#include <expat.h>

#define ORIGIN_SERVER_TAG "origin-server"

struct nst_cpt_node_s;

nst_status_e
nst_cfg_origin_server_capture(void *udata,
                              const XML_Char *name,
                              const XML_Char **attrs,
                              void **posite_node, void **unused1,
                              void **unused2, void **unused3);

#endif
