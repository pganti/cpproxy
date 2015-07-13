#ifndef _NST_LISTENER_H_
#define _NST_LISTENER_H_

#include <nst_config.h>

#include "nst_event_int.h"

#include <nst_allocator.h>
#include <nst_types.h>

struct nst_cfg_svc_s;

typedef struct nst_listener_s nst_listener_t;

struct nst_listener_s {
    nst_connection_t          *conn;    /* listener connection
                                         * we pretty much only use the
                                         * conn->read to allow callback
                                         * from event loop.
                                         */ 
    struct nst_cfg_svc_s      *svc;
};

nst_status_e nst_event_add_listener(struct nst_cfg_svc_s *svc);

void nst_event_del_listener(struct nst_cfg_svc_s *svc);

#endif
