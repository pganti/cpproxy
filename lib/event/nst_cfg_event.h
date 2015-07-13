#ifndef _NST_CFG_EVENT_H_
#define _NST_CFG_EVENT_H_

#include <nst_config.h>

#include <nst_cfg_common.h>

#include <nst_types.h>
#include <nst_log.h>
#include <nst_limits.h>

#include <expat.h>

#define MIN_NCONNECTIONS                (16)
#define DF_MAX_NCONNECTIONS             (307200)
#define DF_MAX_NTP_CONNECTIONS          ((DF_MAX_NCONNECTIONS * 3) / 5);
#define DF_MAX_NACCEPTS_PER_LOOP        (512)
#define DF_MAX_NEPOLL_EVENTS_PER_LOOP   (1024)
#define DF_CONN_POOL_SIZE               (256) /* 256 bytes */
/* Based on this on 2008:
 * http://www.websiteoptimization.com/speed/tweak/average-web-page/
 *
 * Most of the HTTP objects could be done within 4-5 event loops
 */
#define DF_MAX_NBYTES_PER_LOOP     (65536) /* 64 k */

#define EVENT_TAG "event"

struct nst_connection_s;
struct nst_event_s;

typedef struct nst_cfg_event_s nst_cfg_event_t;

extern nst_cfg_event_t event_cfg;

struct nst_cfg_event_s
{
    nst_uint_t max_nconnections;           
    nst_uint_t max_ntp_connections;        /* NOT configurable for now */
    nst_uint_t max_nepoll_events_per_loop;
    nst_uint_t max_naccepts_per_loop;
    /* nst_uint_t max_nmp_accepts_per_loop; */
    nst_uint_t max_nbytes_per_loop;

    nst_uint_t connection_pool_size;
};

void nst_cfg_event_init(nst_cfg_event_t *event);
nst_status_e nst_cfg_event_capture(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs,
                                   void **pevent_cfg, void **unused1,
                                   void **unused2, void **unused3);

nst_cfg_reload_status_e nst_cfg_event_apply_modified(nst_cfg_event_t *event,
                                           const nst_cfg_event_t *new_event);

#endif
