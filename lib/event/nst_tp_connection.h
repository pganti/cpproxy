#ifndef _NST_TP_CONNECTION_H_
#define _NST_TP_CONNECTION_H_

#include <nst_config.h>

#include "nst_connection.h"
#include "nst_cfg_sproxy.h"

#include <queue.h>
#include <nst_errno.h>
#include <nst_refcount.h>

#define NST_TP_CTRL_BYTE(type,data) (u_char)(((u_char)(data) << 4) | (u_char)(type))
#define NST_TP_CTRL_TYPE(urg_byte) ((nst_tp_ctrl_type_e)((urg_byte) & 0x0f))
#define NST_TP_CTRL_DATA(urg_byte) (((urg_byte)>>4) & 0x0f)

extern nst_int_io_ops_t nst_tp_int_io_ops;

typedef struct nst_tp_connection_s nst_tp_connection_t;
typedef enum nst_tp_conn_status_e nst_tp_conn_status_e;
typedef enum nst_tp_conn_type_e   nst_tp_conn_type_e;
typedef enum nst_tp_ctrl_type_e   nst_tp_ctrl_type_e;

enum nst_tp_ctrl_type_e
{
    NST_TP_CTRL_TYPE_UNKNOWN = 0, /* we should never use this one */
    NST_TP_CTRL_TYPE_SYN = 1, /* tell the peer that
                               * 1. I do not have any more data to send
                               *    due to error
                               * AND
                               * 2. The application due to error
                               *    has given up the TP connection and
                               *    will not receive any data from now on.
                               *   
                               */
    NST_TP_CTRL_TYPE_FIN = 2, /* tell the peer that I do not
                               * have anymore data to send but I can still
                               * receive data from the peer.
                               */

    NST_TP_CTRL_TYPE_RST = 3, /* tell the peer that
                               * 1. I do not have any more data to send
                               *    due to error
                               * AND
                               * 2. The application due to error
                               *    has given up the TP connection and
                               *    will not receive any data from now on.
                               *   
                               */

    NST_TP_CTRL_TYPE_OOB_ACK = 4, /* tell the peer that we got the OOB ctrl byte
                                   */

    _NST_TP_CTRL_TYPE_NUM = 5,
};

enum nst_tp_conn_status_e
{
    NST_TP_CONN_STATUS_UNKNOWN = 0,
    NST_TP_CONN_STATUS_FREE    = 1,
    NST_TP_CONN_STATUS_PENDING = 2,
    NST_TP_CONN_STATUS_OPEN    = 3,
    _NST_TP_CONN_STATUS_NUM      = 4,
};

enum nst_tp_conn_type_e
{
    NST_TP_CONN_TYPE_UNKNOWN  = 0,
    NST_TP_CONN_TYPE_ACTIVE   = 1,
    NST_TP_CONN_TYPE_PASSIVE  = 2,
    _NST_TP_CONN_TYPE_NUM     = 3,
};

struct nst_tp_connection_s
{
    nst_tp_conn_type_e type;

    nst_tp_conn_status_e status;

    nst_connection_t *parent;

    nst_cfg_sproxy_t *sproxy;

    nst_uint_t npending_ctrl_bytes;
    uint8_t    ctrl_pending[_NST_TP_CTRL_TYPE_NUM];
    uint8_t    ctrl_sent[_NST_TP_CTRL_TYPE_NUM];
    uint8_t    ctrl_received[_NST_TP_CTRL_TYPE_NUM];

    int io_errno;
    
    struct {
        unsigned    new_tcp_conn:1;                 
        unsigned    app_read_disabled:1;
        unsigned    io_eof:1;
        unsigned    int_error:1;
        unsigned    pending_urgent:1;
        unsigned    io_eof_from_ev:1; /*!< detected eof by 
                                       *   EPOLLRDHUP
                                       */
    } flags;

    const char *int_error_str;

    size_t ndumped_app_bytes;

    TAILQ_ENTRY(nst_tp_connection_s) lru_entry;
    TAILQ_ENTRY(nst_tp_connection_s) queue_entry;
                                     
};

void nst_tp_passive_accept_handler(nst_connection_t *conn);

int nst_tp_connect(nst_connection_t **conn, 
                   nst_sockaddr_t *local_sockaddr,
                   int tcp_ext,
                   nst_uint_t rid,
                   nst_log_level_t noc_log_lvl,
                   nst_log_level_t dbg_log_lvl,
                   nst_cfg_sproxy_t *sproxy,
                   bool ssl);
void nst_tp_conn_free(nst_tp_connection_t *tp_conn);

void nst_tp_init(nst_connection_handler_f conn_handler,
                 nst_connection_acl_f conn_acl);
void nst_tp_reset(void);

void nst_tp_log_stats(void);

nst_io_close_reason_e nst_tp_errno_to_close_reason(int local_errno, bool peer);

#endif
