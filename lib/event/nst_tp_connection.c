#include "nst_tp_connection.h"

#include "nst_unix_recvmsg.h"
#include "nst_unix_close.h"
#include "nst_event_int.h"
#include "nst_event_common.h"
#include "nst_event.h"
#include "nst_io_ops.h"
#include "nst_cfg_svc.h"
#include "nst_init_sockfd.h"
#include "nst_unix_connect.h"

#include <nst_cfg_common.h>

#include <nst_enum_type_helpers.h>
#include <nst_palloc.h>
#include <nst_mempool.h>
#include <nst_log_debug.h>
#include <nst_types.h>
#include <nst_assert.h>

#define NST_TP_MAX_NDUMPED_APP_BYTES            (2097152)   /* 2Mbytes  */
#define NST_TP_MAX_NDUMPED_APP_BYTES_PER_LOOP   (65536)     /* 64Kbytes */

#define NST_TP_CONN_PENDING_FREE_TIMEOUT_MS     (180000) /* 180 s */

#define NST_TP_CONN_MAX_ACTIVE_GARBAGE_CTRL_BYTE (16)

#define TRASH_QENTRY(x)                                        \
    do {                                                       \
        (x)->queue_entry.tqe_next = (void *)-1;                \
        (x)->queue_entry.tqe_prev = (void *)-1;                \
    } while (0)

#define TRASH_LRU_ENTRY(x) \
    do {                                                                \
        (x)->lru_entry.tqe_next = (void *)-1;                           \
        (x)->lru_entry.tqe_prev = (void *)-1;                           \
    } while (0)

typedef struct nst_tp_conn_ctx_s nst_tp_conn_ctx_t;

static char crap_data_buf[8760];  /* 1460 * 6 */

struct nst_tp_conn_ctx_s
{
    nst_mempool_t               *tp_conn_mempool;

    struct nst_tp_conn_queue_s   lru_queue;
    struct nst_tp_conn_queue_s   passive_queue;
    struct nst_tp_conn_queue_s   pending_queue;

    nst_uint_t                   ntp_connections;
    nst_uint_t                   npending;        /* pending close */
    nst_uint_t                   nidle_active;    /* free active   */
    nst_uint_t                   nidle_passive;   /* free passive  */ 
    nst_uint_t                   nopen_active;         /* open active   */
    nst_uint_t                   nopen_passive;        /* open passive  */

    nst_connection_handler_f     conn_handler;
    nst_connection_acl_f         conn_acl;
};

nst_tp_conn_ctx_t nst_tp_conn_ctx = {
    .tp_conn_mempool = NULL,
};

static ssize_t nst_tp_recv(nst_connection_t *conn, u_char *buf, size_t size);
static ssize_t nst_tp_send(nst_connection_t *conn, const u_char *buf, size_t size, int flags);
static nst_status_e nst_tp_close(nst_connection_t *conn, nst_io_close_reason_e reason);
static ssize_t nst_tp_writev_chain(nst_connection_t *conn, nst_iochain_t *in);
static void nst_tp_set_io_eof_from_ev(nst_connection_t *c);
static nst_tp_connection_t * nst_tp_get_pooled_conn (nst_cfg_sproxy_t *sproxy);
static void nst_tp_conn_active_free_read_till_eagain(nst_tp_connection_t *tp_conn, nst_connection_t *conn);
nst_io_ops_t nst_tp_io_ops = {
    .recv       = nst_tp_recv,
    /* .recv_chain = NULL, */
    .udp_recv   = NULL,
    .send       = nst_tp_send,
    .send_chain = nst_tp_writev_chain,
    .close      = nst_tp_close,
    .shutdown   = NULL,
};

nst_int_io_ops_t nst_tp_int_io_ops = {
    .set_io_eof_from_ev = nst_tp_set_io_eof_from_ev,
};

static void nst_tp_conn_move_to_queue(nst_tp_connection_t *tp_conn);
static void nst_tp_read_handler(nst_event_t *rev);
static void nst_tp_write_handler(nst_event_t *wev);
static nst_status_e nst_tp_conn_flush_pending_ctrl_bytes(nst_tp_connection_t *tp_conn);
static nst_status_e nst_tp_conn_recv_ctrl_byte(nst_tp_connection_t *tp_conn);

static void nst_tp_conn_passive_idle_accept(nst_tp_connection_t *tp_conn);

static int nst_conn_close_reason_to_errno_table[_NST_IO_CLOSE_REASON_NUM] = {
    [NST_IO_CLOSE_REASON_OK]        = 0,
    [NST_IO_CLOSE_REASON_ERROR]     = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_FWD_ERROR] = NST_ECONN_PEER_FWD_ERROR,
    [NST_IO_CLOSE_REASON_RST]       = ECONNRESET,
    [NST_IO_CLOSE_REASON_FWD_RST]   = NST_ECONN_PEER_FWD_RST,
    [NST_IO_CLOSE_REASON_TIMEDOUT]  = NST_ECONN_PEER_TIMEDOUT,
    [NST_IO_CLOSE_REASON_FWD_TIMEDOUT]  = NST_ECONN_PEER_FWD_TIMEDOUT,
    [NST_IO_CLOSE_REASON_TP_RESERVED_8] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_7] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_6] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_5] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_4] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_3] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_2] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_1] = NST_ECONN_PEER_ERROR,
    [NST_IO_CLOSE_REASON_TP_RESERVED_0] = NST_ECONN_PEER_ERROR,
};

static const char *mp_ctrl_type_str_table[_NST_TP_CTRL_TYPE_NUM] = {
    [NST_TP_CTRL_TYPE_UNKNOWN] = "TP-TYPE-UNKNOWN",
    [NST_TP_CTRL_TYPE_SYN]     = "TP-SYN",
    [NST_TP_CTRL_TYPE_FIN]     = "TP-FIN",
    [NST_TP_CTRL_TYPE_RST]     = "TP-RST",
    [NST_TP_CTRL_TYPE_OOB_ACK] = "TP-OOB-ACK",
};

static const char *tp_conn_status_str_table[_NST_TP_CONN_STATUS_NUM] = {
    [NST_TP_CONN_STATUS_UNKNOWN] = "TP-STATUS-UNKNOWN",
    [NST_TP_CONN_STATUS_FREE]    = "TP-FREE",
    [NST_TP_CONN_STATUS_PENDING] = "TP-PENDING",
    [NST_TP_CONN_STATUS_OPEN]    = "TP-OPEN",
};

static inline bool
nst_tp_conn_is_reusable(const nst_tp_connection_t *tp_conn)
{
    if(tp_conn->flags.int_error
       || tp_conn->io_errno
       || tp_conn->flags.io_eof
       || tp_conn->flags.io_eof_from_ev) {
        return FALSE;
    } else if(tp_conn->type == NST_TP_CONN_TYPE_ACTIVE) {
        nst_assert(tp_conn->sproxy);
        nst_assert(NST_REFC_VALUE(tp_conn->sproxy) >= 1);
        if(tp_conn->sproxy->flags.destroyed == 1) {
            return FALSE;
        }
    }

    return TRUE;
}

static inline const char *
nst_tp_ctrl_type_to_str(nst_tp_ctrl_type_e ctrl_type)
{
    return nst_enum_type_to_str(mp_ctrl_type_str_table,
                                NST_TP_CTRL_TYPE_UNKNOWN,
                                _NST_TP_CTRL_TYPE_NUM,
                                NST_TP_CTRL_TYPE_UNKNOWN,
                                ctrl_type);
}

static inline const char *
nst_tp_ctrl_byte_to_str(u_char ctrl_byte)
{
    static char ctrl_byte_str[64];

    snprintf(ctrl_byte_str,
             sizeof(ctrl_byte_str),
             "(%s:%X)",
             nst_tp_ctrl_type_to_str(NST_TP_CTRL_TYPE(ctrl_byte)),
             NST_TP_CTRL_DATA(ctrl_byte));
    ctrl_byte_str[sizeof(ctrl_byte_str) - 1] = '\0';

    return ctrl_byte_str;
}

static inline const char *
nst_tp_conn_status_to_str(nst_tp_conn_status_e status)
{
    return nst_enum_type_to_str(tp_conn_status_str_table,
                                NST_TP_CONN_STATUS_UNKNOWN,
                                _NST_TP_CONN_STATUS_NUM,
                                NST_TP_CONN_STATUS_UNKNOWN,
                                status);
}

static inline const char *
nst_tp_conn_type_to_str(nst_tp_conn_type_e type)
{
    if(type == NST_TP_CONN_TYPE_ACTIVE)
        return "active";
    else
        return "passive";
}

static inline void
nst_tp_conn_set_io_errno(nst_tp_connection_t *tp_conn, int saved_errno)
{
    tp_conn->io_errno = saved_errno;
}

static inline bool 
nst_tp_conn_is_urgent_sent(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_FIN]
            || tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_RST]);
}

static inline bool
nst_tp_conn_is_oob_ack_sent(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_OOB_ACK]);
}

static inline bool
nst_tp_conn_is_syn_received(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_received[NST_TP_CTRL_TYPE_SYN]);
}

static inline bool
nst_tp_conn_is_urgent_received(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_received[NST_TP_CTRL_TYPE_FIN]
            || tp_conn->ctrl_received[NST_TP_CTRL_TYPE_RST]);
}

static inline bool
nst_tp_conn_is_rst_received(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_received[NST_TP_CTRL_TYPE_RST]);
}

static inline bool
nst_tp_conn_is_oob_ack_received(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_received[NST_TP_CTRL_TYPE_OOB_ACK]);
}

static inline bool
nst_tp_conn_is_ctrl_type_out(const nst_tp_connection_t *tp_conn,
                             nst_tp_ctrl_type_e mp_ctrl_type)
{
    return (tp_conn->ctrl_sent[mp_ctrl_type]
            || tp_conn->ctrl_pending[mp_ctrl_type]);
}

static inline bool
nst_tp_conn_is_fin_or_rst_out(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_FIN]
            || tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_RST]
            || tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_FIN]
            || tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_RST]);
}

static inline bool
nst_tp_conn_is_oob_ack_out(const nst_tp_connection_t *tp_conn)
{
    return (tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_OOB_ACK]
            || tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_OOB_ACK]);
}

/* should we send the mp_ctrl_byte with MSG_OOB? */
static inline int
nst_tp_conn_ctrl_send_flags(const nst_tp_connection_t *tp_conn,
                            nst_tp_ctrl_type_e mp_ctrl_type)
{
    switch(mp_ctrl_type) {
    case NST_TP_CTRL_TYPE_FIN:
        return MSG_OOB;
    case NST_TP_CTRL_TYPE_RST:
        if(!nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_FIN))
           return MSG_OOB;
        else
            return 0;
    case NST_TP_CTRL_TYPE_SYN:
    case NST_TP_CTRL_TYPE_OOB_ACK:
        return 0;
    default:
        nst_assert(0 && "unhandled nst_tp_ctrl_type_e");
    };
}

/* Add the tp_conn to active_queue or passive_queue.
 * The nidle_acive or nidle_passive will be incremented accordingly.
 * Also pre-pend to lru_queue.
 */
static inline void
nst_tp_conn_add_to_free_queue(nst_tp_connection_t *tp_conn)
{
    nst_assert(tp_conn->queue_entry.tqe_prev == (void *)-1);
    nst_assert(tp_conn->queue_entry.tqe_next == (void *)-1);
    nst_assert(tp_conn->lru_entry.tqe_prev == (void *)-1);
    nst_assert(tp_conn->lru_entry.tqe_next == (void *)-1);
    
    switch(tp_conn->type) {
    case NST_TP_CONN_TYPE_ACTIVE:
        TAILQ_INSERT_HEAD(&tp_conn->sproxy->active_queue,
                          tp_conn,
                          queue_entry);
        nst_tp_conn_ctx.nidle_active++;
        break;
    case NST_TP_CONN_TYPE_PASSIVE:
        TAILQ_INSERT_HEAD(&nst_tp_conn_ctx.passive_queue,
                          tp_conn,
                          queue_entry);
        nst_tp_conn_ctx.nidle_passive++;
        break;
    default:
        nst_assert(0 && "unhandled nst_tp_conn_type_e");
    }
    
    TAILQ_INSERT_HEAD(&nst_tp_conn_ctx.lru_queue,
                      tp_conn,
                      lru_entry);
}

/* Remove from active_queue or passive_queue.
 * The nidle_acive or nidle_passive will be decremented accordingly.
 * Also remove from lru_queue.
 */
static inline void
nst_tp_conn_remove_from_free_queue(nst_tp_connection_t *tp_conn)
{
    nst_assert(tp_conn->queue_entry.tqe_prev != (void *)-1);
    nst_assert(tp_conn->queue_entry.tqe_next != (void *)-1);
    nst_assert(tp_conn->lru_entry.tqe_prev != (void *)-1);
    nst_assert(tp_conn->lru_entry.tqe_next != (void *)-1);

    switch(tp_conn->type) {
    case NST_TP_CONN_TYPE_ACTIVE:
        TAILQ_REMOVE(&tp_conn->sproxy->active_queue,
                     tp_conn,
                     queue_entry);
        nst_tp_conn_ctx.nidle_active--;
        break;
    case NST_TP_CONN_TYPE_PASSIVE:
        TAILQ_REMOVE(&nst_tp_conn_ctx.passive_queue,
                     tp_conn,
                     queue_entry);
        nst_tp_conn_ctx.nidle_passive--;
        break;
    default:
        nst_assert(0 && "unhandled nst_tp_conn_type_e");
    }
    TRASH_QENTRY(tp_conn);
    
    TAILQ_REMOVE(&nst_tp_conn_ctx.lru_queue,
                 tp_conn,
                 lru_entry);
    TRASH_LRU_ENTRY(tp_conn);

    nst_memzero(tp_conn->ctrl_sent, sizeof(tp_conn->ctrl_sent));
}

/* Add to pending_queue.
 * The npending will be incremented accordingly.
 */
static inline void
nst_tp_conn_add_to_pending_queue(nst_tp_connection_t *tp_conn)
{
    nst_assert(tp_conn->queue_entry.tqe_prev == (void *)-1);
    nst_assert(tp_conn->queue_entry.tqe_next == (void *)-1);

    TAILQ_INSERT_HEAD(&nst_tp_conn_ctx.pending_queue,
                      tp_conn,
                      queue_entry);
    nst_tp_conn_ctx.npending++;
}

/* Remove from pending queue.
 * The npending will be decremented accordingly.
 */
static inline void
nst_tp_conn_remove_from_pending_queue(nst_tp_connection_t *tp_conn)
{
    nst_assert(tp_conn->queue_entry.tqe_prev != (void *)-1);
    nst_assert(tp_conn->queue_entry.tqe_next != (void *)-1);

    TAILQ_REMOVE(&nst_tp_conn_ctx.pending_queue,
                 tp_conn,
                 queue_entry);
    TRASH_QENTRY(tp_conn);
    nst_tp_conn_ctx.npending--;
}

/* There are two functions to initialize a newly created
 * nst_tp_connection_t object:
 *
 * 1. nst_tp_conn_passive_init() for passive TP conn
 * 2. nst_tp_conn_active_init() for active TP conn
 */

/* Init a new tp_conn after accepting a new TCP connection */
static inline void
nst_tp_conn_passive_init(nst_tp_connection_t *tp_conn,
                         nst_connection_t *conn)
{
    nst_memzero(tp_conn, sizeof(*tp_conn));

    tp_conn->type = NST_TP_CONN_TYPE_PASSIVE;
    tp_conn->status = NST_TP_CONN_STATUS_FREE; /* it is free until we got
                                                * a TP SYN
                                                */
    tp_conn->parent = conn;
    tp_conn->sproxy = NULL;
    tp_conn->flags.new_tcp_conn=1;
    TRASH_QENTRY(tp_conn);
    TRASH_LRU_ENTRY(tp_conn);

    nst_assert(conn->flags.closed == 0);
    conn->flags.closed = 1; /* app does not have the control at this point */
    conn->tp_conn = tp_conn;
    /* conn->io_ops = &nst_tp_io_ops; */
    conn->tid = 0;

    /* For passive, we are still free until we got a TP SYN */
    nst_tp_conn_add_to_free_queue(tp_conn);
    
    /* We pretend we have got TP FIN and TP RST to stop
     * nst_tp_read_handler() from reading TP FIN and TP RST.
     * 
     * (We are not expecting TP FIN and TP RST because it is a newly created TCP
     *  connection)
     */
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_FIN]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_FIN, 0);
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_RST]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_RST, NST_IO_CLOSE_REASON_OK);
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_OOB_ACK]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_OOB_ACK, 0);

    /* book keeping */
    nst_tp_conn_ctx.ntp_connections++;
}

/* Init a newly created tp_conn */
static inline void
nst_tp_conn_active_init(nst_tp_connection_t *tp_conn,
                        nst_connection_t *conn,
                        nst_cfg_sproxy_t *sproxy)
{
    nst_memzero(tp_conn, sizeof(*tp_conn));

    tp_conn->type = NST_TP_CONN_TYPE_ACTIVE;
    tp_conn->status = NST_TP_CONN_STATUS_OPEN;
    tp_conn->parent = conn;
    tp_conn->sproxy = sproxy;
    tp_conn->flags.new_tcp_conn = 1;
    NST_REFC_GET(sproxy);
    TRASH_QENTRY(tp_conn);
    TRASH_LRU_ENTRY(tp_conn);

    /* We do not put into any active_queue and lru_queue because the app
     * should get the conn handler immediately.
     */

    /* We also don't need to set closed since all active conn will be passed
     * to app immediately
     */
    nst_assert(conn->flags.closed == 0);
    conn->flags.closed = 1;
    conn->tp_conn = tp_conn;
    conn->io_ops = &nst_tp_io_ops;

    /* We pretend we have got TP FIN and TP RST to stop
     * nst_tp_read_handler() from reading TP FIN and TP RST.
     * 
     * (We are not expecting TP FIN and TP RST because it is a newly created TCP
     *  connection)
     */
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_FIN]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_FIN, 0);
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_RST]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_RST, NST_IO_CLOSE_REASON_OK);
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_OOB_ACK]
        = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_OOB_ACK, 0);

    /* book keeping */
    nst_tp_conn_ctx.ntp_connections++;
}

/* Reset the tp_conn and conn.
 * Remove from pending queue if needed.
 * Add to the right free queue by calling nst_tp_conn_add_to_free_queue().
 */
static inline void
nst_tp_conn_move_to_free_queue(nst_tp_connection_t *tp_conn)
{
    nst_connection_t *conn = tp_conn->parent;

    /* clean up conn */ 
    nst_assert(conn->flags.closed == 1);

    conn->tid = 0;
    conn->noc_log_lvl = NST_LOG_LEVEL_DEFAULT;
    conn->dbg_log_lvl = NST_LOG_LEVEL_DEFAULT;
    conn->io_errno = 0;
    conn->flags.io_eof = 0;
    conn->flags.shutdown = 0;
    conn->data = NULL;
    nst_event_del_timer(conn->read);
    nst_event_del_timer(conn->write);
    nst_event_clear_timedout(conn->read);
    nst_event_clear_timedout(conn->write);
    /* nst_destroy_pool(conn->pool); */ /* pool is destroyed by apps */

    /* clean up tp_conn */

    /* remove any pending ctrl bytes */
    tp_conn->npending_ctrl_bytes = 0;
    nst_memzero(tp_conn->ctrl_pending, sizeof(tp_conn->ctrl_pending));

    /* we should not clear up the ctrl_sent vertor to avoid sending
     * OOB_ACK again in nst_tp_read_handler.
     */

    /* The ctrl_received of TP FIN and TP RST should not be cleared
     * now so that we can check for error case when duplicate TP FIN and/or
     * TP RST are received.
     */
    tp_conn->ctrl_received[NST_TP_CTRL_TYPE_SYN] = 0;

    tp_conn->io_errno = 0;
    nst_memzero(&tp_conn->flags, sizeof(tp_conn->flags));
    tp_conn->int_error_str = NULL;
    tp_conn->ndumped_app_bytes = 0;
    tp_conn->flags.new_tcp_conn = 0;

    if(tp_conn->status == NST_TP_CONN_STATUS_PENDING) {
        /* If it is in pending_queue, remove it first */
        nst_tp_conn_remove_from_pending_queue(tp_conn);
    }

    tp_conn->status = NST_TP_CONN_STATUS_FREE;
    nst_tp_conn_add_to_free_queue(tp_conn);
    NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s is moved to free queue",
                     nst_connection_get_dbg_str(conn));
    if(conn->read->ready) {
        switch(tp_conn->type) {
        case NST_TP_CONN_TYPE_PASSIVE:
            nst_event_postpone(conn->read);
            break;
        case NST_TP_CONN_TYPE_ACTIVE:
            /* we will get either EAGAIN or error */
            nst_tp_conn_active_free_read_till_eagain(tp_conn, conn);
            break;
        default:
            nst_assert(0 && "Never should land here");
        }
    }
}

static inline void
nst_tp_conn_move_to_pending_queue(nst_tp_connection_t *tp_conn)
{
    if(tp_conn->status == NST_TP_CONN_STATUS_PENDING)
        return;

    tp_conn->status = NST_TP_CONN_STATUS_PENDING;
    nst_tp_conn_add_to_pending_queue(tp_conn);
    NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s is moved to pending queue. "
                     "urg-received:%d urg-sent:%d",
                     nst_connection_get_dbg_str(tp_conn->parent),
                     nst_tp_conn_is_urgent_received(tp_conn),
                     nst_tp_conn_is_urgent_sent(tp_conn));

}

void
nst_tp_conn_free(nst_tp_connection_t *tp_conn)
{
    nst_connection_t *conn = tp_conn->parent;

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "closing %s io_eof:(%d|%d) io_errno:%d int_error:%d(%s)",
                nst_connection_get_brief_str(conn),
                tp_conn->flags.io_eof,
                tp_conn->flags.io_eof_from_ev,
                tp_conn->io_errno,
                tp_conn->flags.int_error,
                tp_conn->int_error_str ? tp_conn->int_error_str : "no-int-error-string");
        
    switch(tp_conn->status) {
    case NST_TP_CONN_STATUS_PENDING:
        nst_tp_conn_remove_from_pending_queue(tp_conn);
        break;
    case NST_TP_CONN_STATUS_OPEN:
        break;
    case NST_TP_CONN_STATUS_FREE:
        nst_tp_conn_remove_from_free_queue(tp_conn);
        break;
    default:
        nst_assert(0 && "unhandled nst_tp_conn_status_e");
    }

    if(tp_conn->type == NST_TP_CONN_TYPE_ACTIVE) {
        nst_assert(tp_conn->sproxy);
        NST_REFC_PUT(tp_conn->sproxy);
    }

    nst_tp_conn_ctx.ntp_connections--;
    nst_mempool_free(nst_tp_conn_ctx.tp_conn_mempool, tp_conn);

    nst_assert(tp_conn->type != NST_TP_CONN_TYPE_ACTIVE || !conn->pool);
    nst_unix_close(conn, NST_IO_CLOSE_REASON_OK);
}

static inline nst_status_e
nst_tp_conn_free_from_lru(void)
{
    nst_tp_connection_t *tp_conn;
    if(TAILQ_ETPTY(&nst_tp_conn_ctx.lru_queue))
        return NST_ERROR;

    tp_conn = TAILQ_LAST(&nst_tp_conn_ctx.lru_queue, nst_tp_conn_queue_s);
    nst_tp_conn_free(tp_conn);
    return NST_OK;
}

static void
nst_tp_conn_move_to_queue(nst_tp_connection_t *tp_conn)
{
    bool move_to_pending = FALSE;
    nst_connection_t *conn = tp_conn->parent;

    /* If app still has a hand on it, we cannot move.  It will be retried
     * when the app calls nst_tp_close() later
     */
    if(!conn->flags.closed)
        return;

    /* If we get a TCP FIN, we will close the physical TCP connection */
    if(!nst_tp_conn_is_reusable(tp_conn)) {
        nst_tp_conn_free(tp_conn);
        return;
    }

    if(tp_conn->status == NST_TP_CONN_STATUS_FREE)
        /* It is already in free queue */
        return;

    /* app has given up the tp_conn handle, we will install our own
     * read and writer handlers.
     */
    conn->read->handler = nst_tp_read_handler;
    conn->write->handler = nst_tp_write_handler;

    /* we always register for read event to learn the TCP FIN/RST event */
    nst_handle_read_event(conn->read, 0);

    if(!nst_tp_conn_is_urgent_received(tp_conn)
       || !nst_tp_conn_is_oob_ack_received(tp_conn)
       || !nst_tp_conn_is_syn_received(tp_conn)) {
        if(!conn->read->ready) {
            nst_event_add_timer_if_not_set(conn->read,
                                           NST_TP_CONN_PENDING_FREE_TIMEOUT_MS);
        }

        move_to_pending = TRUE;
    }  else {
        nst_event_del_timer(conn->read);
    }

    if (tp_conn->npending_ctrl_bytes > 0) {
        if(!conn->write->ready)  {
            nst_event_add_timer_if_not_set(conn->write,
                                           NST_TP_CONN_PENDING_FREE_TIMEOUT_MS);
        }
        nst_handle_write_event(conn->write, 0);

        move_to_pending = TRUE;
    } else {
        nst_event_del_timer(conn->write);
    }

    if(move_to_pending) {
        nst_tp_conn_move_to_pending_queue(tp_conn);
    } else {
        /* now, we sent urgent, sent oob ack,
         * received urgent and received OOB
         * => ready to be reused
         */
        nst_tp_conn_move_to_free_queue(tp_conn);
    }
}

static void
nst_tp_write_handler(nst_event_t *wev)
{
    nst_connection_t *conn = (nst_connection_t *)wev->data;
    nst_tp_connection_t *tp_conn = (nst_tp_connection_t *)conn->tp_conn;

    nst_assert(conn->flags.closed);

    if(nst_event_is_timedout(wev)) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "%s write event timed out out when in mp-status:%s",
                      nst_connection_get_dbg_str(conn),
                      nst_tp_conn_status_to_str(tp_conn->status));
        tp_conn->flags.int_error = 1;
        tp_conn->int_error_str = "timed out when writing TP FIN/RST";
        nst_tp_conn_move_to_queue(tp_conn);
        nst_tp_conn_move_to_free_queue(tp_conn);
        return;
    }

    if(nst_tp_conn_flush_pending_ctrl_bytes(tp_conn) == NST_ERROR)
        nst_tp_conn_free(tp_conn);
    else
        nst_tp_conn_move_to_queue(tp_conn);
}

/* Flush the pending TP ctrl bytes when the write event is triggered */
static nst_status_e
nst_tp_conn_flush_pending_ctrl_bytes(nst_tp_connection_t *tp_conn)
{
    nst_tp_ctrl_type_e mp_ctrl_type;
    u_char mp_ctrl_byte;
    u_char *ctrl_sent;
    u_char *ctrl_pending;
    int n;
    nst_connection_t *conn = tp_conn->parent;
    size_t old_npending_ctrl_bytes;

    nst_assert(conn->flags.closed);

    if(!conn->write->ready) {
        NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s write not ready for flushing mp ctrl bytes",
                         nst_connection_get_brief_str(conn));
        return NST_OK;
    }

    if(!tp_conn->npending_ctrl_bytes) {
        return NST_OK;
    }

    old_npending_ctrl_bytes = tp_conn->npending_ctrl_bytes;

    ctrl_sent = tp_conn->ctrl_sent;
    ctrl_pending = tp_conn->ctrl_pending;

    for(mp_ctrl_type = NST_TP_CTRL_TYPE_SYN;
        mp_ctrl_type < _NST_TP_CTRL_TYPE_NUM;
        mp_ctrl_type++) {
        int flags;

        mp_ctrl_byte = ctrl_pending[mp_ctrl_type];
        if(!mp_ctrl_byte)
            /* nothing pending */
            continue;
        
        /* TP FIN must be sent in urgent */
        flags = nst_tp_conn_ctrl_send_flags(tp_conn, mp_ctrl_type);

        n = nst_send(conn, &mp_ctrl_byte, 1, flags);
        NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s sent ctrl byte:%s oob:%d n:%d",
                         nst_connection_get_dbg_str(tp_conn->parent),
                         nst_tp_ctrl_byte_to_str(mp_ctrl_byte),
                         (flags & MSG_OOB),
                         n);
        if(n == 1) {
            ctrl_pending[mp_ctrl_type] = 0;
            ctrl_sent[mp_ctrl_type] = mp_ctrl_byte;
            tp_conn->npending_ctrl_bytes--;
        } else if(n == NST_AGAIN) {
            break;
        } else {
            /* n == NST_ERROR */
            nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
            return NST_ERROR;
        }
    }

    return NST_OK;
}

/* Update the tp_conn and/or move it to the right queue after
 * receiving a TP ctrl byte.
 *
 * tp_conn may be moved to free/pending queue or even be free-ed by calling
 * nst_tp_conn_move_to_queue()
 */
static inline nst_status_e
nst_tp_conn_received_ctrl_byte(nst_tp_connection_t *tp_conn,
                               uint8_t mp_ctrl_byte,
                               bool oob)
{
    nst_tp_ctrl_type_e mp_ctrl_type = NST_TP_CTRL_TYPE(mp_ctrl_byte);
    uint8_t *ctrl_received = tp_conn->ctrl_received;
    nst_status_e ret = NST_OK;
    bool notify_app_passive_handler = FALSE;
    nst_connection_t *conn = tp_conn->parent;

    NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s received ctrl byte:%s oob:%d",
                     nst_connection_get_dbg_str(tp_conn->parent),
                     nst_tp_ctrl_byte_to_str(mp_ctrl_byte),
                     oob);

    switch(mp_ctrl_type) {
    case NST_TP_CTRL_TYPE_SYN:
        if(ctrl_received[NST_TP_CTRL_TYPE_SYN]) {
            /* got double TP SYN? */
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received double TP SYN";
            ret = NST_ERROR;
        } else if(oob) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received TP SYN in urgent mode";
            ret = NST_ERROR;
        } else {
            memset(ctrl_received, 0, sizeof(tp_conn->ctrl_received));
            notify_app_passive_handler =
                (tp_conn->type == NST_TP_CONN_TYPE_PASSIVE);
        }
        break;

    case NST_TP_CTRL_TYPE_FIN:
        if(ctrl_received[NST_TP_CTRL_TYPE_FIN]) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received double TP FIN";
            ret = NST_ERROR;
        } else if(ctrl_received[NST_TP_CTRL_TYPE_RST]) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received TP FIN after TP RST";
            ret = NST_ERROR;
        } else if(!oob) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received non-urgent TP FIN";
            ret = NST_ERROR;
        } else {
            conn->flags.io_eof = 1;
        }
        break;

    case NST_TP_CTRL_TYPE_OOB_ACK:
        if(ctrl_received[NST_TP_CTRL_TYPE_OOB_ACK]) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received double TP OOB ACK";
            ret = NST_ERROR;
        } else if(!nst_tp_conn_is_urgent_sent(tp_conn)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received OOB ACK before sending out OOB";
            ret = NST_ERROR;
        }
        break;
                            
    case NST_TP_CTRL_TYPE_RST:
        if(ctrl_received[NST_TP_CTRL_TYPE_RST]) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received double TP RST";
            ret = NST_ERROR;
        } else if(ctrl_received[NST_TP_CTRL_TYPE_FIN]) {
            if(oob) {
                tp_conn->flags.int_error = 1;
                tp_conn->int_error_str = 
                    "received an urgent TP RST after an urgent TP FIN";
                ret = NST_ERROR;
            }
        } else if(!oob){
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "received non-urgent TP RST before TP FIN";
            ret = NST_ERROR;
        } else {
            uint8_t mp_ctrl_data;

            mp_ctrl_data = NST_TP_CTRL_DATA(mp_ctrl_byte);
            if(mp_ctrl_data == NST_IO_CLOSE_REASON_OK) {
                tp_conn->flags.int_error = 1;
                tp_conn->int_error_str =
                    "received TP RST with NST_IO_CLOSE_REASON_OK";
                ret = NST_ERROR;
            } else {
                int peer_errno;
                peer_errno = nst_conn_close_reason_to_errno_table[mp_ctrl_data];
                nst_connection_set_io_errno(conn, peer_errno);
            }
        }
        break;

    default:
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "c#:%ui received unknown ctrl byte %Xd",
                      tp_conn->parent->number,
                      (int)mp_ctrl_byte);
        tp_conn->flags.int_error = 1;
        tp_conn->int_error_str =
            "recevied unknown ctrl byte";
        ret = NST_ERROR;
    }

    if(ret == NST_OK) {
        ctrl_received[mp_ctrl_type] = mp_ctrl_byte;
        if(notify_app_passive_handler) {
            nst_tp_conn_passive_idle_accept(tp_conn);
        }
    } else {
        NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "received invalid TP ctrl byte %Xd. %s",
                         mp_ctrl_byte, tp_conn->int_error_str);
    }

    return ret;
}

/* Check if the mp_ctrl_byte makes any sense to be sent.
 *
 * Send it out by calling nst_tp_flush_pending_ctrl_bytes(), so the 
 * tp_conn may be moved to free/pending queue or even being free-ed if errors
 * detected.  To avoid this, the caller has to ensure conn->closed has
 * the proper value.  You can look at nst_tp_conn_move_to_queue() to
 * understand the effect of the conn->closed
 */
static inline nst_status_e
nst_tp_conn_send_ctrl_byte(nst_tp_connection_t *tp_conn, u_char mp_ctrl_byte)
{
    nst_connection_t *conn = tp_conn->parent;
    nst_tp_ctrl_type_e mp_ctrl_type = NST_TP_CTRL_TYPE(mp_ctrl_byte);

    nst_assert(conn->flags.closed);

    NST_DEBUG_LOG_OV(tp_conn->parent->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "%s sending ctrl byte:%s",
                     nst_connection_get_dbg_str(tp_conn->parent),
                     nst_tp_ctrl_byte_to_str(mp_ctrl_byte));

    switch(mp_ctrl_type) {
    case NST_TP_CTRL_TYPE_SYN:
        /* It must be occupied by the upper application */
        /* nst_assert(tp_conn->status == NST_TP_CONN_STATUS_OPEN); */
        /* nst_assert(conn->closed == 0); */

        /* only one TP SYN can be sent */
        if(nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_SYN)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "sent double TP SYN";
        }
        break;

    case NST_TP_CTRL_TYPE_FIN:
        if(!nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_SYN)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "TP FIN is sent before TP SYN";
        } else if(nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_RST)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "TP FIN is sent after TP RST";
        } else if(nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_FIN)) {
            NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                             NST_LOG_LEVEL_DEBUG,
                             "%s sending TP FIN after another TP FIN. ignored",
                             nst_connection_get_brief_str(conn));
            /* The application may have called nst_tp_shutdown() and then
             * followed by nst_tp_close() IF we eventually implemented
             * nst_tp_shutdown()
             */
            return NST_OK; /* pretend that we have sent */
        }

        break;

    case NST_TP_CTRL_TYPE_OOB_ACK:
        if(!nst_tp_conn_is_urgent_received(tp_conn)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "sending OOB ACK before receiving OOB";
        } else if(nst_tp_conn_is_ctrl_type_out(tp_conn,
                                               NST_TP_CTRL_TYPE_OOB_ACK)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "sending duplicate OOB ACK";
        }
        break;

    case NST_TP_CTRL_TYPE_RST:
        /* TP SYN must have been sent out */
        if(!nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_SYN)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "TP RST is sent before TP SYN";
        } else if(nst_tp_conn_is_ctrl_type_out(tp_conn, NST_TP_CTRL_TYPE_RST)) {
            tp_conn->flags.int_error = 1;
            tp_conn->int_error_str = "sent double TP RST";
        }

        break;
    default:
        nst_assert(0 && "unhandled nst_tp_ctrl_type_e");
    }
    
    if(tp_conn->flags.int_error) {
        return NST_ERROR;
    } else {
        tp_conn->ctrl_pending[mp_ctrl_type] = mp_ctrl_byte;
        tp_conn->npending_ctrl_bytes++;
        if(nst_tp_conn_flush_pending_ctrl_bytes(tp_conn) == NST_ERROR)
            return NST_ERROR;
        else
            return NST_OK;
    }
}

static nst_status_e
nst_tp_conn_recv_ctrl_byte(nst_tp_connection_t *tp_conn)
{
    nst_connection_t *conn = tp_conn->parent;
    ssize_t n;
    ssize_t ndumped;
    const u_char *ctrl_received;
    struct iovec iov;
    struct msghdr msg;

    nst_assert(conn->flags.closed);
    if(!conn->read->ready) {
        NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s read not ready to read mp ctrl bytes",
                         nst_connection_get_brief_str(conn));
        return NST_OK;
    }

    ctrl_received = tp_conn->ctrl_received;
    nst_memzero(&iov, sizeof(iov));
    nst_memzero(&msg, sizeof(msg));
    iov.iov_base = crap_data_buf;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ndumped = 0;
    while(conn->flags.closed) {
        if(ctrl_received[NST_TP_CTRL_TYPE_SYN]
           && !nst_tp_conn_is_urgent_received(tp_conn)) {
                iov.iov_len = sizeof(crap_data_buf);
        } else {
                iov.iov_len = 1;
        }
	if (sockatmark(conn->fd)) /* check if urgent byte has been received. This part is hit only on the cproxy: Madhu*/
        {
            NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s received urgent data",
                         nst_connection_get_brief_str(conn));

            iov.iov_len = 1;
            n = nst_recvmsg(conn, &msg, 1, 0);
            msg.msg_flags = MSG_OOB;
        }
       else
       {
            n = nst_recvmsg(conn, &msg, iov.iov_len, 0);
            msg.msg_flags = 0;
       }

        if(n == NST_ERROR) {
            nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
            return NST_ERROR;
        } else if(n == NST_AGAIN) {
            return NST_OK;
        } else if(n == 0) {
            conn->flags.io_eof = tp_conn->flags.io_eof = 1;
            return NST_DONE;
        }

        nst_assert(n > 0);

        if(ctrl_received[NST_TP_CTRL_TYPE_SYN]
           && !nst_tp_conn_is_urgent_received(tp_conn) 
           && !(msg.msg_flags & MSG_OOB)) {
            /* we got SYN and 
             * not yet getting urgent FIN/RST and
             * the new data is not urgent
             * ==> it is the app left over data, dump it
             */

            /* dump the app data */
            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                          "dumped %d bytes left over app data",
                          n);
            tp_conn->ndumped_app_bytes += n;
            ndumped += n;
            if(tp_conn->ndumped_app_bytes > NST_TP_MAX_NDUMPED_APP_BYTES) {
                tp_conn->flags.int_error = 1;
                tp_conn->int_error_str = "dumped too much left over app data.";
                return NST_ERROR;
            } else if(ndumped > NST_TP_MAX_NDUMPED_APP_BYTES_PER_LOOP) {
                NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                              "c#:%ui dumped too much left over app data "
                              "in this event. postpone",
                              conn->number);
                nst_event_postpone(conn->read);
                return NST_OK;
            } else {
                /* keep reading */
                continue;
            }
        } else {
            nst_status_e ret;
            nst_assert(n == 1);
            /* n == 1 */

            ret = nst_tp_conn_received_ctrl_byte(tp_conn,
                                                 crap_data_buf[0],
                                                 msg.msg_flags & MSG_OOB);
            if(ret != NST_OK
               ||
               crap_data_buf[0] == NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_SYN, 0)
               ||
               crap_data_buf[0] == NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_OOB_ACK, 0)
               ) {
                return ret;
            }
            /* read till we got TP OOB_ACK or TP SYN or error out */
        }
    } /* while (TRUE) */

    return NST_OK;
}

/* Handle the read event. It should only be used when
 * 1. the tp_conn is in free/pending queue.
 * OR
 * 2. the apps has given up the read event by calling
 *    nst_connection_disable_read()
 */
static void
nst_tp_read_handler(nst_event_t *rev)
{
    nst_connection_t *conn = (nst_connection_t *)rev->data;
    nst_tp_connection_t *tp_conn = conn->tp_conn;

    nst_assert(conn->flags.closed);

    if(nst_event_is_timedout(rev)) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "%s read event timedout out when in mp-status:%s",
                      nst_connection_get_brief_str(conn),
                      nst_tp_conn_status_to_str(tp_conn->status));
        tp_conn->flags.int_error = 1;
        tp_conn->int_error_str = "timed out when reading TP FIN";
        nst_tp_conn_move_to_free_queue(tp_conn);
        return;
    }

    if(nst_tp_conn_recv_ctrl_byte(tp_conn) != NST_OK) {
        nst_tp_conn_free(tp_conn);
        return;
    }

    if(nst_tp_conn_is_urgent_received(tp_conn)
       && !nst_tp_conn_is_oob_ack_out(tp_conn)) {
        /* we probably have just received the urgent byte */
        if(nst_tp_conn_send_ctrl_byte(tp_conn,
                    NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_OOB_ACK, 0)) != NST_OK) {
            nst_tp_conn_free(tp_conn);
            return;
        }
    }

    nst_tp_conn_move_to_queue(tp_conn);
}


/* A TP SYN has been received from a free passive connection
 * tp_conn may be free-ed if there is error when sending TP SYN
 */
static void
nst_tp_conn_passive_idle_accept(nst_tp_connection_t *tp_conn)
{
    nst_connection_t *conn = tp_conn->parent;

    nst_tp_conn_remove_from_free_queue(tp_conn);
    tp_conn->status = NST_TP_CONN_STATUS_OPEN;
    nst_assert(conn->flags.closed == 1);

    conn->read->ready = 1; /* The TP SYN is sent just before data is sent,
                            * so the data must be ready.  Please see
                            * the nst_tp_send() function.
                            */
    conn->write->ready = 1; /* Lets to be a bit aggressive and it should be
                             * usually ready
                             */
    if(conn->pool == NULL) {
        conn->pool = nst_create_pool(event_ctx.cfg.connection_pool_size,
                                     &nst_dl_logger);
    }

    if(nst_tp_conn_send_ctrl_byte(tp_conn,
                                  NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_SYN, 0))
       == NST_OK) {
        nst_tp_conn_ctx.nopen_passive++;

        /* transferring control to the apps */
        conn->flags.closed = 0; /* never move this statement after 
                           * nst_tp_conn_send_ctrl_byte()
                           */
        conn->read->handler = NULL;
        conn->write->handler = NULL;
        NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s accepted passive TP conn",
                         nst_connection_get_dbg_str(tp_conn->parent));
        nst_tp_conn_ctx.conn_handler(conn);
    } else {
        NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                      "%s failed to accept passive TP conn",
                      nst_connection_get_dbg_str(tp_conn->parent));
        nst_tp_conn_free(tp_conn);
    }
}

/* A newly accepted TCP connection */
void
nst_tp_passive_accept_handler(nst_connection_t *conn)
{
    /* we get a newly accepted TCP connection */
    nst_tp_connection_t *tp_conn;

    if(nst_tp_conn_ctx.ntp_connections >= event_ctx.cfg.max_ntp_connections) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "max num of TP connections (%ui) reached",
                    event_ctx.cfg.max_ntp_connections);
                    
        if(nst_tp_conn_free_from_lru() == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "max num of TP connections (%ui) reached and cannot "
                        "free from LRU. rejecting %s",
                        event_ctx.cfg.max_ntp_connections,
                        nst_connection_get_dbg_str(conn));
        }
        nst_unix_close(conn, NST_IO_CLOSE_REASON_OK);
        return;
    }
    
    if(nst_tp_conn_ctx.conn_acl && !nst_tp_conn_ctx.conn_acl(conn)) {
        nst_unix_close(conn, NST_IO_CLOSE_REASON_ERROR);
        return;
    }

    tp_conn = nst_mempool_alloc(nst_tp_conn_ctx.tp_conn_mempool);
    if(!tp_conn) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot get nst_tp_connection_t object from mempool");
        nst_unix_close(conn, NST_IO_CLOSE_REASON_OK);
        return;
    }

    nst_tp_conn_passive_init(tp_conn, conn);

    conn->data = NULL;
    conn->read->handler = nst_tp_read_handler;
    conn->write->handler = nst_tp_write_handler;

    /* We assume deferred accept is always
     * ON.
     *
     * It should fall through to
     * nst_tp_conn_passive_idle_accept.
     */
    if(nst_tp_conn_recv_ctrl_byte(tp_conn) != NST_OK)
        nst_tp_conn_free(tp_conn);
}

/* Initialize the TP layer */
void
nst_tp_init(nst_connection_handler_f conn_handler,
            nst_connection_acl_f conn_acl)
{
    nst_memzero(&nst_tp_conn_ctx, sizeof(nst_tp_conn_ctx));
    nst_tp_conn_ctx.tp_conn_mempool = 
        nst_mempool_create("TP CONN POOL", TRUE,
                           event_ctx.cfg.max_ntp_connections,
                           event_ctx.cfg.max_ntp_connections,
                           sizeof(nst_tp_connection_t),
                           FALSE);
    nst_assert(nst_tp_conn_ctx.tp_conn_mempool);

    TAILQ_INIT(&nst_tp_conn_ctx.passive_queue);
    TAILQ_INIT(&nst_tp_conn_ctx.lru_queue);
    TAILQ_INIT(&nst_tp_conn_ctx.pending_queue);

    nst_tp_conn_ctx.conn_handler = conn_handler;
    nst_tp_conn_ctx.conn_acl = conn_acl;
}

static void
nst_tp_remove_all_passive_conn(void)
{
    nst_tp_connection_t *tp_conn;
    nst_tp_connection_t *tmp_tp_conn;

    TAILQ_FOREACH_SAFE(tp_conn,
                       &nst_tp_conn_ctx.passive_queue,
                       queue_entry,
                       tmp_tp_conn) {
        nst_tp_conn_free(tp_conn);
    }

    TAILQ_FOREACH_SAFE(tp_conn,
                       &nst_tp_conn_ctx.pending_queue,
                       queue_entry,
                       tmp_tp_conn) {
        nst_tp_conn_free(tp_conn);
    }
}

void
nst_tp_reset(void)
{
    /* TODO: free the pending connections */

    if(nst_tp_conn_ctx.tp_conn_mempool) {
        nst_tp_remove_all_passive_conn();
        nst_mempool_destroy(nst_tp_conn_ctx.tp_conn_mempool);
    }
}

void
nst_connection_disable_read(nst_connection_t *conn)
{
    nst_tp_connection_t *tp_conn;

    if(conn->type != NST_CONN_TYPE_TP)
        return;

    tp_conn = (nst_tp_connection_t *)conn->tp_conn;
    nst_assert(!conn->flags.closed);

    tp_conn->flags.app_read_disabled = 1;
    conn->read->handler = nst_tp_read_handler;
    nst_handle_read_event(conn->read, 0);
}

void
nst_connection_enable_read(nst_connection_t *conn,
                           nst_event_handler_f handler)
{
    nst_tp_connection_t *tp_conn;

    if(conn->type != NST_CONN_TYPE_TP)
        return;

    tp_conn = (nst_tp_connection_t *)conn->tp_conn;
    nst_assert(!conn->flags.closed);

    tp_conn->flags.app_read_disabled = 0;
    conn->read->handler = handler;
    nst_handle_read_event(conn->read, 0);
}

static inline nst_status_e
nst_tp_send_common(nst_tp_connection_t *tp_conn, nst_connection_t *conn)
{
    ssize_t n;
    size_t old_nsent = conn->nsent;

    if(nst_tp_conn_is_fin_or_rst_out(tp_conn)) {
        /* We sent TP FIN and/or MR RST. return with EPIPE error */
        nst_connection_set_io_errno(conn, EPIPE);
        return NST_ERROR;
    } else if(tp_conn->io_errno) {
        nst_connection_set_io_errno(conn, tp_conn->io_errno);
        return NST_ERROR;
    } else if(tp_conn->flags.int_error) {
        nst_connection_set_io_errno(conn, NST_ECONN_TP);
        return NST_ERROR;
    } 

    if(tp_conn->npending_ctrl_bytes) {
        /* Send the pending TP SYN */
        nst_assert(tp_conn->npending_ctrl_bytes == 1);
        nst_assert(tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_SYN]);
        n = nst_send(conn, &tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_SYN], 1, 0);
        if(n == NST_ERROR) {
            nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
            return n;
        } else if(n == NST_AGAIN) {
            return n;
        } else {
            nst_assert(n == 1);
            conn->nsent = old_nsent;
            tp_conn->ctrl_sent[NST_TP_CTRL_TYPE_SYN] =
                tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_SYN];
            tp_conn->ctrl_pending[NST_TP_CTRL_TYPE_SYN] = 0;
            tp_conn->npending_ctrl_bytes--;
        }
    }

    return NST_OK;
}

/* It is for the upper layer to write data to the socket.
 *
 * It should only be called by upper layer!
 */
ssize_t
nst_tp_send(nst_connection_t *conn, const u_char *buf, size_t size, int flags)
{
    ssize_t n;
    nst_tp_connection_t *tp_conn = (nst_tp_connection_t *)conn->tp_conn;

    nst_assert(tp_conn);
    nst_assert(!conn->flags.closed);
    nst_assert(size);
    nst_assert(flags);

    n = nst_tp_send_common(tp_conn, conn);
    if(n != NST_OK)
        return n;

    /* All clear! Send out the app data now! */
    n = nst_send(conn, buf, size, 0);
    if(n == NST_ERROR) {
        nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
        return NST_ERROR;
    } else {
        return n;
    }
}

/* It is for the upper layer to write data to the socket.
 *
 * It should only be called by upper layer!
 */
ssize_t
nst_tp_writev_chain(nst_connection_t *conn, nst_iochain_t *in)
{
    ssize_t n;
    nst_tp_connection_t *tp_conn = (nst_tp_connection_t *)conn->tp_conn;

    nst_assert(tp_conn);
    nst_assert(!conn->flags.closed);
    nst_assert(nst_iochain_get_data_len(in) > 0);

    n = nst_tp_send_common(tp_conn, conn);
    if(n != NST_OK)
        return n;

    /* All clear! Send out the app data now! */
    n = nst_send_chain(conn, in);
    if(n == NST_ERROR) {
        nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
        return NST_ERROR;
    } else {
        return n;
    }
}

/* It is for the upper layer to read data from the socket.  It will filter
 * out the urgent byte.
 *
 * It should only be called by upper layer!
 */
ssize_t
nst_tp_recv(nst_connection_t *conn, u_char *buf, size_t size)
{
    ssize_t n;
    size_t old_nread;
    u_char saved_byte;
    nst_tp_connection_t *tp_conn = (nst_tp_connection_t *)conn->tp_conn;
    const u_char *ctrl_received = tp_conn->ctrl_received;
    struct iovec iov = { buf, size };
    struct msghdr msg = { 0, 0, &iov, 1, 0, 0, 0 };
    bool received_oob = FALSE;

    if(!conn->read->ready) {
        NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "%s not ready",
                         nst_connection_get_brief_str(conn));
        return NST_AGAIN;
    }

    /* TP RST can only be sent after app later has given up control on 
     * the TP connection and nst_tp_recv can only be called by app only.
     * Note: even for ssl TP, the opnessl will only read upon the app request.
     */
    nst_assert(!conn->flags.closed);
    nst_assert(size);

    old_nread = conn->nread;
    while(!ctrl_received[NST_TP_CTRL_TYPE_SYN]) {
        /* If the active connection have not received TP SYN, we will
         * try to read it here.
         */
        u_char mp_ctrl_byte;
        nst_assert(tp_conn->type == NST_TP_CONN_TYPE_ACTIVE);
        n = nst_recv(conn, &mp_ctrl_byte, 1);
        if(n == 1) {
            if(nst_tp_conn_received_ctrl_byte(tp_conn, mp_ctrl_byte, FALSE) == NST_ERROR) {
                return NST_ERROR;
            } else {
                conn->nread = old_nread;
                /* Fall through to receive app data */
                break;
            }
        } else if(n == NST_ERROR) {
            nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
            return n;
        } else if(n == NST_AGAIN) {
            return n;
        } else {
            nst_assert(n == 0);
            conn->flags.io_eof = tp_conn->flags.io_eof = 1;
            return 0;
        }
    }

    if(nst_tp_conn_is_urgent_received(tp_conn)) {
        if(ctrl_received[NST_TP_CTRL_TYPE_RST]) {
            return NST_ERROR;
        } else {
            conn->flags.io_eof = 1;
            return 0;
        }
    } else if(tp_conn->flags.io_eof) {
        conn->flags.io_eof = 1;
        return 0;
    } else if(tp_conn->flags.int_error) {
        nst_connection_set_io_errno(conn, NST_ECONN_TP);
        return NST_ERROR;
    }

 HANDLE_RECEIVED_CTRL_BYTE:
    if(tp_conn->flags.int_error) {
        nst_connection_set_io_errno(conn, NST_ECONN_TP);
        return NST_ERROR;
    }

    /* have we received TP FIN or TP RST */
    if(ctrl_received[NST_TP_CTRL_TYPE_RST]) {
        /* Always! Always! Always! check TP RST first!!!! */
        /* We got TP RST */
        return NST_ERROR;
    } else if(ctrl_received[NST_TP_CTRL_TYPE_FIN]) {
        /* We got TP FIN */
        return 0;
    } /* else if(nst_tp_is_ctrl_type_out(NST_TP_CTRL_TYPE_RST)) {
        conn->io_errno = ECONNRESET;
        return NST_ERROR;
        }*/
    nst_assert(!received_oob);

    saved_byte = buf[0];
    if (sockatmark(conn->fd))
    {
	    NST_DEBUG_LOG_OV(conn->dbg_log_lvl,
			    NST_LOG_LEVEL_DEBUG,
			    "%s received urgent data",
			    nst_connection_get_brief_str(conn));
	    iov.iov_len = 1;
	    n = nst_recvmsg(conn, &msg, 1, 0);
	    msg.msg_flags = MSG_OOB;
    }
    else
    {
	    n = nst_recvmsg(conn, &msg, size, 0);
	    msg.msg_flags = 0;
    }
    if(n == NST_AGAIN) {
        return n;
    } else if(n == NST_ERROR) {
        nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
        return NST_ERROR;
    } else if(n == 0) {
        conn->flags.io_eof = tp_conn->flags.io_eof = 1;
        return 0;
    }
 
    if(msg.msg_flags & MSG_OOB) {
        u_char mp_ctrl_byte;

        /* we must have already setsockops the SO_OOBINLINE_TELL, so
         * ret can only be 1
         */
        nst_assert(n == 1);

        conn->nread = old_nread;

        mp_ctrl_byte = buf[0];
        buf[0] = saved_byte;
        if(nst_tp_conn_received_ctrl_byte(tp_conn, mp_ctrl_byte, TRUE) == NST_ERROR) {
            conn->io_errno = NST_ECONN_TP;
            return NST_ERROR;
        }
        received_oob = TRUE;
        /* ..ok..i know i know it is ugly */
        goto HANDLE_RECEIVED_CTRL_BYTE;
    } else {
        /* return to the app */
        return n;
    }
}

int
nst_tp_connect(nst_connection_t **conn, 
               nst_sockaddr_t *local_sockaddr,
               int tcp_ext,
               nst_uint_t tid,
               nst_log_level_t noc_log_lvl,
               nst_log_level_t dbg_log_lvl,
               nst_cfg_sproxy_t *sproxy,
               bool ssl)
{
  nst_tp_connection_t * tp_conn;
  nst_connection_t    * c;
   
  tp_conn = nst_tp_get_pooled_conn (sproxy);

    if(tp_conn == NULL) {
        int ret;
        
        if(nst_tp_conn_ctx.ntp_connections >= event_ctx.cfg.max_ntp_connections
           && nst_tp_conn_free_from_lru() == NST_ERROR) {
            NST_NOC_LOG_OV(noc_log_lvl,
                           NST_LOG_LEVEL_ERROR,
                           "num of TP connections >= %ui and "
                           "cannot free from LRU",
                           event_ctx.cfg.max_ntp_connections);
        }

        ret = nst_unix_connect(conn,
                               &sproxy->mp_listen_sockaddr, 
                               local_sockaddr,
                               tcp_ext,
                               tid,
                               noc_log_lvl,
                               dbg_log_lvl);
        if(ret == NST_AGAIN || ret == NST_OK) {
            nst_tp_connection_t *tp_conn;
            nst_connection_t *c;

            c = *conn;
            c->type = NST_CONN_TYPE_TP;
            if(nst_init_tp_sockfd(c->fd) == NST_ERROR) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                       "nst_tp_connect() to %s:%s failed. "
                       "setsockops failed.",
                       nst_sockaddr_get_ip_str(&sproxy->mp_listen_sockaddr),
                       nst_sockaddr_get_port_str(&sproxy->mp_listen_sockaddr));
                nst_unix_close(*conn, NST_IO_CLOSE_REASON_CONN_ERROR);
                return NST_ERROR;
            }

            tp_conn = nst_mempool_alloc(nst_tp_conn_ctx.tp_conn_mempool);
            if(!tp_conn) {
                NST_NOC_LOG_OV(noc_log_lvl,
                               NST_LOG_LEVEL_ERROR,
                               "cannot get new nst_connection_t object for "
                               "TP conn. max num of connections reached?");
                nst_unix_close(*conn, NST_IO_CLOSE_REASON_MALLOC_FAILURE);
                return NST_ERROR;
            }

            nst_tp_conn_active_init(tp_conn, c, sproxy);
            if(nst_tp_conn_send_ctrl_byte(tp_conn,
                                          NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_SYN, 0))
               == NST_ERROR) {
                nst_tp_conn_free(tp_conn);
                return NST_ERROR;
            } else {
                /* transferring ownership to apps */
                nst_tp_conn_ctx.nopen_active++;
                c->flags.closed = 0;
                return ret;
            }

        } else {
            *conn = NULL;
            return NST_ERROR;
        }
    } else { /* We want a connection from the pool */
        nst_tp_connection_t  * old_tp_conn = tp_conn;
        c = *conn = old_tp_conn->parent;

        nst_assert(c->flags.closed == 1);

        c->read->handler = NULL;
        c->write->handler = NULL;

        c->tid = tid;
        c->write->ready = 1;
        c->noc_log_lvl = noc_log_lvl;
        c->dbg_log_lvl = dbg_log_lvl;

        NST_DEBUG_LOG_OV(dbg_log_lvl,
                         NST_LOG_LEVEL_DEBUG,
                         "Reusing connection c#:%ui for t#:%ui (%s:%s->%s:%s) "
                         "for TP connecting to %s",
                         c->number, c->tid,
                         nst_sockaddr_get_ip_str(&c->local_sockaddr),
                         nst_sockaddr_get_port_str(&c->local_sockaddr),
                         nst_sockaddr_get_ip_str(&c->peer_sockaddr),
                         nst_sockaddr_get_port_str(&c->peer_sockaddr),
                         sproxy->sysid);

        if(nst_tp_conn_send_ctrl_byte(old_tp_conn,
                                      NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_SYN, 0))
           == NST_ERROR) {
            nst_tp_conn_free(old_tp_conn);
            *conn = NULL;
            return NST_ERROR;
        } else {
            nst_assert(!tp_conn->flags.new_tcp_conn);
            /* transferring ownership to apps */
            nst_tp_conn_ctx.nopen_active++;
            c->flags.closed = 0;

            return NST_OK;
        }
    }
}

nst_status_e
nst_tp_close(nst_connection_t *conn, nst_io_close_reason_e reason)
{
    u_char mp_ctrl_byte;
    nst_tp_connection_t *tp_conn = (nst_tp_connection_t *)conn->tp_conn;

    nst_assert(!conn->flags.closed);
    nst_assert(reason < 0x00FF);
    conn->tid = 0;

    nst_event_del_timer(conn->read);
    nst_event_del_timer(conn->write);
    nst_event_clear_timedout(conn->read);
    nst_event_clear_timedout(conn->write);

    if(tp_conn->type == NST_TP_CONN_TYPE_ACTIVE) {
        nst_assert(conn->is_upstream == 1);
        nst_assert(!conn->pool);
        nst_tp_conn_ctx.nopen_active--;
    } else {
        if(conn->pool) {
            nst_destroy_pool(conn->pool);
            conn->pool = NULL;
        }
        nst_tp_conn_ctx.nopen_passive--;
    }

    if(!nst_tp_conn_is_reusable(tp_conn)) {
        nst_tp_conn_free(tp_conn);
        return NST_OK;
    }

    if(reason) {
        /* reason != 0 ==> close on error ==> we sent TP RST */
        mp_ctrl_byte = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_RST, reason);
    } else {
        mp_ctrl_byte = NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_FIN, reason);
    }
    
    /* Now, we are trying to move the tp_conn to the right queue */

    /* we can only send and recv ctrl bytes if conn->closed is set */
    conn->flags.closed = 1;

    if(nst_tp_conn_send_ctrl_byte(tp_conn, mp_ctrl_byte) != NST_OK) {
        nst_tp_conn_free(tp_conn);
        return NST_OK;
    }

    /* read the TP SYN if we haven't got one */
    if(!nst_tp_conn_is_syn_received(tp_conn)) {
        nst_assert(tp_conn->type == NST_TP_CONN_TYPE_ACTIVE);
        /* try to read the SYN byte */
        if(nst_tp_conn_recv_ctrl_byte(tp_conn) != NST_OK) {
            nst_tp_conn_free(tp_conn);
            return NST_OK;
        }
    }

    /* read the OOB byte if we haven't got one */
    if(!nst_tp_conn_is_urgent_received(tp_conn)) {
        /* try to read the urgent byte */
        if(nst_tp_conn_recv_ctrl_byte(tp_conn) != NST_OK) {
            nst_tp_conn_free(tp_conn);
            return NST_OK;
        }
    } 

    /* send out the OOB ACK if we received OOB and haven't sent out OOB ACK */
    if(nst_tp_conn_is_urgent_received(tp_conn)
       && !nst_tp_conn_is_oob_ack_out(tp_conn)) {
        if(nst_tp_conn_send_ctrl_byte(tp_conn,
                     NST_TP_CTRL_BYTE(NST_TP_CTRL_TYPE_OOB_ACK, 0)) != NST_OK) {
            nst_tp_conn_free(tp_conn);
            return NST_OK;
        }
    }

    /* read the OOB ACK if we haven't got one and we did send out OOB */
    if(nst_tp_conn_is_urgent_sent(tp_conn)
       && !nst_tp_conn_is_oob_ack_received(tp_conn)) {
        if(nst_tp_conn_recv_ctrl_byte(tp_conn) != NST_OK) {
            nst_tp_conn_free(tp_conn);
            return NST_OK;
        }
    }

    /* move to pending queue or free queue */
    nst_tp_conn_move_to_queue(tp_conn);

    return NST_OK;
}

void
nst_tp_log_stats(void)
{
    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "total mp-conn: %ui "
                "active: (open:%ui idle:%ui) passive: (open:%ui idle:%ui)",
                nst_tp_conn_ctx.ntp_connections,
                nst_tp_conn_ctx.nopen_active,
                nst_tp_conn_ctx.nidle_active,
                nst_tp_conn_ctx.nopen_passive,
                nst_tp_conn_ctx.nidle_passive);
}

nst_io_close_reason_e
nst_tp_errno_to_close_reason(int local_errno, bool peer)
{
    if(!local_errno)
        return NST_IO_CLOSE_REASON_OK;

    switch(local_errno) {
    case NST_ECONN_PEER_ERROR:
        return (peer ? NST_IO_CLOSE_REASON_FWD_ERROR : 0);
    case NST_ECONN_PEER_FWD_ERROR:
        return (peer ? NST_IO_CLOSE_REASON_FWD_ERROR : 0);
    case EPIPE:
    case ECONNRESET:
    case NST_ECONN_PEER_RST:
    case NST_ECONN_PEER_FWD_RST:
        return (peer ? NST_IO_CLOSE_REASON_FWD_RST : 0);
    case ETIMEDOUT:
    case NST_ECONN_RTIMEDOUT:
    case NST_ECONN_WTIMEDOUT:
        return (peer ?
                NST_IO_CLOSE_REASON_FWD_TIMEDOUT
                : NST_IO_CLOSE_REASON_TIMEDOUT);
    case NST_ECONN_PEER_TIMEDOUT:
    case NST_ECONN_PEER_FWD_TIMEDOUT:
        return (peer ? NST_IO_CLOSE_REASON_FWD_TIMEDOUT : 0);
    case NST_ECONN_TP:
    default:
        return (peer ? NST_IO_CLOSE_REASON_FWD_ERROR : NST_IO_CLOSE_REASON_ERROR);
    }
}

static void
nst_tp_set_io_eof_from_ev(nst_connection_t *c)
{
    nst_tp_connection_t *tp_conn = c->tp_conn;

    nst_assert(tp_conn);
    nst_assert(c->type == NST_CONN_TYPE_TP);

    c->flags.io_eof_from_ev = tp_conn->flags.io_eof_from_ev = 1;
}

static nst_tp_connection_t *
nst_tp_get_pooled_conn (nst_cfg_sproxy_t *sproxy)
{
    nst_tp_connection_t   * old_tp_conn = NULL;
    old_tp_conn = TAILQ_FIRST(&sproxy->active_queue);

    if (old_tp_conn != NULL) { 
        nst_tp_conn_remove_from_free_queue(old_tp_conn);
        nst_assert(old_tp_conn->status == NST_TP_CONN_STATUS_FREE);
        old_tp_conn->status = NST_TP_CONN_STATUS_OPEN;

        return old_tp_conn;
    }
        
    return NULL;
}
static void
nst_tp_conn_active_free_read_till_eagain(nst_tp_connection_t *tp_conn,
                                         nst_connection_t *conn)
{
    u_char byte;
    ssize_t n;
    struct iovec iov;
    struct msghdr msg;
    size_t nread = 0;

    nst_memzero(&iov, sizeof(iov));
    nst_memzero(&msg, sizeof(msg));

    iov.iov_base = &byte;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        n = nst_unix_recvmsg(conn, &msg, 1, 0);
        if(n == NST_AGAIN) {
            /* most common case */
            return;
        } else if(n == 1) {
            if(nst_tp_conn_received_ctrl_byte(tp_conn, byte,
                                              msg.msg_flags & MSG_OOB)) {
                nst_tp_conn_free(tp_conn);
                return;
            }
            nread++;
        } else if(n == 0) {
            conn->flags.io_eof = tp_conn->flags.io_eof = 1;
            nst_tp_conn_free(tp_conn);
            return;
        } else {
            nst_tp_conn_set_io_errno(tp_conn, conn->io_errno);
            nst_tp_conn_free(tp_conn);
            return;
        }            
    } while(nread < NST_TP_CONN_MAX_ACTIVE_GARBAGE_CTRL_BYTE);

    NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                  "%V received too many garbage ctrl bytes",
                  nst_connection_get_dbg_str(conn));
    tp_conn->flags.int_error = 1;
    tp_conn->int_error_str = "too many garbage ctrl bytes";
    nst_tp_conn_free(tp_conn);
}

