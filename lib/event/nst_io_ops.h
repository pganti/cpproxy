#ifndef _NST_IO_OPS_H_
#define _NST_IO_OPS_H_

#include <nst_types.h>

#include <sys/types.h>

struct nst_iochain_s;
struct nst_connection_s;

typedef enum nst_io_close_reason_e nst_io_close_reason_e;

typedef struct nst_io_ops_s nst_io_ops_t;
typedef struct nst_int_io_ops_s nst_int_io_ops_t;

typedef ssize_t (*nst_recv_f)(struct nst_connection_s *c,
                              u_char *buf, size_t size);
/*
typedef ssize_t (*nst_recv_chain_f)(struct nst_connection_s *c,
                                    struct nst_chain_s *in);
*/
typedef ssize_t (*nst_send_f)(struct nst_connection_s *c,
                              const u_char *buf, size_t size, int flags);
typedef ssize_t (*nst_send_chain_f)(struct nst_connection_s *c,
                                                struct nst_iochain_s *in);
typedef nst_status_e (*nst_close_f)(struct nst_connection_s *c,
                                    nst_io_close_reason_e close_reason);
typedef nst_status_e (*nst_shutdown_f)(struct nst_connection_s *c);

typedef void (*nst_set_io_eof_f)(struct nst_connection_s *c);

enum nst_io_close_reason_e
{
    NST_IO_CLOSE_REASON_OK        = 0, /* just normal close */

    NST_IO_CLOSE_REASON_ERROR     = 1, /* A catch all proxy error */

    NST_IO_CLOSE_REASON_FWD_ERROR = 2, /* error on the other side
                                        * of connection
                                        */

    NST_IO_CLOSE_REASON_RST       = 3, /* app would like to close by
                                        * RST
                                        */

    NST_IO_CLOSE_REASON_FWD_RST   = 4,   /* forward RST from the other side */
    NST_IO_CLOSE_REASON_TIMEDOUT       = 5,
    NST_IO_CLOSE_REASON_FWD_TIMEDOUT   = 6,

    /* WARNING! anything < 16 is reserved for TP and TP only */
    NST_IO_CLOSE_REASON_TP_RESERVED_8  = 7,
    NST_IO_CLOSE_REASON_TP_RESERVED_7  = 8,
    NST_IO_CLOSE_REASON_TP_RESERVED_6  = 9,
    NST_IO_CLOSE_REASON_TP_RESERVED_5  = 10,
    NST_IO_CLOSE_REASON_TP_RESERVED_4  = 11,
    NST_IO_CLOSE_REASON_TP_RESERVED_3  = 12,
    NST_IO_CLOSE_REASON_TP_RESERVED_2  = 13,
    NST_IO_CLOSE_REASON_TP_RESERVED_1  = 14,
    NST_IO_CLOSE_REASON_TP_RESERVED_0  = 15,

    NST_IO_CLOSE_REASON_NBSET_FAILED = 16,/* setting of non blocking failed */
    NST_IO_CLOSE_REASON_EVADD_FAILED = 17,/* Event addition failed */
    NST_IO_CLOSE_REASON_CONN_ERROR   = 18,
    NST_IO_CLOSE_REASON_MALLOC_FAILURE = 19,/* Malloc failure */
    NST_IO_CLOSE_REASON_APP_GONE = 20,
    _NST_IO_CLOSE_REASON_NUM = 21,
};

struct nst_io_ops_s {
    nst_recv_f         recv;
    /* nst_recv_chain_f   recv_chain; */
    nst_recv_f         udp_recv;
    nst_send_f         send;
    nst_send_chain_f   send_chain;
    nst_close_f        close;
    nst_shutdown_f     shutdown;
};

struct nst_int_io_ops_s {
    nst_set_io_eof_f    set_io_eof_from_ev;
};

#endif
