#ifndef _NST_CONNECTION_H_
#define _NST_CONNECTION_H_

#include <nst_config.h>

#include "nst_io_ops.h"
#include "nst_event_common.h"

#include <nst_sockaddr.h>
#include <nst_log.h>
#include <nst_assert.h>
#include <nst_errno.h>

struct nst_pool_s;
struct nst_buf_s;
struct nst_tp_connection_s;
struct nst_cfg_svc_s;

typedef struct nst_connection_s nst_connection_t;
typedef enum nst_conn_type_e nst_conn_type_e;
typedef void (*nst_connection_handler_f)(nst_connection_t *c);

/* should a connection be accepted. for example, we should only accept
 * TP connection from our cpproxy by IP ACL.
 *
 * TRUE:  allow
 * FALSE: deny
 */
typedef bool (*nst_connection_acl_f)(const nst_connection_t *c);

enum nst_conn_type_e {
    NST_CONN_TYPE_UNKNOWN       = 0,
    NST_CONN_TYPE_TCP           = 1,
    NST_CONN_TYPE_TP            = 2,
    NST_CONN_TYPE_UNIX          = 3,
    NST_CONN_TYPE_PIPE          = 4,
    NST_CONN_TYPE_RTNETLINK     = 5,
    _NUM_NST_CONN_TYPE          = 6,
};

struct nst_connection_s {
    nst_conn_type_e  type;

    void                  *data;
    struct nst_event_s    *read;
    struct nst_event_s    *write;

    int                    fd;

    nst_io_ops_t          *io_ops; /* overrided according to connection type */

    struct nst_pool_s *pool;

    nst_sockaddr_t     local_sockaddr;
    nst_sockaddr_t     peer_sockaddr;

    struct nst_cfg_svc_s  *svc; /* only for passively accepted connection */

    nst_uint_t          number;         /* connection number */
    nst_uint_t          tid;            /* transaction number
                                         * (e.g. HTTP request number)
                                         */
    nst_log_level_t     noc_log_lvl;
    nst_log_level_t     dbg_log_lvl;

    int                 io_errno;     /* what is the errno for the last
                                       * socket io operation.
                                       */

    size_t              nsent;
    size_t              nread;

    unsigned            postponed_free:1; /* either read or write event
                                           * is in postponed_queue. we
                                           * need to postpone the free
                                           * also
                                           */
    unsigned            is_upstream:1;     /* is it a upstream connection?
                                           * => i.e. we are actively
                                           *    making this connection
                                           *    by calling connect()
                                           */

    struct {
        unsigned            io_eof:1; /*!< detected eof (i.e. TCP FIN or TP FIN)
                                       *   from peer by recv().
                                       */
        unsigned            closed:1;        /*!< app closed the connection? */
        unsigned            shutdown:1;      /*!< did we send FIN? */
        unsigned            io_eof_from_ev:1; /*!< detected eof by 
                                               *   EPOLLRDHUP for TCP
                                               *   or
                                               *   EPOLLURG for TP
                                               */
        unsigned            io_err_from_ev:1; /*!< detected io_eof by EPOLLERR
                                               */
        unsigned            connected:1;
    } flags;
    /* unsigned            unexpected_eof:1; */ /* ML on NGX: I totally have no
                                           * idea how is it used
                                           */
    /* unsigned            destroyed:1; */
    /* unsigned            buffered:8; */
    /* unsigned            timedout:1; */
    /* unsigned            idle:1; */

    
    struct nst_tp_connection_s *tp_conn; /* An object contains TP connection
                                          * related valuables.
                                          *
                                          * Think of it as an extension to
                                          * the socket connection.
                                          *
                                          * It will be NULL for
                                          * non TP connection.
                                          */

    /* nst_ssl_connection_t *ssl_conn; */ /* tmp remove */
};

nst_connection_t *nst_get_connection(int fd);
void nst_free_connection(nst_connection_t *c);
void nst_do_free_connection(nst_connection_t *c);
int nst_connection_add_toeventq (nst_connection_t * c);
const char *nst_connection_get_brief_str(const nst_connection_t *c);
const char *nst_connection_get_dbg_str(const nst_connection_t *c);

static inline
void nst_connection_set_io_errno(nst_connection_t *c, int io_errno)
{
    if(c->io_errno == 0) {
        c->io_errno = io_errno;
    }
}

nst_connection_t *nst_get_connection(int fd);
void nst_free_connection(nst_connection_t *c);
void nst_do_free_connection(nst_connection_t *c);
int nst_connection_add_toeventq (nst_connection_t * c);
const char *nst_connection_get_brief_str(const nst_connection_t *c);
const char *nst_connection_get_dbg_str(const nst_connection_t *c);
int nst_connection_rtt (const nst_connection_t * conn);
#endif /* #ifndef _NST_CONNECTION_H_ */
