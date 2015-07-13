#include "nst_unix_io_ops.h"

#include "nst_unix_close.h"
#include "nst_connection.h"

#include <nst_types.h>

#include <sys/types.h>

struct nst_connection_s;
struct nst_iochain_s;
struct msghdr;

ssize_t nst_unix_recv(struct nst_connection_s *c, u_char *buf, size_t size);
ssize_t nst_unix_readv_chain(struct nst_connection_s *c,
                             struct nst_iochain_s *chain);
ssize_t nst_udp_unix_recv(struct nst_connection_s *c, u_char *buf, size_t size);
ssize_t nst_unix_send(struct nst_connection_s *c, const u_char *buf, size_t size, int flags);
ssize_t nst_unix_writev_chain(struct nst_connection_s *c,
                              struct nst_iochain_s *in);
nst_status_e nst_unix_shutdown(struct nst_connection_s *c);

void nst_unix_set_io_eof_from_ev(struct nst_connection_s *c);

nst_io_ops_t nst_unix_io_ops = {
    .recv        = nst_unix_recv,
    /* .recv_chain  = nst_unix_readv_chain, */
    .udp_recv    = nst_udp_unix_recv,
    .send        = nst_unix_send,
    .send_chain  = nst_unix_writev_chain,
    .close       = nst_unix_close,
    .shutdown    = nst_unix_shutdown,
};

nst_int_io_ops_t nst_unix_int_io_ops = {
    .set_io_eof_from_ev = nst_unix_set_io_eof_from_ev,
};

void nst_unix_set_io_eof_from_ev(nst_connection_t *c)
{
    c->flags.io_eof_from_ev = 1;
}
