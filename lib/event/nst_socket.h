#ifndef _NST_SOCKET_H__
#define _NST_SOCKET_H_


#include <nst_config.h>


#define NST_WRITE_SHUTDOWN SHUT_WR

typedef int  nst_socket_t;

#define nst_socket          socket
#define nst_socket_n        "socket()"


#if (NST_HAVE_FIONBIO)

int nst_nonblocking(nst_socket_t s);
int nst_blocking(nst_socket_t s);

#define nst_nonblocking_n   "ioctl(FIONBIO)"
#define nst_blocking_n      "ioctl(!FIONBIO)"

#else

#define nst_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define nst_nonblocking_n   "fcntl(O_NONBLOCK)"

#define nst_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define nst_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

int nst_tcp_nopush(nst_socket_t s);
int nst_tcp_push(nst_socket_t s);

#if (NST_LINUX)

#define nst_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define nst_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define nst_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define nst_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define nst_shutdown_socket    shutdown
#define nst_shutdown_socket_n  "shutdown()"

#define nst_close_socket    close
#define nst_close_socket_n  "close() socket"


#endif /* _NST_SOCKET_H_INCLUDED_ */
