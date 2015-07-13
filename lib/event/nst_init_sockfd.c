#include "nst_init_sockfd.h"

#include "nst_event_int.h"

#include <nst_log.h>
#include <nst_errno.h>
#include <nst_types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int
nst_nonblocking(int fd)
{
    int  nb;

    nb = 1;

    if(ioctl(fd, FIONBIO, &nb) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "ioctl(FIONBIO, 1) failed. %s(%d)",
                    nst_strerror(errno), errno);
        return -1;
    } else {
        return 0;
    }
}
nst_status_e
nst_init_sockfd(int fd, int tcp_ext)
{
    int on = 1;

    if (!(nst_event_flags & (NST_USE_AIO_EVENT|NST_USE_RTSIG_EVENT))) {
        /* ML on NGX:
         * For Linux epoll,  it will fall through to here
         * to set the newly accepted socket to nonblocking mode.
         */
        if (nst_nonblocking(fd) == -1) {
            return NST_ERROR;
        }
    }

    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                  (const void *) &on, sizeof(on)) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "enable TCP_NODELAY failed. %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }
 return NST_OK;
}

nst_status_e
nst_init_tp_sockfd(int fd)
{
    int on = 1;

    if(setsockopt(fd, SOL_SOCKET, SO_OOBINLINE,
                  (const void *) &on, sizeof(on)) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "setsockopt(SO_OOBINLINE) failed %s(%ud)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    return NST_OK;
}

