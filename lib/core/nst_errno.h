#ifndef _NST_ERRNO_H_INCLUDED_
#define _NST_ERRNO_H_INCLUDED_

#include <nst_types.h>

#include <errno.h>

#define NST_EPERM         EPERM
#define NST_ENOENT        ENOENT
#define NST_ESRCH         ESRCH
#define NST_EINTR         EINTR
#define NST_ECHILD        ECHILD
#define NST_ENOMEM        ENOMEM
#define NST_EACCES        EACCES
#define NST_EBUSY         EBUSY
#define NST_EEXIST        EEXIST
#define NST_ENOTDIR       ENOTDIR
#define NST_EISDIR        EISDIR
#define NST_EINVAL        EINVAL
#define NST_ENOSPC        ENOSPC
#define NST_EPIPE         EPIPE
#define NST_EAGAIN        EAGAIN
#define NST_EINPROGRESS   EINPROGRESS
#define NST_EADDRINUSE    EADDRINUSE
#define NST_ECONNABORTED  ECONNABORTED
#define NST_ECONNRESET    ECONNRESET
#define NST_ENOTCONN      ENOTCONN
#define NST_ETIMEDOUT     ETIMEDOUT
#define NST_ECONNREFUSED  ECONNREFUSED
#define NST_ENAMETOOLONG  ENAMETOOLONG
#define NST_ENETDOWN      ENETDOWN
#define NST_ENETUNREACH   ENETUNREACH
#define NST_EHOSTDOWN     EHOSTDOWN
#define NST_EHOSTUNREACH  EHOSTUNREACH
#define NST_ENOSYS        ENOSYS
#define NST_ECANCELED     ECANCELED
#define NST_ENOMOREFILES  0



#define nst_errno                  errno
#define nst_socket_errno           errno
#define nst_set_errno(err)         errno = err
#define nst_set_socket_errno(err)  errno = err

#define _NST_ERRNO_PLUS_BASE(x)    ((x) << 16)
#define _NST_ERRNO_MINUS_BASE(x)   ((x) >> 16)
#define _NST_ERRNO_BASE            (_NST_ERRNO_PLUS_BASE(1) - 1)
#define IS_NST_ERRNO(x) ((x) >= _NST_ERRNO_BASE \
                         && (x) < _NST_ERRNO_PLUS_BASE(_NST_ERRNO_NUM))

#define NST_ERRNO_UNKNOWN                _NST_ERRNO_BASE /*!< acting as a catch
                                                          *   all errno
                                                          */
#define NST_ECONN_TP                     _NST_ERRNO_PLUS_BASE(1) /*!< error in
                                                                  *TP protocol
                                                                  */
#define NST_ECONN_PEER_ERROR             _NST_ERRNO_PLUS_BASE(2) /*!< Peer has
                                                                  *a catch all
                                                                  *error
                                                                  */
#define NST_ECONN_PEER_FWD_ERROR         _NST_ERRNO_PLUS_BASE(3) /*!< Peer has
                                                                  *a catch all
                                                                  *error on the
                                                                  *other conn
                                                                  */
#define NST_ECONN_PEER_RST               _NST_ERRNO_PLUS_BASE(4) /*!< Peer sends
                                                                  *a RST
                                                                  */
#define NST_ECONN_PEER_FWD_RST           _NST_ERRNO_PLUS_BASE(5) /*!< Peer fwd
                                                                  *the RST from
                                                                  *the other
                                                                  *conn
                                                                  */
#define NST_ECONN_RTIMEDOUT              _NST_ERRNO_PLUS_BASE(6) /*!< I locally
                                                                  *detected read
                                                                  *time out
                                                                  */
#define NST_ECONN_WTIMEDOUT              _NST_ERRNO_PLUS_BASE(7) /*!< I locally
                                                                  *detected
                                                                  *write time
                                                                  *out
                                                                  */
#define NST_ECONN_PEER_TIMEDOUT          _NST_ERRNO_PLUS_BASE(8) /*!< Peer
                                                                  *detected
                                                                  *timeout
                                                                  */
#define NST_ECONN_PEER_FWD_TIMEDOUT      _NST_ERRNO_PLUS_BASE(9) /*!< Peer
                                                                  *detected
                                                                  *time out on
                                                                  *the other
                                                                  *conn
                                                                  */
#define _NST_ERRNO_NUM                   10 /* including unknown (0) */

extern const char *NST_ERRNO_STR[];

char *nst_strerror_r(int err, char *errstr, size_t size);
const char *nst_strerror(int err);

#endif /* _NST_ERRNO_H_INCLUDED_ */
