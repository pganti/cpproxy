#ifndef _NST_CONFIG_H_
#define _NST_CONFIG_H_

/* Imported from ngx_auto_headers.h */
#define NST_LINUX  (1)

/* Imported from ngx_auto_config.h */
#define NST_HAVE_GCC_VARIADIC_MACROS  1
#define NST_HAVE_C99_VARIADIC_MACROS  1
#define NST_HAVE_EPOLL  1
#define NST_HAVE_CLEAR_EVENT  1
#define NST_HAVE_SENDFILE  1
#define NST_HAVE_SENDFILE64  1
#define NST_HAVE_PR_SET_DUTPABLE  1
#define NST_HAVE_SCHED_SETAFFINITY  1
#define NST_HAVE_NONALIGNED  1
#define NST_CPU_CACHE_LINE  64
#define NST_HAVE_O_DIRECT  1
#define NST_HAVE_ALIGNED_DIRECTIO  1
#define NST_HAVE_UNIX_DOMAIN  1
#define NST_PTR_SIZE  8
#define NST_SIG_ATOMIC_T_SIZE  4
#define NST_HAVE_LITTLE_ENDIAN  1
#define NST_MAX_SIZE_T_VALUE  9223372036854775807LL
#define NST_SIZE_T_LEN  (sizeof("-9223372036854775808") - 1)
#define NST_MAX_OFF_T_VALUE  9223372036854775807LL
#define NST_OFF_T_LEN  (sizeof("-9223372036854775808") - 1)
#define NST_TIME_T_SIZE  8
#define NST_TIME_T_LEN  (sizeof("-9223372036854775808") - 1)
#define NST_HAVE_PREAD  1
#define NST_HAVE_PWRITE  1
#define NST_HAVE_STRERROR_R (1)
#define NST_HAVE_LOCALTIME_R  1
#define NST_HAVE_POSIX_MEMALIGN  1
#define NST_HAVE_MEMALIGN  1
#define NST_HAVE_SCHED_YIELD  1
#define NST_HAVE_MAP_ANON  1
#define NST_HAVE_MAP_DEVZERO  1
#define NST_HAVE_SYSVSHM  1
#define NST_HAVE_MSGHDR_MSG_CONTROL  1
#define NST_HAVE_FIONBIO  1
#define NST_HAVE_GMTOFF  1
#define NST_HAVE_D_TYPE  1
#define NST_USE_HTTP_FILE_CACHE_UNIQ  1
#define NST_SUPPRESS_WARN  1
#define NST_STP  1
/* End imported from ngx_auto_config.h */

/* Imported from ngx_linux_config.h */
#define NST_HAVE_DEFERRED_ACCEPT    (1)
#define NST_HAVE_SO_SNDLOWAT        (0)
#define NST_HAVE_GNU_CRYPT_R        (1)
#define NST_HAVE_INHERITED_NONBLOCK (0)
#define __need_IOV_MAX    /* for IOV_MAX */
#include <stdio.h>        /* for IOV_MAX */
extern char **environ;
/* End imported from ngx_linux_config.h */

/*  Imported from ngx_config.h */
#define NST_INT32_LEN   sizeof("-2147483648") - 1
#define NST_INT64_LEN   sizeof("-9223372036854775808") - 1
#define NST_INT_LEN     sizeof("-9223372036854775808") - 1
#define NST_UINT_LEN    sizeof("18446744073709551615") - 1

#define NST_MAXHOSTNAMELEN   (256)

#if (NST_PTR_SIZE == 4)
#define NST_INT_T_LEN   NST_INT32_LEN
#else
#define NST_INT_T_LEN   NST_INT64_LEN
#endif

#define nst_inline           inline
#define NST_ALIGNMENT        sizeof(unsigned long)    /* platform word */
#define nst_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define nst_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

#if ((__GNU__ == 2) && (__GNUC_MINOR__ < 8))
#define NST_MAX_UINT32_VALUE  (uint32_t) 0xffffffffLL
#else
#define NST_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#endif
/* End imported from ngx_config.h */

/* Pronto Specifically added*/
#define NST_DIR_DELIMITER_CHAR        '/'
#define NST_VALGRIND                  (1)

#endif /* _NST_CONFIG_H_ */
