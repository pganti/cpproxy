
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_CORE_H_INCLUDED_
#define _NST_CORE_H_INCLUDED_

/* _FILE_OFFSET_BITS feature should be defined at the very
 *     beginning for it to work. We can refer to /usr/include/features.h
 *     for details.
 *
 *     I have already put it into CFLAGS. It is defined here again just in
 *     case.
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS  64
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>             /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <glob.h>

#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NODELAY, TCP_CORK */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#include <time.h>               /* tzset() */
#include <malloc.h>             /* memalign() */
#include <limits.h>             /* IOV_MAX */
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <crypt.h>
#include <sys/utsname.h>        /* uname() */
#include <nst_types.h>

#include <nst_config.h>         /* TODO: decouple nst_config.h from nst_core.h */
#include <nst_version.h>         /* TODO: decouple nst_config.h from nst_core.h */



extern nst_pid_t nst_getpid (); /* why it is here??? */

#include <nst_errno.h>
#include <queue.h>
#include <nst_assert.h>
#include <nst_mempool.h>
#include <nst_log.h>

#include <nst_atomic.h>
#include <nst_rbtree.h>

#include <nst_time.h>
#include <nst_shmem.h>
#include <nst_user.h>
#include <nst_string.h>
#include <nst_alloc.h>
#include <nst_palloc.h>
#include <nst_queue.h>
#include <nst_array.h>
#include <nst_list.h>
#include <nst_hash.h>

#include <nst_crc.h>
#include <nst_crc32.h>
#if (NST_PCRE)
#include <nst_regex.h>
#endif

#include <nst_radix_tree.h>
#include <nst_times.h>
#include <nst_shmtx.h>
#include <nst_slab.h>
#include <nst_inet.h>
#include <nst_buf.h>
#include <nst_thread.h>
#include <nst_timer.h>

void nst_cpuinfo(void);
nst_log_t * nst_corelib_init (const char *agent);
nst_int_t nst_daemon(nst_log_t *log, const char * changeroot);

#endif /* _NST_CORE_H_INCLUDED_ */
