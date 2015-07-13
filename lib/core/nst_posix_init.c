#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nst_posix_init.h"

#include "nst_cpuinfo.h"
#include "nst_linux_init.h"
#include "nst_alloc.h"
#include "nst_log.h"
#include "nst_errno.h"
#include "nst_times.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>

nst_int_t   nst_ncpu;
struct rlimit  rlmt;

nst_status_e
nst_os_init(void)
{
    nst_uint_t    n;
    int           fd;
    unsigned int  rd;

    n = 0;
    if (nst_os_specific_init() != NST_OK) {
        return NST_ERROR;
    }

    nst_pagesize = getpagesize();
    nst_cacheline_size = NST_CPU_CACHE_LINE;

    n = nst_pagesize;

    for (n = nst_pagesize; n >>= 1; nst_pagesize_shift++) { /* void */ }

    if (nst_ncpu == 0) {
        nst_ncpu = 1;
    }

    nst_cpuinfo();

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "getrlimit(RLIMIT_NOFILE) failed) %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    rd = nst_time();
    if ((fd = open ("/dev/random", O_RDONLY)) > 0) {
        int ret;
        ret = fcntl (fd, F_SETFL, O_NONBLOCK);
        if (ret == 0) {
            ret = read (fd, (char *)&rd, sizeof(unsigned int));
            if (ret != sizeof(unsigned int)) {
                rd = nst_time();
            }
        }
        close (fd);
    }
    srandom(rd);

    return NST_OK;
}

void
ngx_os_status(void)
{
    nst_os_specific_status();

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "getrlimit(RLIMIT_NOFILE): %r:%r",
                rlmt.rlim_cur, rlmt.rlim_max);
}

