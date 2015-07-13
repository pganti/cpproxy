#include "nst_linux_init.h"

#include "nst_log.h"
#include "nst_errno.h"
#include "nst_string.h"

#include <sys/utsname.h>

u_char  nst_linux_kern_ostype[50];
u_char  nst_linux_kern_osrelease[50];

nst_status_e
nst_os_specific_init(void)
{
    struct utsname  u;

    if (uname(&u) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "uname() failed. %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    (void) nst_cpystrn(nst_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(nst_linux_kern_ostype));

    (void) nst_cpystrn(nst_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(nst_linux_kern_osrelease));

    return NST_OK;
}


void
nst_os_specific_status(void)
{

    NST_NOC_LOG(NST_LOG_LEVEL_INFO, "OS: %s %s",
                nst_linux_kern_ostype, nst_linux_kern_osrelease);
}
