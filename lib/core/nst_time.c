#include "nst_time.h"

#include "nst_config.h"

#include <time.h>

void
nst_localtime(time_t s, nst_tm_t *tm)
{
#if (NST_HAVE_LOCALTIME_R)
    (void) localtime_r(&s, tm);

#else
    nst_tm_t  *t;

    t = localtime(&s);
    *tm = *t;

#endif

    tm->nst_tm_mon++;
    tm->nst_tm_year += 1900;
}


void
nst_libc_localtime(time_t s, struct tm *tm)
{
#if (NST_HAVE_LOCALTIME_R)
    (void) localtime_r(&s, tm);

#else
    struct tm  *t;

    t = localtime(&s);
    *tm = *t;

#endif
}


void
nst_libc_gmtime(time_t s, struct tm *tm)
{
#if (NST_HAVE_LOCALTIME_R)
    (void) gmtime_r(&s, tm);

#else
    struct tm  *t;

    t = gmtime(&s);
    *tm = *t;

#endif
}
