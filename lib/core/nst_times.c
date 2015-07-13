#include "nst_times.h"

#include "nst_config.h"
#include "nst_atomic.h"

/*
 * The time may be updated by signal handler or by several threads.
 * The time update operations are rare and require to hold the nst_time_lock.
 * The time read operations are frequent, so they are lock-free and get time
 * values and strings from the current slot.  Thus thread may get the corrupted
 * values only if it is preempted while copying and then it is not scheduled
 * to run more than NST_TIME_SLOTS seconds.
 */

#define NST_TIME_SLOTS   64

static nst_uint_t                  slot;
static nst_atomic_t                nst_time_lock;
volatile nst_msec_t                nst_current_msec;
volatile nst_time_t              * nst_cached_time;
/* volatile nst_str_t                 nst_cached_err_log_time; */
volatile nst_str_t                 nst_cached_log_time;
volatile nst_str_t                 nst_cached_http_time;
volatile nst_str_t                 nst_cached_http_log_time;
volatile struct timeval            nst_cached_tv;

static nst_time_t        cached_time[NST_TIME_SLOTS];
/* static u_char            cached_err_log_time[NST_TIME_SLOTS] */
/*                                     [sizeof("1970/09/28 12:00:00")]; */
static u_char            cached_log_time[NST_TIME_SLOTS]
                                       [sizeof("20090304181152")];
static u_char            cached_http_time[NST_TIME_SLOTS]
                                    [sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
static u_char            cached_http_log_time[NST_TIME_SLOTS]
                                    [sizeof("28/Sep/1970:12:00:00 +0600")];

static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void
nst_time_init(void)
{
    /* nst_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1; */
    nst_cached_log_time.len = sizeof("20090304181152") - 1;
    nst_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    nst_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;

    nst_cached_time = &cached_time[0];

#if !(NST_WIN32)
    tzset();
#endif

    nst_time_update(0, 0);
}


void
nst_time_update (time_t sec, nst_uint_t msec)
{
    u_char          *p0, *p1, *p2;
    nst_tm_t         tm, gmt;
    nst_time_t      *tp;
    struct timeval   tv;

    if (!nst_trylock(&nst_time_lock)) {
        return;
    }

    nst_gettimeofday(&tv);
    nst_cached_tv = tv;

    if (sec == 0) {
        sec = tv.tv_sec;
        msec = tv.tv_usec / 1000;
    }

    nst_current_msec = (nst_msec_t) sec * 1000 + msec;

    tp = &cached_time[slot];

    if (tp->sec == sec) {
        tp->msec = msec;
        nst_unlock(&nst_time_lock);
        return;
    }

    if (slot == NST_TIME_SLOTS - 1) {
        slot = 0;
    } else {
        slot++;
    }

    tp = &cached_time[slot];

    tp->sec = sec;
    tp->msec = msec;

    nst_gmtime(sec, &gmt);


    p0 = &cached_http_time[slot][0];

    (void) nst_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[gmt.nst_tm_wday], gmt.nst_tm_mday,
                       months[gmt.nst_tm_mon - 1], gmt.nst_tm_year,
                       gmt.nst_tm_hour, gmt.nst_tm_min, gmt.nst_tm_sec);

#if (NST_HAVE_GETTIMEZONE)

    tp->gmtoff = nst_gettimezone();
    nst_gmtime(sec + tp->gmtoff * 60, &tm);

#elif (NST_HAVE_GMTOFF)

    nst_localtime(sec, &tm);
    tp->gmtoff = (nst_int_t) (tm.nst_tm_gmtoff / 60);

#else

    nst_localtime(sec, &tm);
    tp->gmtoff = nst_timezone(tm.nst_tm_isdst);

#endif


#if 0
    p1 = &cached_err_log_time[slot][0];

    (void) nst_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.nst_tm_year, tm.nst_tm_mon,
                       tm.nst_tm_mday, tm.nst_tm_hour,
                       tm.nst_tm_min, tm.nst_tm_sec);
#endif
    p1 = &cached_log_time[slot][0];

    snprintf ((char *)p1,
              nst_cached_log_time.len + 1,
              "%04d%02d%02d%02d%02d%02d",
              tm.nst_tm_year,
              tm.nst_tm_mon,
              tm.nst_tm_mday,
              tm.nst_tm_hour,
              tm.nst_tm_min,
              tm.nst_tm_sec);


    p2 = &cached_http_log_time[slot][0];

    (void) nst_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
                       tm.nst_tm_mday, months[tm.nst_tm_mon - 1],
                       tm.nst_tm_year, tm.nst_tm_hour,
                       tm.nst_tm_min, tm.nst_tm_sec,
                       tp->gmtoff < 0 ? '-' : '+',
                       nst_abs(tp->gmtoff / 60), nst_abs(tp->gmtoff % 60));


    nst_memory_barrier();

    nst_cached_time = tp;
    nst_cached_log_time.data = p1;
    nst_cached_http_time.data = p0;
    /* nst_cached_err_log_time.data = p1; */
    nst_cached_http_log_time.data = p2;

    nst_unlock(&nst_time_lock);
}


u_char *
nst_http_time(u_char *buf, time_t t)
{
    nst_tm_t  tm;

    nst_gmtime(t, &tm);

    return nst_sprintf(buf, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[tm.nst_tm_wday],
                       tm.nst_tm_mday,
                       months[tm.nst_tm_mon - 1],
                       tm.nst_tm_year,
                       tm.nst_tm_hour,
                       tm.nst_tm_min,
                       tm.nst_tm_sec);
}


u_char *
nst_http_cookie_time(u_char *buf, time_t t)
{
    nst_tm_t  tm;

    nst_gmtime(t, &tm);

    /*
     * Netscape 3.x does not understand 4-digit years at all and
     * 2-digit years more than "37"
     */

    return nst_sprintf(buf,
                       (tm.nst_tm_year > 2037) ?
                                         "%s, %02d-%s-%d %02d:%02d:%02d GMT":
                                         "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
                       week[tm.nst_tm_wday],
                       tm.nst_tm_mday,
                       months[tm.nst_tm_mon - 1],
                       (tm.nst_tm_year > 2037) ? tm.nst_tm_year:
                                                 tm.nst_tm_year % 100,
                       tm.nst_tm_hour,
                       tm.nst_tm_min,
                       tm.nst_tm_sec);
}


void
nst_gmtime(time_t t, nst_tm_t *tp)
{
    nst_int_t   yday;
    nst_uint_t  n, sec, min, hour, mday, mon, year, wday, days, leap;

    /* the calculation is valid for positive time_t only */

    n = (nst_uint_t) t;

    days = n / 86400;

    /* Jaunary 1, 1970 was Thursday */

    wday = (4 + days) % 7;

    n %= 86400;
    hour = n / 3600;
    n %= 3600;
    min = n / 60;
    sec = n % 60;

    /*
     * the algorithm based on Gauss' formula,
     * see src/http/nst_http_parse_time.c
     */

    /* days since March 1, 1 BC */
    days = days - (31 + 28) + 719527;

    /*
     * The "days" should be adjusted to 1 only, however, some March 1st's go
     * to previous year, so we adjust them to 2.  This causes also shift of the
     * last Feburary days to next year, but we catch the case when "yday"
     * becomes negative.
     */

    year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    if (yday < 0) {
        leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
        yday = 365 + leap + yday;
        year--;
    }

    /*
     * The empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     *     mon = (yday + 31) * 15 / 459
     *     mon = (yday + 31) * 17 / 520
     *     mon = (yday + 31) * 20 / 612
     */

    mon = (yday + 31) * 10 / 306;

    /* the Gauss' formula that evaluates days before the month */

    mday = yday - (367 * mon / 12 - 30) + 1;

    if (yday >= 306) {

        year++;
        mon -= 10;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

    } else {

        mon += 2;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday += 31 + 28 + leap;
         */
    }

    tp->nst_tm_sec = (nst_tm_sec_t) sec;
    tp->nst_tm_min = (nst_tm_min_t) min;
    tp->nst_tm_hour = (nst_tm_hour_t) hour;
    tp->nst_tm_mday = (nst_tm_mday_t) mday;
    tp->nst_tm_mon = (nst_tm_mon_t) mon;
    tp->nst_tm_year = (nst_tm_year_t) year;
    tp->nst_tm_wday = (nst_tm_wday_t) wday;
}
