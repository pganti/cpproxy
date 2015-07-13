#ifndef _NST_TIMES_H_INCLUDED_
#define _NST_TIMES_H_INCLUDED_

#include "nst_config.h"
#include "nst_string.h"
#include "nst_time.h"
#include "nst_types.h"

#include <time.h>

#define NST_LOG_TIME_YEAR_BASE 1900

typedef struct {
    time_t      sec;
    nst_uint_t  msec;
    nst_int_t   gmtoff;
} nst_time_t;

typedef struct {
    time_t sec;
    nst_uint_t msec;
} nst_timeval_ms_t;

void nst_time_init(void);
void nst_time_update(time_t sec, nst_uint_t msec);
u_char *nst_http_time(u_char *buf, time_t t);
u_char *nst_http_cookie_time(u_char *buf, time_t t);
void nst_gmtime(time_t t, nst_tm_t *tp);


extern volatile nst_time_t  *nst_cached_time;

#define nst_time()           nst_cached_time->sec
#define nst_timeofday()      (nst_time_t *) nst_cached_time

#define nst_timeval_ms(x)                            \
    do {                                            \
        nst_time_t *tp = nst_timeofday();           \
        (x).sec = tp->sec;                           \
        (x).msec = tp->msec;                         \
    } while(0)

static inline u32
nst_timeval_toms (struct timeval * tv)
{
    float      msec, sec, usec;
    
    sec = (float) tv->tv_sec;
    usec = (float) tv->tv_usec;

    msec = (sec * 1000) + (usec / 1000);

    return (u32) msec;
}

/* extern volatile nst_str_t        nst_cached_err_log_time; */
extern volatile nst_str_t        nst_cached_log_time;
extern volatile nst_str_t        nst_cached_http_time;
extern volatile nst_str_t        nst_cached_http_log_time;
extern volatile struct timeval   nst_cached_tv;

/*
 * milliseconds elapsed since epoch and truncated to nst_msec_t,
 * used in event timers
 */
extern volatile nst_msec_t   nst_current_msec;


static inline void
nst_getcached_tv (struct timeval * tv)
{
    *tv = nst_cached_tv;
}
#endif /* _NST_TIMES_H_INCLUDED_ */
