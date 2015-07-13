
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_TIME_H_INCLUDED_
#define _NST_TIME_H_INCLUDED_


#include <nst_config.h>
#include <nst_rbtree.h>

#include <sys/time.h>
#include <time.h>

typedef nst_rbtree_key_t      nst_msec_t;
typedef nst_rbtree_key_int_t  nst_msec_int_t;

typedef struct tm             nst_tm_t;

#define nst_tm_sec            tm_sec
#define nst_tm_min            tm_min
#define nst_tm_hour           tm_hour
#define nst_tm_mday           tm_mday
#define nst_tm_mon            tm_mon
#define nst_tm_year           tm_year
#define nst_tm_wday           tm_wday
#define nst_tm_isdst          tm_isdst

#define nst_tm_sec_t          int
#define nst_tm_min_t          int
#define nst_tm_hour_t         int
#define nst_tm_mday_t         int
#define nst_tm_mon_t          int
#define nst_tm_year_t         int
#define nst_tm_wday_t         int


#if (NST_HAVE_GMTOFF)
#define nst_tm_gmtoff         tm_gmtoff
#define nst_tm_zone           tm_zone
#endif


#if (NST_SOLARIS)

#define nst_timezone(isdst) (- (isdst ? altzone : timezone) / 60)

#else

#define nst_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)

#endif

#define nst_time_sec_to_ms(sec) ((sec) * 1000)
#define nst_time_ms_to_sec(ms) ((ms) / 1000)

void nst_localtime(time_t s, nst_tm_t *tm);
void nst_libc_localtime(time_t s, struct tm *tm);
void nst_libc_gmtime(time_t s, struct tm *tm);

#define nst_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
#define nst_msleep(ms)        (void) usleep(ms * 1000)
#define nst_sleep(s)          (void) sleep(s)

# define nst_timercmp(a, b, CTP) 						      \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_usec CTP (b)->tv_usec) : 					      \
   ((a)->tv_sec CTP (b)->tv_sec))

# define nst_timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)

# define nst_timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)
#endif /* _NST_TIME_H_INCLUDED_ */
