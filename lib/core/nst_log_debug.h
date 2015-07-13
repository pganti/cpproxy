/*
 * Copyright (C) Igor Sysoev
 *
 * $Id: nst_log_debug.h 554 2009-03-25 18:36:55Z pganti $
 */

#ifndef _NST_LOG_DEBUG_H_INCLUDED_
#define _NST_LOG_DEBUG_H_INCLUDED_


#include <nst_config.h>
#include <nst_log.h>


#define NST_LOG_STDERR            NST_LOG_LEVEL_STDERR
#define NST_LOG_EMERG             NST_LOG_LEVEL_CRITICAL
#define NST_LOG_ALERT             NST_LOG_LEVEL_CRITICAL
#define NST_LOG_CRIT              NST_LOG_LEVEL_CRITICAL
#define NST_LOG_ERR               NST_LOG_LEVEL_ERROR
#define NST_LOG_WARN              NST_LOG_LEVEL_NOTICE
#define NST_LOG_NOTICE            NST_LOG_LEVEL_NOTICE
#define NST_LOG_INFO              NST_LOG_LEVEL_INFO
#define NST_LOG_DEBUG             NST_LOG_LEVEL_DEBUG

#define NST_LOG_DEBUG_CORE        0x010
#define NST_LOG_DEBUG_ALLOC       0x020
#define NST_LOG_DEBUG_MUTEX       0x040
#define NST_LOG_DEBUG_EVENT       0x080
#define NST_LOG_DEBUG_HTTP        0x100
#define NST_LOG_DEBUG_MAIL        0x200
#define NST_LOG_DEBUG_MYSQL       0x400

/*
 * do not forget to update debug_levels[] in src/core/nst_log.c
 * after the adding a new debug level
 */

#define NST_LOG_DEBUG_FIRST       NST_LOG_DEBUG_CORE
#define NST_LOG_DEBUG_LAST        NST_LOG_DEBUG_MYSQL
#define NST_LOG_DEBUG_CONNECTION  0x80000000
#define NST_LOG_DEBUG_ALL         0x7ffffff0


typedef struct nst_log_s           nst_log_t;

struct nst_log_facility;
typedef u_char *(*nst_log_handler_pt) (nst_log_t *log, u_char *buf, size_t len);


struct nst_log_s {
    nst_uint_t           log_level;
    struct nst_log_facility * fac;
};


#define NST_MAX_ERROR_STR   2048


/*********************************/
#define nst_log_error(lvl, log, args...) do {                           \
    nst_log_facility_t * ___fac = log->fac;                             \
    if (___fac->flags.nst_log_enabled && (lvl <= ___fac->conf.level)) { \
        nst_log_error_core(__FUNCTION__, __LINE__, lvl, log, args);     \
    }                                                                   \
 } while (0)

#define nst_log_debug(module, log, args...)                             \
do {                                                                    \
    nst_log_facility_t * __fac = log->fac;                             \
    if (__fac->flags.nst_log_enabled && (NST_LOG_DEBUG <= __fac->conf.level)){ \
        nst_log_error_core(__FUNCTION__, __LINE__, NST_LOG_DEBUG, log, args); \
    }                                                                   \
 } while (0)

void nst_log_error_core(const char * function, int line, nst_uint_t level, nst_log_t *log, nst_err_t err, const char *fmt, ...);

/*********************************/


/*********************************/

#if (NST_DEBUG)


#define nst_log_debug0  nst_log_debug
#define nst_log_debug1  nst_log_debug
#define nst_log_debug2  nst_log_debug
#define nst_log_debug3  nst_log_debug
#define nst_log_debug4  nst_log_debug
#define nst_log_debug5  nst_log_debug
#define nst_log_debug6  nst_log_debug
#define nst_log_debug7  nst_log_debug
#define nst_log_debug8  nst_log_debug


#else /* NO NST_DEBUG */

#define nst_log_debug0(level, log, err, fmt)
#define nst_log_debug1(level, log, err, fmt, arg1)
#define nst_log_debug2(level, log, err, fmt, arg1, arg2)
#define nst_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define nst_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define nst_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define nst_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define nst_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define nst_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)
#endif

/*********************************/

extern nst_log_t           nst_dl_logger;
nst_log_t * nst_log_init(const char *agent);
void nst_log_reset (void);
void nst_log_abort(nst_err_t err, const char *text);
nst_log_t * nst_default_logger ();


#endif /* _NST_LOG_DEBUG_H_INCLUDED_*/
