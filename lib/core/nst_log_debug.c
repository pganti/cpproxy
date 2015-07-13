
/*
 * Copyright (C) Igor Sysoev
 *
 * $Id: nst_log_debug.c 554 2009-03-25 18:36:55Z pganti $
 */
#include <nst_core.h>

nst_log_t           nst_dl_logger;

nst_log_t *
nst_default_logger ()
{
    return &nst_dl_logger;
}

void
nst_log_error_core(const char * function, int line, nst_uint_t level,
                   nst_log_t *log, nst_err_t err, const char *fmt, ...)
{
    va_list               args;
    u_char                errstr[NST_MAX_ERROR_STR + 1024], *p;
    nst_log_facility_t  * fac;
    int                   len = 0;

    fac = log->fac;

    va_start(args, fmt);

    p = nst_vsnprintf(errstr, NST_MAX_ERROR_STR, fmt, args);
    if (p) {
        len = p - errstr;
    }

    va_end(args);


    if (p && err) {
        char  str[1024];
        if (nst_strerror_r (err, str, 1024) != NULL) {
            len += snprintf((char *)p, 1024, " - error(code=%d, errstr=%s)",
                             (int)err, str);
        }
    }
    if (len) {
        errstr [len] = '\0';
        nst_log_facility (fac, fac->conf.level, function, line, level,
                          (const char *)errstr);
    }
}

void
nst_log_abort(nst_err_t err, const char *text)
{
    nst_log_error(NST_LOG_ALERT, nst_default_logger(), err, text);
}

