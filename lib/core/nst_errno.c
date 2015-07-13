
/*
 * Copyright (C) Igor Sysoev
 */

#include <nst_core.h>

const char *NST_ERRNO_STR[_NST_ERRNO_NUM] =
{
    [0]                                               = "catch-all NST errno",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_TP)]             = "TP error",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_ERROR)]     = "peer error",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_FWD_ERROR)] = "peer foward error",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_RST)]       = "peer reset",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_FWD_RST)]   = "peer foward reset",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_RTIMEDOUT)]      = "read timed out",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_WTIMEDOUT)]      = "write timed out",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_TIMEDOUT)]  = "peer timed out",
    [_NST_ERRNO_MINUS_BASE(NST_ECONN_PEER_FWD_TIMEDOUT)]  = "peer forward timed out",

};

char * nst_strerror_r(int err, char *errstr, size_t size)
{
    const char  *str;

    if (size == 0) {
        return 0;
    }

    //errstr[0] = '\0';

    if(IS_NST_ERRNO(err)) {
        str = NST_ERRNO_STR[_NST_ERRNO_MINUS_BASE(err)];
        strncpy(errstr, str, size);
    } else {
        strerror_r(err, errstr, size);
    }

    errstr[size-1] = '\0';

    /* it is not as efficient as nginx way. I changed it for two
     *     reasons:
     *     1. returning a pointer point to '\0' is dangerous.
     *     2. it is pretty useless.  nginx is only using it in ngx_conf_file.c
     *        and we are ditching nginx's config file logic
     *     3. this dangerous optimization only for logging error condition is
     *        not convincing.  how ofter do we log error??
     *
     *     I am keeping this 'return pointer to last \0' behavior
     *     just in case I am missing some code in nginx. However, I am
     *     not using the the ngx_cpystrn to avoid cross #include between
     *     os/unix/ and core/ directories.
     */
    return errstr+strlen(errstr);
}

const char *nst_strerror(int err)
{
    if(IS_NST_ERRNO(err)) {
        return NST_ERRNO_STR[_NST_ERRNO_MINUS_BASE(err)];
    } else {
        return strerror(err);
    }
}
