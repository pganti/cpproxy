
/*
 * Copyright (C) Igor Sysoev
 */
#include <nst_core.h>
#include <crypt.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* pread(), pwrite(), gethostname() */
#endif

/*
 * Solaris has thread-safe crypt()
 * Linux has crypt_r(); "struct crypt_data" is more than 128K
 * FreeBSD needs the mutex to protect crypt()
 *
 * TODO:
 *     nst_crypt_init() to init mutex
 */


#if (NST_CRYPT)

#if (NST_HAVE_GNU_CRYPT_R)

nst_int_t
nst_crypt(nst_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    nst_err_t           err;
    struct crypt_data   cd;

    nst_set_errno(0);

    cd.initialized = 0;
    /* work around the glibc bug */
    cd.current_salt[0] = ~salt[0];

    value = crypt_r((char *) key, (char *) salt, &cd);

    err = nst_errno;

    if (err == 0) {
        len = nst_strlen(value);

        *encrypted = nst_palloc(pool, len);
        if (*encrypted) {
            nst_memcpy(*encrypted, value, len + 1);
            return NST_OK;
        }
    }

    nst_log_error(NST_LOG_CRIT, pool->log, err, "crypt_r() failed");

    return NST_ERROR;
}

#else

nst_int_t
nst_crypt(nst_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    nst_err_t   err;

#if (NST_THREADS && NST_NONREENTRANT_CRYPT)

    /* crypt() is a time consuming funtion, so we only try to lock */

    if (nst_mutex_trylock(nst_crypt_mutex) != NST_OK) {
        return NST_AGAIN;
    }

#endif

    nst_set_errno(0);

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = nst_strlen(value);

        *encrypted = nst_palloc(pool, len);
        if (*encrypted) {
            nst_memcpy(*encrypted, value, len + 1);
        }

#if (NST_THREADS && NST_NONREENTRANT_CRYPT)
        nst_mutex_unlock(nst_crypt_mutex);
#endif
        return NST_OK;
    }

    err = nst_errno;

#if (NST_THREADS && NST_NONREENTRANT_CRYPT)
    nst_mutex_unlock(nst_crypt_mutex);
#endif

    nst_log_error(NST_LOG_CRIT, pool->log, err, "crypt() failed");

    return NST_ERROR;
}

#endif

#endif /* NST_CRYPT */
