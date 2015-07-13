
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>

#if (NST_PCRE)

static void * nst_regex_malloc(size_t size);
static void nst_regex_free(void *p);


static nst_pool_t  *nst_pcre_pool;


void
nst_regex_init(void)
{
    pcre_malloc = nst_regex_malloc;
    pcre_free = nst_regex_free;
}


nst_regex_t *
nst_regex_compile(nst_str_t *pattern, nst_int_t options, nst_pool_t *pool,
    nst_str_t *err)
{
    int              erroff;
    const char      *errstr;
    nst_regex_t     *re;
#if (NST_THREADS)
    nst_core_tls_t  *tls;

#if (NST_SUPPRESS_WARN)
    tls = NULL;
#endif

    if (nst_threaded) {
        tls = nst_thread_get_tls(nst_core_tls_key);
        tls->pool = pool;
    } else {
        nst_pcre_pool = pool;
    }

#else

    nst_pcre_pool = pool;

#endif

    re = pcre_compile((const char *) pattern->data, (int) options,
                      &errstr, &erroff, NULL);

    if (re == NULL) {
       if ((size_t) erroff == pattern->len) {
           nst_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\"%Z",
                        errstr, pattern->data);
        } else {
           nst_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\" at \"%s\"%Z",
                        errstr, pattern->data, pattern->data + erroff);
        }
    }

    /* ensure that there is no current pool */

#if (NST_THREADS)
    if (nst_threaded) {
        tls->pool = NULL;
    } else {
        nst_pcre_pool = NULL;
    }
#else
    nst_pcre_pool = NULL;
#endif

    return re;
}


nst_int_t
nst_regex_capture_count(nst_regex_t *re)
{
    int  rc, n;

    n = 0;

    rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &n);

    if (rc < 0) {
        return (nst_int_t) rc;
    }

    return (nst_int_t) n;
}


nst_int_t
nst_regex_exec(nst_regex_t *re, nst_str_t *s, int *captures, nst_int_t size)
{
    int  rc;

    rc = pcre_exec(re, NULL, (const char *) s->data, s->len, 0, 0,
                   captures, size);

    if (rc == -1) {
        return NST_REGEX_NO_MATCHED;
    }

    return rc;
}


nst_int_t
nst_regex_exec_array(nst_array_t *a, nst_str_t *s, nst_log_t *log)
{
    nst_int_t         n;
    nst_uint_t        i;
    nst_regex_elt_t  *re;

    re = a->elts;

    for (i = 0; i < a->nelts; i++) {

        n = nst_regex_exec(re[i].regex, s, NULL, 0);

        if (n == NST_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            nst_log_error(NST_LOG_ALERT, log, 0,
                          nst_regex_exec_n " failed: %d on \"%V\" using \"%s\"",
                          n, s, re[i].name);
            return NST_ERROR;
        }

        /* match */

        return NST_OK;
    }

    return NST_DECLINED;
}


static void *
nst_regex_malloc(size_t size)
{
    nst_pool_t      *pool;
#if (NST_THREADS)
    nst_core_tls_t  *tls;

    if (nst_threaded) {
        tls = nst_thread_get_tls(nst_core_tls_key);
        pool = tls->pool;
    } else {
        pool = nst_pcre_pool;
    }
#else
    pool = nst_pcre_pool;
#endif

    if (pool) {
        return nst_palloc(pool, size);
    }

    return NULL;
}


static void
nst_regex_free(void *p)
{
    return;
}
#endif
