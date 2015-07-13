
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_REGEX_H_INCLUDED_
#define _NST_REGEX_H_INCLUDED_

#include <nst_core.h>

#include <pcre.h>


#define NST_REGEX_NO_MATCHED  -1000

#define NST_REGEX_CASELESS    PCRE_CASELESS

typedef pcre  nst_regex_t;

typedef struct {
    nst_regex_t   *regex;
    u_char        *name;
} nst_regex_elt_t;


void nst_regex_init(void);
nst_regex_t *nst_regex_compile(nst_str_t *pattern, nst_int_t options,
    nst_pool_t *pool, nst_str_t *err);
nst_int_t nst_regex_capture_count(nst_regex_t *re);
nst_int_t nst_regex_exec(nst_regex_t *re, nst_str_t *s, int *captures,
    nst_int_t size);
nst_int_t nst_regex_exec_array(nst_array_t *a, nst_str_t *s, nst_log_t *log);


#define nst_regex_exec_n           "pcre_exec()"
#define nst_regex_capture_count_n  "pcre_fullinfo()"


#endif /* _NST_REGEX_H_INCLUDED_ */
