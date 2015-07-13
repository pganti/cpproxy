#ifndef _NST_STRING_H_INCLUDED_
#define _NST_STRING_H_INCLUDED_

#include "nst_config.h"
#include "nst_bjhash.h"
#include "nst_types.h"

#include <stdarg.h>
#include <string.h>

struct nst_pool_s; /* Memory pool malloc */


typedef struct nst_str_s {
    size_t      len;
    u_char     *data;
} nst_str_t;


typedef struct {
    nst_str_t   key;
    nst_str_t   value;
} nst_keyval_t;


typedef struct nst_variable_value_s {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    const u_char     *data;
} nst_variable_value_t;


#define nst_string(str)     { sizeof(str) - 1, (u_char *) str }
#define nst_null_string     { 0, NULL }


#define nst_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define nst_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void nst_strlow(u_char *dst, u_char *src, size_t n);

#define nst_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define nst_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define nst_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define nst_strchr(s1, c)   strchr((const char *) s1, (int) c)
#define nst_strlen(s)       strlen((const char *) s)


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define nst_memzero(buf, n)       (void) memset(buf, 0, n)
#define nst_memset(buf, c, n)     (void) memset(buf, c, n)


#if (NST_MEMCPY_LIMIT)

void *nst_memcpy(void *dst, void *src, size_t n);
#define nst_cpymem(dst, src, n)   ((u_char *) nst_memcpy(dst, src, n)) + (n)

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define nst_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define nst_cpymem(dst, src, n)   ((u_char *) memcpy(dst, src, n)) + (n)

#endif


#if ( __INTEL_COTPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static nst_inline u_char *
nst_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return nst_cpymem(dst, src, len);
    }
}

#else

#define nst_copy                  nst_cpymem

#endif

#define static_strlen(x) (sizeof((x)) - 1)

/* msvc and icc7 compile memcmp() to the inline loop */
#define nst_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)

/* for nst_genhash_t */
uint32_t nst_genhash_mstr(const nst_str_t *str);
/* for nst_genhash_t */
int nst_str_cmp(const nst_str_t *str1, const nst_str_t *str2);

u_char *nst_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *nst_pstrdup(struct nst_pool_s *pool, nst_str_t *src);
u_char * nst_sprintf(u_char *buf, const char *fmt, ...);
u_char * nst_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char *nst_vsnprintf(u_char *buf, size_t max, const char *fmt, va_list args);

nst_int_t nst_strcasecmp(const u_char *s1, const u_char *s2);
nst_int_t nst_strncasecmp(const u_char *s1, const u_char *s2, size_t n);

u_char *nst_strnstr(u_char *s1, char *s2, size_t n);

u_char *nst_strstrn(u_char *s1, char *s2, size_t n);
u_char *nst_strcasestrn(u_char *s1, char *s2, size_t n);

nst_int_t nst_rstrncmp(u_char *s1, u_char *s2, size_t n);
nst_int_t nst_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
nst_int_t nst_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);

nst_uint_t nst_atoui(const u_char *line, size_t n);
nst_int_t nst_atoi(u_char *line, size_t n);
ssize_t nst_atosz(u_char *line, size_t n);
off_t nst_atoof(u_char *line, size_t n);
time_t nst_atotm(u_char *line, size_t n);
nst_int_t nst_hextoi(u_char *line, size_t n);

u_char *nst_hex_dump(u_char *dst, u_char *src, size_t len);


#define nst_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define nst_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void nst_encode_base64(nst_str_t *dst, nst_str_t *src);
nst_int_t nst_decode_base64(nst_str_t *dst, nst_str_t *src);

uint32_t nst_utf_decode(u_char **p, size_t n);
size_t nst_utf_length(u_char *p, size_t n);
u_char *nst_utf_cpystrn(u_char *dst, u_char *src, size_t n);
u_char * nst_xstrdup(u_char *src);


#define NST_ESCAPE_URI         0
#define NST_ESCAPE_ARGS        1
#define NST_ESCAPE_HTML        2
#define NST_ESCAPE_REFRESH     3
#define NST_ESCAPE_MEMCACHED   4
#define NST_ESCAPE_MAIL_AUTH   5

#define NST_UNESCAPE_URI       1
#define NST_UNESCAPE_REDIRECT  2

uintptr_t nst_escape_uri(u_char *dst, u_char *src, size_t size,
    nst_uint_t type);
void nst_unescape_uri(u_char **dst, u_char **src, size_t size, nst_uint_t type);
uintptr_t nst_escape_html(u_char *dst, u_char *src, size_t size);



void nst_sort(void *base, size_t n, size_t size,
    nst_int_t (*cmp)(const void *, const void *));
#define nst_qsort             qsort


#define nst_value_helper(n)   #n
#define nst_value(n)          nst_value_helper(n)


#endif /* _NST_STRING_H_INCLUDED_ */
