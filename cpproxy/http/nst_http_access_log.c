#include "nst_http_access_log.h"

#include "nst_http_var.h"

#include <nst_cfg_common.h>
#include <nst_cfg_domain.h>

#include <nst_http_request.h>
/* #include <nst_http_variables.h> */

#include <nst_times.h>
#include <nst_vector.h>
#include <nst_log.h>
#include <nst_string.h>

#define NST_MAX_ACCESS_LOG_BUF_SIZE (8192)

static u_char *nst_http_access_log_time(nst_http_request_t *r,
                                        u_char *buf,
                                        size_t buf_size,
                                        const nst_http_var_t *var);

static u_char *nst_http_access_log_request_id(nst_http_request_t *r,
                                              u_char *buf,
                                              size_t buf_size,
                                              const nst_http_var_t *var);

#if 0
static u_char *nst_http_access_log_request_start_time(nst_http_request_t *r,
                                              u_char *buf,
                                              size_t buf_size,
                                              const nst_http_var_t *var);
#endif

static u_char * nst_http_access_log_request_comment(nst_http_request_t *r,
                                                    u_char *buf,
                                                    size_t buf_size,
                                                    const nst_http_var_t *var);
#if 0
static u_char *nst_http_access_log_ds_bytes_sent(nst_http_request_t *r,
                                                 u_char *buf,
                                                 size_t buf_size,
                                                 nst_http_var_t *ops);
static u_char *nst_http_access_log_ds_bytes_received(nst_http_request_t *r,
                                                     u_char *buf,
                                                     size_t buf_size,
                                                     nst_http_var_t *ops);

static u_char *nst_http_access_log_ups_bytes_sent(nst_http_request_t *r,
                                                  u_char *buf,
                                                  size_t buf_size,
                                                  nst_http_var_t *ops);
static u_char *nst_http_access_log_ups_bytes_received(nst_http_request_t *r,
                                                      u_char *buf,
                                                      size_t buf_size,
                                                      nst_http_var_t *ops);
static size_t nst_http_access_log_variable_getlen(nst_http_request_t *r,
                                                  uintptr_t data);
static u_char *nst_http_access_log_variable(nst_http_request_t *r,
                                            u_char *buf,
                                            nst_http_var_t *ops);
static uintptr_t nst_http_access_log_escape(u_char *dst, const u_char *src, size_t size);
#endif

static nst_cfg_domain_t dummy_domain;
static nst_str_t dummy_domain_name = nst_string("dummy_default_http_access_log");

static nst_str_t df_http_access_log_format = 
    nst_string("$time_local $rid $ds_req_x_nst_rid $ds_req_x_nst_real_ip "
               "($ds_bytes_received > $ds_remote_ip:$ds_remote_port, "
               "$ds_local_ip:$ds_local_port < $ds_bytes_sent) "
               "($ups_bytes_sent > $ups_local_ip:$ups_local_port, "
               "$ups_remote_ip:$ups_remote_port < $ups_bytes_received) "
               "$ds_req_method $ds_req_host $ups_stats $ds_stats "
               "[$req_comment]");

static nst_http_var_t nst_http_access_log_core_vars[] = {
    { nst_string("time_local"),
      sizeof("28/Sep/1970:12:00:00 +0600") - 1,
      NULL,
      nst_http_access_log_time,
      NULL,
      0 },

    { nst_string("rid"),
      NST_UINT_LEN,
      NULL,
      nst_http_access_log_request_id,
      NULL,
      0 },

    { nst_string("req_comment"),
      NST_HTTP_REQ_LOG_COMMENT_BUF_SIZE - 1,
      NULL,
      nst_http_access_log_request_comment,
      NULL,
      0 },

#if 0
    { nst_string("req_start_time"),
      static_strlen("20090304181152.544"),
      NULL,
      nst_http_access_log_request_start_time,
      NULL,
      0 },
    { nst_string("ds_body_bytes_sent"), NST_OFF_T_LEN,
                          nst_http_access_log_body_bytes_sent },
    { nst_string("ds_req_hdr_length"), NST_SIZE_T_LEN,
                          nst_http_access_log_request_length },
#endif
};

static u_char *
nst_http_access_log_time(nst_http_request_t *r,
                         u_char *buf,
                         size_t buf_size,
                         const nst_http_var_t *var)
{
    return nst_cpymem(buf,
                      nst_cached_http_log_time.data,
                      min(nst_cached_http_log_time.len, buf_size));
}

static u_char *
nst_http_access_log_request_id(nst_http_request_t *r,
                               u_char *buf,
                               size_t buf_size,
                               const nst_http_var_t *var)
{
    return nst_snprintf(buf, buf_size, "%ui", r->id);
}

#if 0
static u_char *
nst_http_access_log_request_start_time(nst_http_request_t *r,
                                       u_char *buf,
                                       size_t buf_size,
                                       const nst_http_var_t *var)
{
    nst_tm_t tm;

    nst_localtime(r->downstream_stats.start.sec, &tm);

    return nst_snprintf (buf,
                         buf_size,
                         "%04d%02d%02d%02d%02d%02d.%03d",
                         tm.nst_tm_year,
                         tm.nst_tm_mon,
                         tm.nst_tm_mday,
                         tm.nst_tm_hour,
                         tm.nst_tm_min,
                         tm.nst_tm_sec,
                         r->downstream_stats.start.msec);

}
#endif

static u_char *
nst_http_access_log_request_comment(nst_http_request_t *r,
                                    u_char *buf,
                                    size_t buf_size,
                                    const nst_http_var_t *var)
{
    if(*r->log_comment == '\0') {
        return nst_snprintf(buf, buf_size, "-");
    } else {
        return nst_snprintf(buf, buf_size, r->log_comment);
    }
}
static u_char *
nst_http_access_log_copy_short(nst_http_request_t *r,
                               u_char *buf,
                               size_t buf_size,
                               const nst_http_var_t *var)
{
    size_t     len;
    uintptr_t  data;

    len = min(var->max_len, buf_size);
    data = var->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
nst_http_access_log_copy_long(nst_http_request_t *r,
                              u_char *buf,
                              size_t buf_size,
                              const nst_http_var_t *var)
{
    return nst_cpymem(buf, (u_char *) var->data,
                      min(var->max_len, buf_size));
}

#if 0
static nst_status_e
nst_http_access_log_variable_compile(nst_http_access_log_ops_t *ops,
                                     nst_str_t *value,
                                     nst_vector_t **dynamic_vars)
{
    nst_int_t  index;

    index = nst_http_variables_get_index(value);
    if (index == -1) {
        return NST_ERROR;
    }

    ops->len = 0;
    ops->getlen = nst_http_access_log_variable_getlen;
    ops->run = nst_http_access_log_variable;
    ops->data = index;

    return NST_OK;
}


static size_t
nst_http_access_log_variable_getlen(nst_http_request_t *r,
                                    uintptr_t data)
{
    uintptr_t                   len;
    nst_http_variable_value_t  *value;

    value = nst_http_request_get_variable_by_index(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = nst_http_access_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
nst_http_access_log_variable(nst_http_request_t *r,
                             u_char *buf,
                             nst_http_access_log_ops_t *ops)
{
    nst_http_variable_value_t  *value;

    value = nst_http_request_get_variable_by_index(r, ops->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return nst_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) nst_http_access_log_escape(buf, value->data, value->len);
    }
}

static uintptr_t
nst_http_access_log_escape(u_char *dst, const u_char *src, size_t size)
{
    nst_uint_t      i, n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n  = 0;

        for (i = 0; i < size; i++) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
        }

        return (uintptr_t) n;
    }

    for (i = 0; i < size; i++) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
    }

    return (uintptr_t) dst;
}
#endif

nst_status_e
nst_http_access_log_compile(nst_cfg_domain_t *domain)
{
    u_char                *data, ch;
    size_t                 i, len;
    const nst_str_t       *domain_name;
    nst_str_t              format, var;
    nst_uint_t             bracket;
    nst_http_var_t        *new_v;
    const nst_http_var_t  *v;
    nst_vector_t          *new_vars = NULL;
    nst_status_e           ret = NST_OK;

    nst_assert(domain->http_access_log_vars == NULL);

    if(domain->http_access_log_format.len == 0) {
        nst_assert(domain != &dummy_domain);
        /* we are going to use the default */
        goto DONE;
    }

    format = domain->http_access_log_format;
    domain_name = nst_cfg_domain_get_name(domain);

    for (i = 0; i < format.len; i++) {
        if (format.data[i] != '%') {
            continue;
        }

        ch = format.data[i + 1];

        if ((ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z')
            || ch == '{')
        {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "the http-log-string-format \"%%name\" "
                        "in domain \"%V\" are not supported, "
                        "use the \"$variable\" instead",
                        domain_name);
            ret = NST_ERROR;
            goto DONE;
        }
    }

    new_vars = nst_vector_new(&nst_cfg_allocator,
                              NULL,
                              64,
                              sizeof(nst_http_var_t));
    if(!new_vars) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot allocate new log vars for http-access-log-format "
                    "in domain \"%V\"",
                    domain_name);
        ret = NST_ERROR;
        goto DONE;
    }

    i = 0;

    while (i < format.len) {

        if( !(new_v = nst_vector_push(new_vars)) ) {
            nst_vector_free(new_vars);
            return NST_ERROR;
        }

        nst_memzero(new_v, sizeof(*new_v));

        data = &format.data[i];

        if (format.data[i] == '$') {

            if (++i == format.len) {
                ret = NST_ERROR;
                goto DONE;
            }

            if (format.data[i] == '{') {
                bracket = 1;

                if (++i == format.len) {
                    ret = NST_ERROR;
                    goto DONE;
                }

                var.data = &format.data[i];

            } else {
                bracket = 0;
                var.data = &format.data[i];
            }

            for (var.len = 0; i < format.len; i++, var.len++) {
                ch = format.data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "the closing bracket in \"%V\" "
                            "variable is missing in the "
                            "http-access-log-format in domain \"%V\"",
                            &var, domain_name);
                nst_vector_free(new_vars);
                return NST_ERROR;
            }

            if (var.len == 0) {
                ret = NST_ERROR;
                goto DONE;
            }

            v = nst_http_var_get(&var);
            if(v) {
                memcpy(new_v, v, sizeof(*v));
                if(v->domain_cfg) {
                    v->domain_cfg(domain);
                }
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "cannot recognize variable \"%V\" in "
                            "http-access-log-format in domain \"%V\"",
                            &var, domain_name);
                ret = NST_ERROR;
                goto DONE;
            }

#if 0
            for (v = nst_http_access_log_vars; v->name.len; v++) {

                if (v->name.len == var.len
                    && nst_strncmp(v->name.data, var.data, var.len) == 0)
                {
                    ops->len = v->len;
                    ops->getlen = NULL;
                    ops->run = v->run;
                    ops->data = 0;

                    goto found;
                }
            }

            if (nst_http_access_log_variable_compile(ops,
                                                     &var,
                                                     domain_vars) != NST_OK) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "cannot recognize variable \"%V\" in "
                            "http-access-log-format in domain \"%V\"",
                            domain_name, format);
                nst_vector_free(opss);
                return NULL;
            }
            found:
#endif

            continue;

        } /* if(format.data[i] == '$' */

        i++;

        while (i < format.len && format.data[i] != '$') {
            i++;
        }

        len = &format.data[i] - data;

        if (len) {

            new_v->max_len = len;
            new_v->getlen = NULL;

            if (len <= sizeof(uintptr_t)) {
                new_v->write = nst_http_access_log_copy_short;
                new_v->data = 0;

                while (len--) {
                    new_v->data <<= 8;
                    new_v->data |= data[len];
                }

            } else {
                    new_v->write = nst_http_access_log_copy_long;
                    new_v->data = (uintptr_t) data;
            }
        }
    } /* while (i < format.len) */

DONE:
    if(ret == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "invalid http-access-log-format \"%V\" in domain \"%V\"",
                    &format,
                    domain_name);
        nst_vector_free(new_vars);
        new_vars = NULL;
    } 

    if(new_vars) {
        domain->http_access_log_vars = new_vars;
    } else if(domain != &dummy_domain) {
        memcpy(&domain->var_flags,
               &dummy_domain.var_flags,
               sizeof(domain->var_flags));
    }

    return ret;
}

void
nst_http_request_access_log(nst_http_request_t *r)
{
    static u_char  access_log_buf[NST_MAX_ACCESS_LOG_BUF_SIZE];
    nst_str_t      access_log_mstr;
    u_char        *p;
    u_char        *last;
    size_t         len;
    nst_uint_t     i;
    nst_http_var_t *var;
    nst_vector_t   *vars;
    size_t         nvars;
    len = 0;
    vars = (r->domain_cfg && r->domain_cfg->http_access_log_vars) ?
        r->domain_cfg->http_access_log_vars : dummy_domain.http_access_log_vars;

    nvars = nst_vector_get_nelts(vars);
    p = access_log_buf;
    last = access_log_buf + NST_MAX_ACCESS_LOG_BUF_SIZE;
    for(i = 0; i < nvars && p < last; i++) {
        var = nst_vector_get_elt_at(vars, i);
        p = var->write(r, p, last - p, var);
    }

    access_log_mstr.data = access_log_buf;
    if(p < last) {
        *p = '\0'; /* mostly for gdb */
        access_log_mstr.len = p - access_log_buf;
    } else {
        access_log_buf[NST_MAX_ACCESS_LOG_BUF_SIZE - 1] = '\0'; /* mostly for gdb */
        access_log_mstr.len = NST_MAX_ACCESS_LOG_BUF_SIZE -1;
    }

    NST_ACCESS_LOG("%V", &access_log_mstr);
}

nst_status_e
nst_http_access_log_init(void)
{
    nst_str_t *alias;

    nst_memzero(&dummy_domain, sizeof(dummy_domain));
    dummy_domain.http_access_log_format = df_http_access_log_format;
    dummy_domain.aliases = nst_vector_new(&nst_cfg_allocator,
                                          NULL,
                                          1,
                                          sizeof(nst_str_t));
    alias = nst_vector_push(dummy_domain.aliases);
    *alias = dummy_domain_name;

    if(nst_http_var_add(nst_http_access_log_core_vars,
                        sizeof(nst_http_access_log_core_vars)/
                        sizeof(nst_http_access_log_core_vars[0]))
       == NST_ERROR)
        return NST_ERROR;

    nst_http_access_log_compile(&dummy_domain);

    return (dummy_domain.http_access_log_vars ? NST_OK : NST_ERROR);
}

void
nst_http_access_log_reset(void)
{
    nst_vector_free(dummy_domain.aliases);
    nst_vector_free(dummy_domain.http_access_log_vars);
}
