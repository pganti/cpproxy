#include "nst_http_req_header.h"

#include "nst_http_parse.h"
#include "nst_http_header.h"
#include "nst_http_request.h"
#include "nst_http_transaction.h"

#include <nst_cpproxy_cfg.h>

#include <nst_connection.h>

#include <nst_palloc.h>
#include <nst_hash.h>
#include <nst_string.h>
#include <nst_types.h>

#include <stddef.h>

static nst_status_e nst_http_process_unique_header_line(nst_http_request_t *r,
                                                        nst_table_elt_t *h,
                                                        nst_uint_t offset);

static nst_status_e nst_http_process_header_line(nst_http_request_t *r,
                                              nst_table_elt_t *h,
                                              nst_uint_t offset);

static nst_status_e nst_http_process_host(nst_http_request_t *r,
                                           nst_table_elt_t *h,
                                           nst_uint_t offset);

static nst_status_e nst_http_process_connection(nst_http_request_t *r,
                                                nst_table_elt_t *h,
                                                nst_uint_t offset);
/*
static nst_status_e nst_http_process_content_length(nst_http_request_t *r,
                                                    nst_table_elt_t *h,
                                                    nst_uint_t offset);
i*/
static nst_status_e nst_http_process_user_agent(nst_http_request_t *r,
                                                nst_table_elt_t *h,
                                                nst_uint_t offset);
static nst_status_e nst_http_process_x_nst_real_ip(nst_http_request_t *r,
                                                   nst_table_elt_t *h,
                                                   nst_uint_t offset);
static nst_status_e nst_http_process_x_nst_rid(nst_http_request_t *r,
                                               nst_table_elt_t *h,
                                               nst_uint_t offset);


nst_hash_t nst_http_req_header_hash;

#if 0
static nst_str_t nst_http_req_hdr_no_copy[] = {
    nst_string("Connection"),
    nst_string("X-Forwarded-For"),
    nst_string("X-Msu-Real-IP"),
};
#endif

static nst_http_header_handler_t  nst_http_req_header_handlers[] = {
    { nst_string("Host"),
      offsetof(nst_http_req_header_t, host),
      nst_http_process_host },

    { nst_string("Connection"),
      offsetof(nst_http_req_header_t, connection),
      nst_http_process_connection },

    { nst_string("Content-Length"),
      offsetof(nst_http_req_header_t, content_length),
      nst_http_process_unique_header_line },

    { nst_string("Content-Type"),
      offsetof(nst_http_req_header_t, content_type),
      nst_http_process_header_line },

    { nst_string("Transfer-Encoding"),
      offsetof(nst_http_req_header_t, transfer_encoding),
      nst_http_process_header_line },

    { nst_string("Expect"),
      offsetof(nst_http_req_header_t, expect),
      nst_http_process_unique_header_line },

    { nst_string("User-Agent"),
      offsetof(nst_http_req_header_t, user_agent),
      nst_http_process_user_agent },

    { nst_string("Accept-Encoding"),
      offsetof(nst_http_req_header_t, accept_encoding),
      nst_http_process_header_line },

    { nst_string("X-Forwarded-For"),
      offsetof(nst_http_req_header_t, x_forwarded_for),
      nst_http_process_header_line },

    { nst_string(NST_HTTP_HDR_X_NST_REAL_IP),
      offsetof(nst_http_req_header_t, end_user_ip),
      nst_http_process_x_nst_real_ip },

    { nst_string(NST_HTTP_HDR_X_NST_RID),
      offsetof(nst_http_req_header_t, rid),
      nst_http_process_x_nst_rid },
};

nst_status_e
nst_http_req_header_hash_init(void)
{
    nst_array_t         headers_in;
    nst_hash_key_t     *hk;
    nst_hash_init_t     hash;
    nst_http_header_handler_t  *header;
    nst_pool_t         *temp_pool = NULL;
    nst_status_e        ret = NST_OK;

    size_t nnst_http_req_header_handlers
        = sizeof(nst_http_req_header_handlers)/sizeof(nst_http_req_header_handlers[0]);
    size_t i;

    temp_pool = nst_create_pool(1024, &nst_dl_logger);
    if(!temp_pool)
        return NST_ERROR;

    if (nst_array_init(&headers_in, temp_pool, 32, sizeof(nst_hash_key_t))
        != NST_OK)
    {
        ret = NST_ERROR;
        goto DONE;
    }

    for (i = 0; i < nnst_http_req_header_handlers; i++) {
        header = &nst_http_req_header_handlers[i];
        hk = nst_array_push(&headers_in);
        if (hk == NULL) {
            ret = NST_ERROR;
            goto DONE;
        }

        hk->key = header->name;
        hk->key_hash = nst_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &nst_http_req_header_hash;
    hash.key = nst_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = nst_align(64, nst_cacheline_size);
    hash.name = "req_header_hash";
    hash.pool = cpproxy_cfg_sticky_pool;
    hash.temp_pool = NULL;

    if (nst_hash_init(&hash, headers_in.elts, headers_in.nelts) != NST_OK) {
        ret = NST_ERROR;
        goto DONE;
    }

 DONE:
    if(temp_pool)
        nst_destroy_pool(temp_pool);
        
    return ret;
}

void
nst_http_req_header_init(nst_http_req_header_t *req_hdr, nst_pool_t *pool)
{
    req_hdr->connection_type = NST_HTTP_CONNECTION_CLOSE;
    req_hdr->content_length_n = -1;
    nst_list_init(&req_hdr->headers, pool, 20, sizeof(nst_table_elt_t));
}

static nst_status_e
nst_http_process_unique_header_line(nst_http_request_t *r,
                                    nst_table_elt_t *h,
                                    nst_uint_t offset)
{
    nst_table_elt_t  **ph;

    ph = (nst_table_elt_t **) ((char *) &r->parsed_req_hdr + offset);

    if (*ph == NULL) {
        *ph = h;
        return NST_OK;
    }

    NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                "r#:%ui c#:%ui "
                "client sent duplicate header: \"%V: %V\", "
                "previous value: \"%V: %V\"",
                r->id, r->htran->cli_connection->number,
                &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);

    return NST_ERROR;
}

static nst_status_e
nst_http_process_header_line(nst_http_request_t *r,
                             nst_table_elt_t *h,
                             nst_uint_t offset)
{
    nst_table_elt_t  **ph;

    ph = (nst_table_elt_t **) ((char *) &r->parsed_req_hdr + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NST_OK;
}


static nst_status_e 
nst_http_process_host(nst_http_request_t *r,
                      nst_table_elt_t *h,
                      nst_uint_t offset)
{
    ssize_t  len;

    if (r->parsed_req_hdr.host == NULL) {
        r->parsed_req_hdr.host = h;
    }

    len = nst_http_validate_host(h->value.data, h->value.len);

    if (len <= 0) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui c#:%ui "
                    "client sent invalid header: \"%V: %V\", ",
                    r->id, r->htran->cli_connection->number,
                    &h->key, &h->value);
                    
        nst_http_downstream_error(r, 0, NST_HTTP_BAD_REQUEST);
        return NST_ERROR;
    }

    /* the host name in req line takes precedence */
    if (r->parsed_req_hdr.server.len) {
        return NST_OK;
    }

    r->parsed_req_hdr.server.len = len;
    r->parsed_req_hdr.server.data = h->value.data;

    if((size_t)(len + 1) < h->value.len && h->value.data[len] == ':') {
        /* get the port */
        off_t tmp_porth;

        tmp_porth = nst_atoof(h->value.data + len + 1,
                              h->value.len - len - 1);
        if(tmp_porth > 0 && tmp_porth < 65536) {
            r->parsed_req_hdr.portn = htons((in_port_t)tmp_porth);
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "r#:%ui c#:%ui "
                        "client sent invalid header: \"%V: %V\", ",
                        r->id, r->htran->cli_connection->number,
                        &h->key, &h->value);
            return NST_ERROR;
        }
    }

    return NST_OK;
}

static nst_status_e
nst_http_process_connection(nst_http_request_t *r,
                            nst_table_elt_t *h,
                            nst_uint_t offset)
{
    if (nst_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->parsed_req_hdr.connection_type = NST_HTTP_CONNECTION_CLOSE;

    } else if (nst_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->parsed_req_hdr.connection_type = NST_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return NST_OK;
}
/*
static nst_status_e
nst_http_process_content_length(nst_http_request_t *r,
                                nst_table_elt_t *h,
                                nst_uint_t offset)
{
    if(nst_http_process_unique_header_line(r, h, offset) == NST_ERROR)
        return NST_ERROR;

    r->parsed_req_hdr.content_length_n = nst_atoof(h->value.data, h->value.len);
    if(r->parsed_req_hdr.content_length_n == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui c#:%ui "
                    "client sent invalid header: \"%V: %V\", ",
                    r->id, r->htran->cli_connection->number,
                    &h->key, &h->value);
        nst_http_downstream_error(r, 0, NST_HTTP_LENGTH_REQUIRED);
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}
*/
static nst_status_e
nst_http_process_user_agent(nst_http_request_t *r,
                            nst_table_elt_t *h,
                            nst_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (r->parsed_req_hdr.user_agent) {
        return NST_OK;
    }

    r->parsed_req_hdr.user_agent = h;

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = nst_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->parsed_req_hdr.browser_flags.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
                r->parsed_req_hdr.browser_flags.msie4 = 1;
                /* fall through */
            case '5':
            case '6':
            case '7':
            default:
                r->parsed_req_hdr.browser_flags.msie6 = 1;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (nst_strstrn(user_agent, "Opera", 5 - 1)) {
        r->parsed_req_hdr.browser_flags.opera = 1;
        r->parsed_req_hdr.browser_flags.msie = 0;
        r->parsed_req_hdr.browser_flags.msie4 = 0;
        r->parsed_req_hdr.browser_flags.msie6 = 0;
    }

    if (!r->parsed_req_hdr.browser_flags.msie 
        && !r->parsed_req_hdr.browser_flags.opera) {

        if (nst_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->parsed_req_hdr.browser_flags.gecko = 1;

        } else if (nst_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->parsed_req_hdr.browser_flags.konqueror = 1;
        }
    }

    return NST_OK;
}

nst_status_e
nst_http_process_x_nst_real_ip(nst_http_request_t *r,
                               nst_table_elt_t *h,
                               nst_uint_t offset)
{
    nst_sockaddr_t *end_user_ip;

    if(!nst_http_downstream_is_nst(r)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "got %V request header line from non pronto machine. ignored",
                    h->key);
        return NST_OK;
    }

    if (!r->parsed_req_hdr.end_user_ip) {
        end_user_ip = r->parsed_req_hdr.end_user_ip
            = nst_pcalloc(r->pool, sizeof(nst_sockaddr_t));
        if(!end_user_ip)
            return NST_ERROR;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui got double %V. ignored the last one",
                    r->id, h->key);
        end_user_ip = r->parsed_req_hdr.end_user_ip;
    }

    nst_sockaddr_init(end_user_ip,
                      (const char *)h->value.data,
                      0,
                      AF_INET);

    return NST_OK;
}

nst_status_e
nst_http_process_x_nst_rid(nst_http_request_t *r,
                           nst_table_elt_t *h,
                           nst_uint_t offset)
{
    if(!nst_http_downstream_is_nst(r)) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "r#:%ui got %V request header line from non pronto machine. ignored",
                    r->id, h->key);
        return NST_OK;
    }

    if (r->parsed_req_hdr.rid) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "r#:%ui got double %V. ignored the last one",
                    r->id, h->key);
    }

    r->parsed_req_hdr.rid = nst_atoui(h->value.data, h->value.len);

    return NST_OK;
}
