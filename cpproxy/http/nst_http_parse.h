#ifndef _NST_HTTP_PARSE_H_
#define _NST_HTTP_PARSE_H_

#include "nst_config.h"

#include <nst_types.h>

#include <sys/types.h>

/* must be 2^n */
#define NST_HTTP_LC_HEADER_LEN             32

struct nst_array_s;
struct nst_str_s;
struct nst_http_request_s;
struct nst_iobuf_s;

typedef struct nst_http_header_parsing_s nst_http_header_parsing_t;
struct nst_http_header_parsing_s {
    nst_uint_t                     state;
    u_char                        *header_name_start;
    u_char                        *header_name_end;
    u_char                        *header_start;
    u_char                        *header_end;

    nst_uint_t                     header_hash;
    nst_uint_t                     lowcase_index;
    u_char                         lowcase_header[NST_HTTP_LC_HEADER_LEN];
};

nst_status_e nst_http_parse_request_line(struct nst_http_request_s *r,
                                         struct nst_iobuf_s *b);

nst_status_e nst_http_parse_header_line(struct nst_http_request_s *r,
                                        struct nst_iobuf_s *b,
                                        nst_uint_t allow_underscores);

nst_status_e nst_http_parse_complex_uri(struct nst_http_request_s *r,
                                        bool merge_slashes);

nst_status_e
nst_http_parse_unsafe_uri(struct nst_http_request_s *r,
                          struct nst_str_s *uri,
                          struct nst_str_s *args,
                          nst_uint_t *flags);

nst_status_e nst_http_parse_multi_header_lines(struct nst_array_s *headers,
                                               struct nst_str_s *name,
                                               struct nst_str_s *value);

ssize_t nst_http_validate_host(u_char *host, size_t len);

#endif
