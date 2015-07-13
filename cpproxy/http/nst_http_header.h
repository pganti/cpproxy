#ifndef _NST_HTTP_HEADER_H_
#define _NST_HTTP_HEADER_H_

#include <nst_config.h>

#include <nst_string.h>
#include <nst_types.h>

#define NST_HTTP_HDR_HOST               "Host"
#define NST_HTTP_HDR_X_NST_REAL_IP      "X-Nst-Real-IP"
#define NST_HTTP_HDR_X_NST_RID          "X-Nst-RID"

#define static_hdr_name_strlen(x) (static_strlen(x) + 2) /* +2 for ": " */

struct nst_http_request_s;
struct nst_table_elt_s;
typedef nst_status_e (*nst_http_header_handler_f)(struct nst_http_request_s *r,
                                                  struct nst_table_elt_s *h,
                                                  nst_uint_t offset);

typedef struct nst_http_header_handler_s nst_http_header_handler_t;

struct nst_http_header_handler_s {
    nst_str_t                         name;
    nst_uint_t                        offset;
    nst_http_header_handler_f         handler;
};

#endif
