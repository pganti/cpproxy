/* always includes nst_config.h first in the .h file */
#include <nst_config.h>

/* local includes */
#include "nst_http_parse.h"
#include "nst_http_req_header.h"
#include "nst_http_transaction.h"
#include "nst_http_defaults.h"

/* libevent includes */
#include <nst_io_ops.h>
#include <nst_connection.h>
#include <nst_cfg_svc.h>

/* libcore includes */
#include <nst_time.h>

/* sys and std includes */
#include <time.h>

#define NST_HTTP_MAX_URI_CHANGES           10
#define NST_HTTP_MAX_SUBREQUESTS           50

#define NST_HTTP_DISCARD_BUFFER_SIZE       4096
#define NST_HTTP_LINGERING_BUFFER_SIZE     4096


#define NST_HTTP_VERSION_9                 9
#define NST_HTTP_VERSION_10                1000
#define NST_HTTP_VERSION_11                1001

#define NST_HTTP_UNKNOWN                   0x0001
#define NST_HTTP_GET                       0x0002
#define NST_HTTP_HEAD                      0x0004
#define NST_HTTP_POST                      0x0008
#define NST_HTTP_PUT                       0x0010
#define NST_HTTP_DELETE                    0x0020
#define NST_HTTP_MKCOL                     0x0040
#define NST_HTTP_COPY                      0x0080
#define NST_HTTP_MOVE                      0x0100
#define NST_HTTP_OPTIONS                   0x0200
#define NST_HTTP_PROPFIND                  0x0400
#define NST_HTTP_PROPPATCH                 0x0800
#define NST_HTTP_LOCK                      0x1000
#define NST_HTTP_UNLOCK                    0x2000
#define NST_HTTP_TRACE                     0x4000
#define NST_HTTP_MCON                      0x8000
#define NST_HTTP_CONNECTION_CLOSE          1
#define NST_HTTP_CONNECTION_KEEP_ALIVE     2


#define NST_NONE                           1


#define NST_HTTP_PARSE_HEADER_DONE         1

#define NST_HTTP_CLIENT_ERROR              10
#define NST_HTTP_PARSE_INVALID_METHOD      10
#define NST_HTTP_PARSE_INVALID_REQUEST     11
#define NST_HTTP_PARSE_INVALID_09_METHOD   12

#define NST_HTTP_PARSE_INVALID_HEADER      13


#define NST_HTTP_ZERO_IN_URI               1
#define NST_HTTP_SUBREQUEST_IN_MEMORY      2


#define NST_HTTP_OK                        200
#define NST_HTTP_CREATED                   201
#define NST_HTTP_NO_CONTENT                204
#define NST_HTTP_PARTIAL_CONTENT           206

#define NST_HTTP_SPECIAL_RESPONSE          300
#define NST_HTTP_MOVED_PERMANENTLY         301
#define NST_HTTP_MOVED_TETPORARILY         302
#define NST_HTTP_NOT_MODIFIED              304

#define NST_HTTP_BAD_REQUEST               400
#define NST_HTTP_UNAUTHORIZED              401
#define NST_HTTP_FORBIDDEN                 403
#define NST_HTTP_NOT_FOUND                 404
#define NST_HTTP_NOT_ALLOWED               405
#define NST_HTTP_REQUEST_TIME_OUT          408
#define NST_HTTP_CONFLICT                  409
#define NST_HTTP_LENGTH_REQUIRED           411
#define NST_HTTP_PRECONDITION_FAILED       412
#define NST_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NST_HTTP_REQUEST_URI_TOO_LARGE     414
#define NST_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NST_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NST_HTTP_CLOSE                     444

#define NST_HTTP_OWN_CODES                 495

#define NST_HTTPS_CERT_ERROR               495
#define NST_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NST_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NST_HTTP_CLIENT_CLOSED_REQUEST     499


#define NST_HTTP_INTERNAL_SERVER_ERROR     500
#define NST_HTTP_NOT_ITPLEMENTED           501
#define NST_HTTP_BAD_GATEWAY               502
#define NST_HTTP_SERVICE_UNAVAILABLE       503
#define NST_HTTP_GATEWAY_TIME_OUT          504
#define NST_HTTP_VERSION_NOT_SUPPORTED     505
#define NST_HTTP_INSUFFICIENT_STORAGE      507

#define NST_HTTP_INT_ERROR_BASE            (600)
#define NST_HTTP_ERROR_RESP_FILTER         (NST_HTTP_INT_ERROR_BASE + 1)
#define NST_HTTP_ERROR_NH_NOT_FOUND        (NST_HTTP_INT_ERROR_BASE + 2)
#define NST_HTTP_ERROR_DOMAIN_NOT_FOUND    (NST_HTTP_INT_ERROR_BASE + 3)

#define NST_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NST_HTTP_WRITE_BUFFERED            0x10
#define NST_HTTP_GZIP_BUFFERED             0x20
#define NST_HTTP_SSI_BUFFERED              0x01
#define NST_HTTP_SUB_BUFFERED              0x02
#define NST_HTTP_COPY_BUFFERED             0x04


struct nst_cfg_domain_s;
struct nst_connection_s;
struct nst_event_s;
struct nst_pool_s;
struct nst_upstream_s;
struct nst_array_s;

typedef struct nst_http_request_s nst_http_request_t;
typedef enum nst_http_req_state_e nst_http_req_state_e;
typedef struct nst_http_request_line_s nst_http_request_line_t;
typedef struct nst_http_filter_flags_s nst_http_filter_flags_t;

typedef void (*nst_http_downstream_event_handler_f)(nst_http_request_t *r,
                                                    bool do_write);

/*! \brief The state of a HTTP request
 *
 */
enum nst_http_req_state_e {
    NST_HTTP_REQ_STATE_INITING_REQ            = 0, /*!< init state */

    NST_HTTP_REQ_STATE_READING_REQ            = 1, /*!< reading request header
                                                    */
    NST_HTTP_REQ_STATE_PROCESS_REQ            = 2, /*!< processing request
                                                    *  header
                                                    */

    NST_HTTP_REQ_STATE_RESOLVE_UPSTREAM       = 3, /*!< resolving hostname
                                                    *   of upstream
                                                    */
    NST_HTTP_REQ_STATE_CONNECT_UPSTREAM       = 4, /*!< TCP connecting to
                                                    *   upstream
                                                    */

    NST_HTTP_REQ_STATE_WRITING_REQ_HDR        = 5, /*!< writing request header
                                                    *   to upstream
                                                    */
    NST_HTTP_REQ_STATE_RELAY_REQ_BODY         = 6, /*!< relaying request body
                                                    *   to upstream
                                                    */

    NST_HTTP_REQ_STATE_READING_RESP_HDR       = 7, /*!< reading response
                                                    *   header from upstream
                                                    */
    NST_HTTP_REQ_STATE_RELAY_RESP_BODY        = 8, /*!< relaying response
                                                    *   body to downstream
                                                    */

    NST_HTTP_REQ_STATE_LINGERING_CLOSE        = 9, /*!< not used */
    NST_HTTP_REQ_STATE_KEEPALIVE_STATE        = 10, /*!< idle keepalive 
                                                     *    downstream connection
                                                     */

    NST_HTTP_REQ_STATE_TUNNEL_RELAY           = 11, /*!< Bindly tunneling
                                                     *   data between
                                                     *   downstream and upstream
                                                     */

    _NUM_NST_HTTP_REQ_STATE                   = 12,
};

/*! Contains information of a parsed HTTP request line
 *
 *  A request line is the very first line of a HTTP request header.
 *  For example, "GET / HTTP/1.1\r\n"
 */
struct nst_http_request_line_s {
        nst_uint_t                        state;
        nst_uint_t                        method;
        nst_uint_t                        http_version;

        nst_str_t                         request_line; /* NULL terminated */
        nst_str_t                         uri;
        nst_str_t                         args;
        nst_str_t                         exten;
        nst_str_t                         unparsed_uri;

        nst_str_t                         method_name;
        nst_str_t                         http_protocol;

        u_char                           *uri_start;
        u_char                           *uri_end;
        u_char                           *uri_ext;
        u_char                           *args_start;
        u_char                           *request_start;
        u_char                           *request_end;
        u_char                           *method_end;
        u_char                           *schema_start;
        u_char                           *schema_end;
        u_char                           *host_start;
        u_char                           *host_end;
        u_char                           *port_start;
        u_char                           *port_end;

        unsigned                          http_minor:16;
        unsigned                          http_major:16;
};

struct nst_http_filter_flags_s {
    unsigned done:1;
    unsigned truncated:1;
    unsigned error:1;
};


/*! The main struct to describe a HTTP request. It contains objects such
 *  as downstream connection, upstream object (struct nst_http_upstream_s)
 *  and parsed request line(struct nst_http_req_line_s)...etc.
 *
 */
struct nst_http_request_s {
    nst_uint_t                        id; /* request id */

    nst_http_req_state_e              state;

    nst_int_t                         http_error;

    struct nst_http_transaction_s    *htran;

    struct nst_pool_s                *pool; 

    struct nst_cfg_domain_s          *domain_cfg;

    nst_http_req_header_t             parsed_req_hdr; /* parsed request header */
    /* nst_http_headers_out_t            parsed_resp_hdr; */ /* parsed and processed
                                                    * response header
                                                    */
    nst_http_downstream_event_handler_f      read_event_handler;
    nst_http_downstream_event_handler_f      write_event_handler;

    struct nst_iobuf_s               *last_req_ln_iobuf;
    struct nst_iobuf_s               *last_req_hdr_iobuf;
    nst_iochain_t                     req_hdr_iochain_in;
    /* raw input from downstream before filtering */
    nst_iochain_t                     req_body_iochain_in;
    nst_iochain_t                     recycle_req_body_iochain_in;
    nst_iochain_t                     resp_iochain_out;
    /* nst_iochain_t                     req_iochain_out; */

    nst_log_level_t                   noc_log_lvl;
    nst_log_level_t                   dbg_log_lvl;

    off_t                             request_length;

    char                         log_comment[NST_HTTP_REQ_LOG_COMMENT_BUF_SIZE];

    nst_http_request_line_t           req_ln;

    struct {
        /* URI with "/." and on Win32 with "//" */
        unsigned                          complex_uri:1;

        /* URI with "%" */
        unsigned                          quoted_uri:1;

        /* URI with "+" */
        unsigned                          plus_in_uri:1;

        /* URI with "\0" or "%00" */
        unsigned                          zero_in_uri:1;

        unsigned                          invalid_header:1;

        unsigned                          valid_location:1;
        unsigned                          valid_unparsed_uri:1;
        unsigned                          uri_changed:1;
        unsigned                          uri_changes:4;

        unsigned                          gzip:2;

        unsigned                          chunked:1;
        unsigned                          header_only:1;
        unsigned                          zero_body:1;
        unsigned                          keepalive:1;
        unsigned                          lingering_close:1;
        unsigned                          discard_body:1;
        unsigned                          internal:1;
        unsigned                          error_page:1;
        unsigned                          post_action:1;
        unsigned                          request_complete:1;
        unsigned                          request_output:1;
        unsigned                          header_sent:1;
        unsigned                          expect_tested:1;
        unsigned                          root_tested:1;
        unsigned                          done:1;
        unsigned                          logged:1;
        unsigned                          utf8:1;

        unsigned                          buffered:4;

        unsigned                          main_filter_need_in_memory:1;
        unsigned                          filter_need_in_memory:1;
        unsigned                          filter_need_temporary:1;
        unsigned                          allow_ranges:1;
    } req_flags;

    struct {
        unsigned                          chunked:1;
    } resp_flags;

    /* used to parse HTTP headers for both request and response */
    nst_http_header_parsing_t          hdr_parsing;

    struct {
        nst_timeval_ms_t                    start;
        nst_uint_t                          start_ms;
        /* nst_uint_t                          req_rdone_at_ms; */
        /* nst_uint_t                          resp_rdone_at_ms; */
    } downstream_stats;

    struct {
        unsigned      response_sent:1;
        unsigned      is_cache:1;
        unsigned      io_eof:1;
        unsigned      error:1;
    } downstream_flags;

    nst_http_filter_flags_t req_filter_flags;
    nst_http_filter_flags_t resp_filter_flags;


    struct nst_http_upstream_s       *upstream;

    struct nst_array_s               *upstream_states;
};

void nst_http_request_init(struct nst_event_s *rev);

void nst_http_request_error(nst_http_request_t *r, nst_int_t http_error);

/*! It closes the connection and free the request.
 *
 * Note: It is almost just a rename of ngx_http_close_connection
 */
void nst_http_downstream_close(struct nst_connection_s *c,
                               nst_io_close_reason_e reason);

void nst_http_downstream_error(nst_http_request_t *r,
                               int io_errno,
                               nst_int_t http_error);

void nst_http_request_finalizing(nst_http_request_t *r, bool do_write);

void nst_http_request_finalize(nst_http_request_t *r);

void nst_http_request_append_comment(nst_http_request_t *r,
                                     const char *comment,
                                     ssize_t len);

void nst_http_downstream_handler(struct nst_event_s *ev);

in_port_t nst_http_request_get_os_dst_port(const nst_http_request_t *r);

const nst_sockaddr_t *
nst_http_request_get_end_user_ip(const nst_http_request_t *r);

nst_str_t nst_http_request_get_upstream_host_domain(const nst_http_request_t *r);

in_port_t nst_http_request_get_upstream_host_port(const nst_http_request_t *r);

void nst_http_request_add_connection_error_comment(nst_http_request_t *r,
                                                   const nst_connection_t *c);

nst_msec_t nst_http_downstream_get_read_timeout(const nst_http_request_t *r);

void nst_http_downstream_check_broken_connection(nst_http_request_t *r,
                                                 bool is_write_event);

/* same as nst_http_close_request for now */
/* void nst_http_finalize_request(nst_http_request_t *r); */

static inline void
nst_http_request_set_http_error(nst_http_request_t *r, int http_error)
{
    if(r->http_error == 0)
        r->http_error = http_error;
}
static inline bool
nst_http_req_filter_is_done(const nst_http_request_t *r)
{
    return (r->req_filter_flags.done == 1);
}

static inline bool
nst_http_req_filter_is_error(const nst_http_request_t *r)
{
    return (r->req_filter_flags.error == 1);
}

static inline bool
nst_http_resp_filter_is_done(const nst_http_request_t *r)
{
    return (r->resp_filter_flags.done == 1);
}

static inline bool
nst_http_resp_filter_is_error(const nst_http_request_t *r)
{
    return (r->resp_filter_flags.error == 1);
}

static inline bool
nst_http_downstream_is_mp(const nst_http_request_t *r)
{
    return (r->htran->cli_connection->type == NST_CONN_TYPE_TP);
}

static inline bool
nst_http_downstream_is_tcp(const nst_http_request_t *r)
{
    return (r->htran->cli_connection->type == NST_CONN_TYPE_TCP);
}


static inline bool
nst_http_downstream_is_end_user(const nst_http_request_t *r)
{
    /* TODO: exclude cache later */
    return (r->htran->cli_connection->type == NST_CONN_TYPE_TCP);
}

static inline bool
nst_http_downstream_is_ssl(const nst_http_request_t *r)
{
    /* TODO: do the proper checking after SSL implementation */
    return FALSE;
}

static inline bool
nst_http_downstream_is_nst(const nst_http_request_t *r)
{
    return nst_http_downstream_is_mp(r); /* !! nst_http_downstream_is_cache */
}

/* is it a tunnel request? */
static inline bool
nst_http_request_is_tunnel(const nst_http_request_t *r)
{
    nst_connection_t *cli_c = r->htran->cli_connection;
    return ((cli_c->svc && cli_c->svc->type == NST_SVC_TYPE_TUNNEL)
            ||
            (r->req_ln.method == NST_HTTP_MCON));
}
/*
static nst_uint_t
nst_http_request_get_elapsed_msec(const nst_http_request_t *r)
{
    return nst_cached_time - start_at_ms;
}
*/
