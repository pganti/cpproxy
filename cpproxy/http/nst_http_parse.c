#include "nst_http_request.h"
#include "nst_http_transaction.h"

#include <nst_iobuf.h>

#include <stdint.h>


static uint32_t  usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
#if (NST_WIN32)
    0xefffffff, /* 1110 1111 1111 1111  1111 1111 1111 1111 */
#else
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
#endif

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};


#if (NST_HAVE_LITTLE_ENDIAN && NST_HAVE_NONALIGNED)

#define nst_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define nst_str3Ocmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define nst_str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define nst_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && m[4] == c4

#define nst_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)

#define nst_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define nst_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define nst_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
        && m[8] == c8

#else /* !(NST_HAVE_LITTLE_ENDIAN && NST_HAVE_NONALIGNED) */

#define nst_str3_cmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2

#define nst_str3Ocmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[2] == c2 && m[3] == c3

#define nst_str4cmp(m, c0, c1, c2, c3)                                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3

#define nst_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#define nst_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5

#define nst_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6

#define nst_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7

#define nst_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7 && m[8] == c8

#endif


/* gcc, icc, msvc and others compile these switches as an jump table */

nst_status_e
nst_http_parse_request_line(nst_http_request_t *r, nst_iobuf_t *b)
{
    u_char  c, ch, *p, *m;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host,
        sw_port,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done
    } state;

    state = r->req_ln.state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            r->req_ln.request_start = p;

            if (ch == CR || ch == LF) {
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NST_HTTP_PARSE_INVALID_METHOD;
            }

            state = sw_method;
            break;

        case sw_method:
            if (ch == ' ') {
                r->req_ln.method_end = p - 1;
                m = r->req_ln.request_start;

                switch (p - m) {

                case 3:
                    if (nst_str3_cmp(m, 'G', 'E', 'T', ' ')) {
                        r->req_ln.method = NST_HTTP_GET;
                        break;
                    }

                    if (nst_str3_cmp(m, 'P', 'U', 'T', ' ')) {
                        r->req_ln.method = NST_HTTP_PUT;
                        break;
                    }

                    break;

                case 4:
                    if (m[1] == 'O') {

                        if (nst_str3Ocmp(m, 'P', 'O', 'S', 'T')) {
                            r->req_ln.method = NST_HTTP_POST;
                            break;
                        }

                        if (nst_str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
                            r->req_ln.method = NST_HTTP_COPY;
                            break;
                        }

                        if (nst_str3Ocmp(m, 'M', 'O', 'V', 'E')) {
                            r->req_ln.method = NST_HTTP_MOVE;
                            break;
                        }

                        if (nst_str3Ocmp(m, 'L', 'O', 'C', 'K')) {
                            r->req_ln.method = NST_HTTP_LOCK;
                            break;
                        }

                    } else {

                        if (nst_str4cmp(m, 'H', 'E', 'A', 'D')) {
                            r->req_ln.method = NST_HTTP_HEAD;
                            break;
                        }
                    }

                    break;

                case 5:
                    if (nst_str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
                        r->req_ln.method = NST_HTTP_MKCOL;
                    }

                    if (nst_str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
                        r->req_ln.method = NST_HTTP_TRACE;
                    }

                    break;

                case 6:
                    if (nst_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
                        r->req_ln.method = NST_HTTP_DELETE;
                        break;
                    }

                    if (nst_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
                        r->req_ln.method = NST_HTTP_UNLOCK;
                        break;
                    }

                    if (nst_str6cmp(m, 'C', 'O', 'N', 'N','E','C'))  {
                        r->req_ln.method = NST_HTTP_MCON;
                        break;
                    }

                    break;

                case 7:
                    if (nst_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                    {
                        r->req_ln.method = NST_HTTP_OPTIONS;
                    }

                    break;

                case 8:
                    if (nst_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
                    {
                        r->req_ln.method = NST_HTTP_PROPFIND;
                    }

                    break;

                case 9:
                    if (nst_str9cmp(m,
                            'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
                    {
                        r->req_ln.method = NST_HTTP_PROPPATCH;
                    }

                    break;
                }

                state = sw_spaces_before_uri;
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NST_HTTP_PARSE_INVALID_METHOD;
            }

            break;

        /* space* before URI */
        case sw_spaces_before_uri:

            if (ch == '/' ){
                r->req_ln.uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                r->req_ln.schema_start = p;
                state = sw_schema;
                break;
            }

            switch (ch) {
            case ' ':
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                r->req_ln.schema_end = p;
                state = sw_schema_slash;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash:
            switch (ch) {
            case '/':
                state = sw_schema_slash_slash;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                r->req_ln.host_start = p + 1;
                state = sw_host;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                break;
            }

            r->req_ln.host_end = p;

            switch (ch) {
            case ':':
                state = sw_port;
                break;
            case '/':
                r->req_ln.uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                r->req_ln.uri_start = r->req_ln.schema_end + 1;
                r->req_ln.uri_end = r->req_ln.schema_end + 2;
                state = sw_http_09;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->req_ln.port_end = p;
                r->req_ln.uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                r->req_ln.port_end = p;
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                r->req_ln.uri_start = r->req_ln.schema_end + 1;
                r->req_ln.uri_end = r->req_ln.schema_end + 2;
                state = sw_http_09;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                r->req_ln.uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                goto done;
            case '.':
                r->req_flags.complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                r->req_flags.quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->req_flags.complex_uri = 1;
                state = sw_uri;
                break;
#if (NST_WIN32)
            case '\\':
                r->req_flags.complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                r->req_ln.args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->req_flags.complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->req_flags.plus_in_uri = 1;
                break;
            case '\0':
                r->req_flags.zero_in_uri = 1;
                break;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case '/':
                r->req_ln.uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '.':
                r->req_ln.uri_ext = p + 1;
                break;
            case ' ':
                r->req_ln.uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                goto done;
#if (NST_WIN32)
            case '\\':
                r->req_ln.complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                r->req_flags.quoted_uri = 1;
                state = sw_uri;
                break;
            case '?':
                r->req_ln.args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->req_flags.complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->req_flags.plus_in_uri = 1;
                break;
            case '\0':
                r->req_flags.zero_in_uri = 1;
                break;
            }
            break;

        /* URI */
        case sw_uri:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case ' ':
                r->req_ln.uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->req_ln.uri_end = p;
                r->req_ln.http_minor = 9;
                goto done;
            case '#':
                r->req_flags.complex_uri = 1;
                break;
            case '\0':
                r->req_flags.zero_in_uri = 1;
                break;
            }
            break;

        /* space+ after URI */
        case sw_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->req_ln.http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->req_ln.http_minor = 9;
                goto done;
            case 'H':
                r->req_ln.http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }

            r->req_ln.http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }

            r->req_ln.http_major = r->req_ln.http_major * 10 + ch - '0';
            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }

            r->req_ln.http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                goto done;
            }

            if (ch == ' ') {
                state = sw_spaces_after_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }

            r->req_ln.http_minor = r->req_ln.http_minor * 10 + ch - '0';
            break;

        case sw_spaces_after_digit:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* end of request line */
        case sw_almost_done:
            r->req_ln.request_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NST_HTTP_PARSE_INVALID_REQUEST;
            }
        }
    }

    b->pos = p;
    r->req_ln.state = state;

    return NST_AGAIN;

done:

    b->pos = p + 1;

    if (r->req_ln.request_end == NULL) {
        r->req_ln.request_end = p;
    }

    r->req_ln.http_version = r->req_ln.http_major * 1000 + r->req_ln.http_minor;
    r->req_ln.state = sw_start;

    if (r->req_ln.http_version == 9 && r->req_ln.method != NST_HTTP_GET) {
        return NST_HTTP_PARSE_INVALID_09_METHOD;
    }

    return NST_OK;
}


nst_status_e
nst_http_parse_header_line(nst_http_request_t *r, nst_iobuf_t *b,
                           nst_uint_t allow_underscores)
{
    u_char      c, ch, *p;
    nst_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = r->hdr_parsing.state;
    hash = r->hdr_parsing.header_hash;
    i = r->hdr_parsing.lowcase_index;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            r->req_flags.invalid_header = 0;

            switch (ch) {
            case CR:
                r->hdr_parsing.header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                r->hdr_parsing.header_end = p;
                goto header_done;
            default:
                state = sw_name;
                r->hdr_parsing.header_name_start = p;

                c = lowcase[ch];

                if (c) {
                    hash = nst_hash(0, c);
                    r->hdr_parsing.lowcase_header[0] = c;
                    i = 1;
                    break;
                }

                r->req_flags.invalid_header = 1;

                break;

            }
            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                hash = nst_hash(hash, c);
                r->hdr_parsing.lowcase_header[i++] = c;
                i &= (NST_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == '_') {
                if (allow_underscores) {
                    hash = nst_hash(hash, ch);
                    r->hdr_parsing.lowcase_header[i++] = ch;
                    i &= (NST_HTTP_LC_HEADER_LEN - 1);

                } else {
                    r->req_flags.invalid_header = 1;
                }

                break;
            }

            if (ch == ':') {
                r->hdr_parsing.header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                r->hdr_parsing.header_name_end = p;
                r->hdr_parsing.header_start = p;
                r->hdr_parsing.header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                r->hdr_parsing.header_name_end = p;
                r->hdr_parsing.header_start = p;
                r->hdr_parsing.header_end = p;
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && r->upstream
                && p - r->hdr_parsing.header_name_start == 4
                && nst_strncmp(r->hdr_parsing.header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            r->req_flags.invalid_header = 1;

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->hdr_parsing.header_start = p;
                r->hdr_parsing.header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->hdr_parsing.header_start = p;
                r->hdr_parsing.header_end = p;
                goto done;
            default:
                r->hdr_parsing.header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                r->hdr_parsing.header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                r->hdr_parsing.header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->hdr_parsing.header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NST_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NST_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    b->pos = p;
    r->hdr_parsing.state = state;
    r->hdr_parsing.header_hash = hash;
    r->hdr_parsing.lowcase_index = i;

    return NST_AGAIN;

done:

    b->pos = p + 1;
    r->hdr_parsing.state = sw_start;
    r->hdr_parsing.header_hash = hash;
    r->hdr_parsing.lowcase_index = i;

    return NST_OK;

header_done:

    b->pos = p + 1;
    r->hdr_parsing.state = sw_start;

    return NST_HTTP_PARSE_HEADER_DONE;
}


nst_status_e
nst_http_parse_complex_uri(nst_http_request_t *r, bool merge_slashes)
{
    u_char  c, ch, decoded, *p, *u;
    enum {
        sw_usual = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
#if (NST_WIN32)
        sw_dot_dot_dot,
#endif
        sw_quoted,
        sw_quoted_second
    } state, quoted_state;

#if (NST_SUPPRESS_WARN)
    decoded = '\0';
    quoted_state = sw_usual;
#endif

    state = sw_usual;
    p = r->req_ln.uri_start;
    u = r->req_ln.uri.data;
    r->req_ln.uri_ext = NULL;
    r->req_ln.args_start = NULL;

    ch = *p++;

    while (p <= r->req_ln.uri_end) {

        /*
         * we use "ch = *p++" inside the cycle, but this operation is safe,
         * because after the URI there is always at least one charcter:
         * the line feed
         */

        nst_log_debug4(NST_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "s:%d in:'%Xd:%c', out:'%c'", state, ch, ch, *u);

        switch (state) {

        case sw_usual:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch(ch) {
#if (NST_WIN32)
            case '\\':
                r->req_ln.uri_ext = NULL;

                if (p == r->req_ln.uri_start + r->req_ln.uri.len) {

                    /*
                     * we omit the last "\" to cause redirect because
                     * the browsers do not treat "\" as "/" in relative URL path
                     */

                    break;
                }

                state = sw_slash;
                *u++ = '/';
                break;
#endif
            case '/':
                r->req_ln.uri_ext = NULL;
                state = sw_slash;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->req_ln.args_start = p;
                goto args;
            case '#':
                goto done;
            case '.':
                r->req_ln.uri_ext = u + 1;
                *u++ = ch;
                break;
            case '+':
                r->req_flags.plus_in_uri = 1;
            default:
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_slash:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch(ch) {
#if (NST_WIN32)
            case '\\':
                break;
#endif
            case '/':
                if (!merge_slashes) {
                    *u++ = ch;
                }
                break;
            case '.':
                state = sw_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->req_ln.args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                r->req_flags.plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch(ch) {
#if (NST_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u--;
                break;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->req_ln.args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                r->req_flags.plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot_dot:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch(ch) {
#if (NST_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u -= 4;
                if (u < r->req_ln.uri.data) {
                    return NST_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->req_ln.args_start = p;
                goto args;
            case '#':
                goto done;
#if (NST_WIN32)
            case '.':
                state = sw_dot_dot_dot;
                *u++ = ch;
                break;
#endif
            case '+':
                r->req_flags.plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

#if (NST_WIN32)
        case sw_dot_dot_dot:

            if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch(ch) {
            case '\\':
            case '/':
                state = sw_slash;
                u -= 5;
                if (u < r->req_ln.uri.data) {
                    return NST_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*u != '/') {
                    u--;
                }
                if (u < r->req_ln.uri.data) {
                    return NST_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->req_ln.args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                r->req_ln.plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;
#endif

        case sw_quoted:
            r->req_flags.quoted_uri = 1;

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            return NST_HTTP_PARSE_INVALID_REQUEST;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (ch == '%') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;
                }

                if (ch == '#') {
                    *u++ = ch;
                    ch = *p++;

                } else if (ch == '\0') {
                    r->req_flags.zero_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (ch == '?') {
                    *u++ = ch;
                    ch = *p++;

                } else if (ch == '+') {
                    r->req_flags.plus_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            return NST_HTTP_PARSE_INVALID_REQUEST;
        }
    }

done:

    r->req_ln.uri.len = u - r->req_ln.uri.data;

    if (r->req_ln.uri_ext) {
        r->req_ln.exten.len = u - r->req_ln.uri_ext;
        r->req_ln.exten.data = r->req_ln.uri_ext;
    }

    r->req_ln.uri_ext = NULL;

    return NST_OK;

args:

    while (p < r->req_ln.uri_end) {
        if (*p++ != '#') {
            continue;
        }

        r->req_ln.args.len = p - 1 - r->req_ln.args_start;
        r->req_ln.args.data = r->req_ln.args_start;
        r->req_ln.args_start = NULL;

        break;
    }

    r->req_ln.uri.len = u - r->req_ln.uri.data;

    if (r->req_ln.uri_ext) {
        r->req_ln.exten.len = u - r->req_ln.uri_ext;
        r->req_ln.exten.data = r->req_ln.uri_ext;
    }

    r->req_ln.uri_ext = NULL;

    return NST_OK;
}


nst_status_e
nst_http_parse_unsafe_uri(nst_http_request_t *r, nst_str_t *uri,
    nst_str_t *args, nst_uint_t *flags)
{
    u_char  ch, *p;
    size_t  len;

    len = uri->len;
    p = uri->data;

    if (len == 0 || p[0] == '?') {
        goto unsafe;
    }

    if (p[0] == '.' && len == 3 && p[1] == '.' && (p[2] == '/'
#if (NST_WIN32)
                                                   || p[2] == '\\'
#endif
        ))
    {
        goto unsafe;
    }

    for ( /* void */ ; len; len--) {

        ch = *p++;

        if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
            continue;
        }

        if (ch == '?') {
            args->len = len - 1;
            args->data = p;
            uri->len -= len;

            return NST_OK;
        }

        if (ch == '\0') {
            *flags |= NST_HTTP_ZERO_IN_URI;
            continue;
        }

        if ((ch == '/'
#if (NST_WIN32)
             || ch == '\\'
#endif
            ) && len > 2)
        {
            /* detect "/../" */

            if (p[0] == '.' && p[1] == '.' && p[2] == '/') {
                goto unsafe;
            }

#if (NST_WIN32)

            if (p[2] == '\\') {
                goto unsafe;
            }

            if (len > 3) {

                /* detect "/.../" */

                if (p[0] == '.' && p[1] == '.' && p[2] == '.'
                    && (p[3] == '/' || p[3] == '\\'))
                {
                    goto unsafe;
                }
            }
#endif
        }
    }

    return NST_OK;

unsafe:

    NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                "r#:%ui c#:%ui unsafe URI \"%V\" is detected",
                r->id, r->htran->cli_connection->number, uri);

    return NST_ERROR;
}


nst_status_e
nst_http_parse_multi_header_lines(nst_array_t *headers, nst_str_t *name,
    nst_str_t *value)
{
    nst_uint_t         i;
    u_char            *start, *last, *end, ch;
    nst_table_elt_t  **h;

    h = headers->elts;

    for (i = 0; i < headers->nelts; i++) {

        nst_log_debug2(NST_LOG_DEBUG_HTTP, headers->pool->log, 0,
                       "parse header: \"%V: %V\"", &h[i]->key, &h[i]->value);

        if (name->len > h[i]->value.len) {
            continue;
        }

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

        while (start < end) {

            if (nst_strncasecmp(start, name->data, name->len) != 0) {
                goto skip;
            }

            for (start += name->len; start < end && *start == ' '; start++) {
                /* void */
            }

            if (value == NULL) {
                if (start == end || *start == ',') {
                    return i;
                }

                goto skip;
            }

            if (start == end || *start++ != '=') {
                /* the invalid header value */
                goto skip;
            }

            while (start < end && *start == ' ') { start++; }

            for (last = start; last < end && *last != ';'; last++) {
                /* void */
            }

            value->len = last - start;
            value->data = start;

            return i;

        skip:

            while (start < end) {
                ch = *start++;
                if (ch == ';' || ch == ',') {
                    break;
                }
            }

            while (start < end && *start == ' ') { start++; }
        }
    }

    return NST_DECLINED;
}

ssize_t
nst_http_validate_host(u_char *host, size_t len)
{
    u_char      ch;
    size_t      i, last;
    nst_uint_t  dot;

    last = len;
    dot = 0;

    for (i = 0; i < len; i++) {
        ch = host[i];

        if (ch == '.') {
            if (dot) {
                return -1;
            }

            dot = 1;
            continue;
        }

        dot = 0;

        if (ch == ':') {
            last = i;
            continue;
        }

        if (ch == '/' || ch == '\0') {
            return -1;
        }

#if (NGX_WIN32)
        if (ch == '\\') {
            return -1;
        }
#endif
    }

    if (dot) {
        last--;
    }

    return last;
}
