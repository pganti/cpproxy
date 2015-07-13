#ifndef _NST_HTTP_DEFAUTLS_H_
#define _NST_HTTP_DEFAULTS_H_

#define NST_HTTP_REQ_LOG_COMMENT_BUF_SIZE (24)
#define NST_HTTP_REQ_POOL_SIZE          (4096)
#define NST_HTTP_SMALL_REQ_HDR_BUF_SIZE (1460)
#define NST_HTTP_LARGE_REQ_HDR_BUF_SIZE (4380) /* 1460 * 3 */
#define NST_HTTP_REQ_READ_BUF_SIZE      (1460) 
#define NST_HTTP_RESP_READ_BUF_SIZE     (8760) /* 1460 * 6 */
#define NST_HTTP_MAX_REQ_HDR_BUF_SIZE   (8760) /* 1460 * 6 */

#define NST_HTTP_DF_PORT                (80)
#define NST_HTTPS_DF_PORT               (443)

#endif
