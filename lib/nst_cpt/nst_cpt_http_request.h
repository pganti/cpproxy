#ifndef _CPT_HTTP_REQUEST_H
#define _CPT_HTTP_REQUEST_H

struct cpt_http_request_s
{
    DECLARE_CPT_REQUEST(DNS_REQ_TYPE_HTTP);

    const char *method;
    const char *hostname;
    const char *port;
    const char *uri;
    const char *version;
    /* TODO: request headers */
};

#endif
