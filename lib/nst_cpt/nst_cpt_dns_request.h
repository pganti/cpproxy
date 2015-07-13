#ifndef _CPT_DNS_REQUEST_H
#define _CPT_DNS_REQUEST_H

struct cpt_dns_request_s
{
    DECLARE_CPT_REQUEST(DNS_REQ_TYPE_DNS);

    const char *mapped_cdc_name;
};

#endif
