/* Always include myself first */
#include "nst_sockaddr.h"

/* libcore includes */
#include <nst_bjhash.h>
#include <nst_assert.h>
#include <nst_limits.h>
#include <nst_errno.h>

/* system includes */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

void
nst_sockaddr_reset(nst_sockaddr_t *nst_sockaddr)
{
    memset(nst_sockaddr, 0, sizeof(nst_sockaddr_t));
    nst_sockaddr->addr.inet.sin_family = AF_UNSPEC;
}

nst_status_e
nst_sockaddr_init(nst_sockaddr_t *nst_sockaddr,
                  const char *ipstr,
                  in_port_t porth,
                  sa_family_t family)
{
    size_t ipstrlen;

    nst_assert(family == AF_INET && "Only AF_INET is supported");

    ipstrlen = strlen(ipstr);
    if(ipstrlen + 1 > NST_MAX_IP_STR_BUF_SIZE) {
        errno = EINVAL;
        return NST_ERROR;
    }

    if(inet_pton(family, ipstr, &nst_sockaddr->addr.inet.sin_addr) <= 0) {
        return NST_ERROR;
    }
    nst_sockaddr->addr.inet.sin_family = family;
    nst_sockaddr->addr.inet.sin_port = htons(porth);

    memcpy(nst_sockaddr->ip_str, ipstr, ipstrlen + 1);
    nst_sockaddr->ip_mstr.data = (u_char *)nst_sockaddr->ip_str;
    nst_sockaddr->ip_mstr.len = ipstrlen;

    snprintf(nst_sockaddr->port_str, NST_MAX_PORT_STR_BUF_SIZE , "%u", porth);
    nst_sockaddr->port_str[NST_MAX_PORT_STR_BUF_SIZE - 1] = '\0';
    nst_sockaddr->port_mstr.data = (u_char *)nst_sockaddr->port_str;
    nst_sockaddr->port_mstr.len = strlen(nst_sockaddr->port_str);

    return NST_OK;
}

void
nst_sockaddr_init_by_sockaddr(nst_sockaddr_t *sockaddr,
                              const nst_sockaddr_t *src_sockaddr)
{
    memcpy(&sockaddr->addr, &src_sockaddr->addr, sizeof(sockaddr->addr));
    sockaddr->ip_str[0] = '\0';
    sockaddr->ip_mstr.data = (u_char *)sockaddr->ip_str;
    sockaddr->ip_mstr.len = 0;
    sockaddr->port_str[0] = '\0';
    sockaddr->port_mstr.data = (u_char *)sockaddr->port_str;
    sockaddr->port_mstr.len = 0;
}

void
nst_sockaddr_init_by_sa(nst_sockaddr_t *sockaddr,
                        const struct sockaddr *sa,
                        socklen_t addrlen)
{
    nst_assert(sa->sa_family == AF_INET && "Only AF_INET is supported");
    memcpy(&sockaddr->addr.inet, sa, addrlen);
    sockaddr->ip_str[0] = '\0';
    sockaddr->ip_mstr.data = (u_char *)sockaddr->ip_str;
    sockaddr->ip_mstr.len = 0;
    sockaddr->port_str[0] = '\0';
    sockaddr->port_mstr.data = (u_char *)sockaddr->port_str;
    sockaddr->port_mstr.len = 0;
}

void
nst_sockaddr_set_ip(nst_sockaddr_t *sockaddr,
                    sa_family_t family,
                    void *ipn)
{
    nst_assert(family == AF_INET && "Only AF_INET is supported");

    sockaddr->addr.inet.sin_family = family;
    if(ipn) {
        memcpy(&sockaddr->addr.inet.sin_addr,
               ipn, sizeof(sockaddr->addr.inet.sin_addr));
    } else {
        sockaddr->addr.inet.sin_addr.s_addr = INADDR_ANY;
    }
    sockaddr->ip_str[0] = '\0';
    sockaddr->ip_mstr.data = (u_char *)sockaddr->ip_str;
    sockaddr->ip_mstr.len = 0;
}

void
nst_sockaddr_set_port(nst_sockaddr_t *sockaddr, in_port_t portn)
{
    sockaddr->addr.inet.sin_family = AF_INET;
    sockaddr->addr.inet.sin_port = portn;
    sockaddr->port_str[0] = '\0';
    sockaddr->port_mstr.data = (u_char *)sockaddr->port_str;
    sockaddr->port_mstr.len = 0;
}

int
nst_sockaddr_get_family(const nst_sockaddr_t *nst_sockaddr)
{
    return nst_sockaddr->addr.inet.sin_family;
}

const struct sockaddr *
nst_sockaddr_get_sys_sockaddr(const nst_sockaddr_t *nst_sockaddr)
{
    nst_assert(nst_sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    return (struct sockaddr *)(&nst_sockaddr->addr.inet);
}

socklen_t
nst_sockaddr_get_sys_socklen(const nst_sockaddr_t *nst_sockaddr)
{
    nst_assert(nst_sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    return sizeof(nst_sockaddr->addr.inet);
}

static void
nst_sockaddr_do_get_ip_str(nst_sockaddr_t *sockaddr)
{
    sockaddr->ip_mstr.data = (u_char *)sockaddr->ip_str;

    if(sockaddr->addr.inet.sin_family == AF_UNSPEC) {
        memcpy(sockaddr->ip_str, "0.0.0.0", sizeof("0.0.0.0"));
        sockaddr->ip_mstr.len = static_strlen("0.0.0.0");
        return;
    }

    nst_assert(sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    if(inet_ntop(sockaddr->addr.inet.sin_family,
                 &sockaddr->addr.inet.sin_addr,
                 sockaddr->ip_str,
                 sizeof(sockaddr->ip_str))) {
        sockaddr->ip_mstr.len = strlen(sockaddr->ip_str);
    } else {
        sockaddr->ip_str[0] = '\0';
        sockaddr->ip_mstr.len = 0;
    }

}

static void
nst_sockaddr_do_get_port_str(nst_sockaddr_t *sockaddr)
{
    sockaddr->port_mstr.data = (u_char *)sockaddr->port_str;

    if(sockaddr->addr.inet.sin_family == AF_UNSPEC) {
        memcpy(sockaddr->port_str, "0", sizeof("0"));
        sockaddr->port_mstr.len = static_strlen("0");
        return;
    }

    nst_assert(sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    snprintf(sockaddr->port_str,
             NST_MAX_PORT_STR_BUF_SIZE,
             "%u",
             ntohs(sockaddr->addr.inet.sin_port));
    sockaddr->port_str[NST_MAX_PORT_STR_BUF_SIZE - 1] = '\0';
    sockaddr->port_mstr.len = strlen(sockaddr->port_str);
}

const nst_str_t *
nst_sockaddr_get_ip_mstr(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->ip_mstr.len)
        nst_sockaddr_do_get_ip_str((nst_sockaddr_t *)sockaddr);

    return &sockaddr->ip_mstr;
}

const char *
nst_sockaddr_get_ip_str(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->ip_mstr.len)
        nst_sockaddr_do_get_ip_str((nst_sockaddr_t *)sockaddr);

    return sockaddr->ip_str;
}

size_t
nst_sockaddr_get_ip_strlen(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->ip_mstr.len)
        nst_sockaddr_do_get_ip_str((nst_sockaddr_t *)sockaddr);

    return sockaddr->ip_mstr.len;
}

const nst_str_t *
nst_sockaddr_get_port_mstr(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->port_mstr.len)
        nst_sockaddr_do_get_port_str((nst_sockaddr_t *)sockaddr);

    return &sockaddr->port_mstr;
}

const char *
nst_sockaddr_get_port_str(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->port_mstr.len)
        nst_sockaddr_do_get_port_str((nst_sockaddr_t *)sockaddr);

    return sockaddr->port_str;
}

size_t
nst_sockaddr_get_port_strlen(const nst_sockaddr_t *sockaddr)
{
    if(!sockaddr->port_mstr.len)
        nst_sockaddr_do_get_port_str((nst_sockaddr_t *)sockaddr);

    return sockaddr->port_mstr.len;
}

in_port_t
nst_sockaddr_get_port(const nst_sockaddr_t *nst_sockaddr)
{
    nst_assert(nst_sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    return nst_sockaddr->addr.inet.sin_port;
}

nst_genhash_key_t
nst_genhash_sockaddr_ip(const void *key)
{
    const nst_sockaddr_t *nst_sockaddr = (const nst_sockaddr_t *)key;

    nst_assert(nst_sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    return nst_bjhash_uint32s(&nst_sockaddr->addr.inet.sin_addr.s_addr,
                              sizeof(nst_sockaddr->addr.inet.sin_addr.s_addr)/sizeof(uint32_t),
                              0);
}

nst_genhash_key_t
nst_genhash_sockaddr(const void *key)
{
    nst_sockaddr_t *nst_sockaddr = (nst_sockaddr_t *)key;
    uint32_t iphash;

    nst_assert(nst_sockaddr->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    iphash = nst_bjhash_uint32s(&nst_sockaddr->addr.inet.sin_addr.s_addr,
                                sizeof(nst_sockaddr->addr.inet.sin_addr.s_addr)/sizeof(uint32_t),
                                0);

    return nst_bjhash_bytes(&nst_sockaddr->addr.inet.sin_port,
                            sizeof(nst_sockaddr->addr.inet.sin_port),
                            iphash);
}

int
nst_sockaddr_cmp_ip(const void *s1, const void *s2)
{
    const nst_sockaddr_t *nst_sockaddr1 = (const nst_sockaddr_t *)s1;
    const nst_sockaddr_t *nst_sockaddr2 = (const nst_sockaddr_t *)s2;

    nst_assert(nst_sockaddr1->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");
    nst_assert(nst_sockaddr2->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    return memcmp(&nst_sockaddr1->addr.inet.sin_addr.s_addr,
                  &nst_sockaddr2->addr.inet.sin_addr.s_addr,
                  sizeof(nst_sockaddr1->addr.inet.sin_addr.s_addr));
}

int
nst_sockaddr_cmp(const void *s1, const void *s2)
{
    const nst_sockaddr_t *nst_sockaddr1 = (const nst_sockaddr_t *)s1;
    const nst_sockaddr_t *nst_sockaddr2 = (const nst_sockaddr_t *)s2;
    int rc;

    nst_assert(nst_sockaddr1->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");
    nst_assert(nst_sockaddr2->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    rc = memcmp(&nst_sockaddr1->addr.inet.sin_addr,
                &nst_sockaddr2->addr.inet.sin_addr,
                sizeof(nst_sockaddr1->addr.inet.sin_addr));
    if(rc) {
        return rc;
    } else {
        return memcmp(&nst_sockaddr1->addr.inet.sin_port,
                      &nst_sockaddr2->addr.inet.sin_port,
                      sizeof(nst_sockaddr1->addr.inet.sin_port));
    }
}

nst_status_e
nst_sockaddr_next(nst_sockaddr_t *next, const nst_sockaddr_t *current)
{
    uint32_t ipn;
    u_char ipn_vec[4];
    int i;

    nst_assert(current->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");

    ipn = current->addr.inet.sin_addr.s_addr;
    memcpy(ipn_vec, &current->addr.inet.sin_addr.s_addr, sizeof(ipn_vec));

    for(i = 3; i >= 0; i--) {
        if(ipn_vec[i] < 254) {
            ipn_vec[i]++;
            break;
        } else if(ipn_vec[i] == 254) {
            ipn_vec[i] = 1;
        } else {
            return NST_ERROR;
        }
    }

    if(i < 0)
        return NST_ERROR;

    memcpy(&ipn, ipn_vec, sizeof(ipn));
    nst_sockaddr_set_ip(next, AF_INET, &ipn);

    return NST_OK;
}

bool
nst_sockaddr_is_equal(const nst_sockaddr_t *sockaddr0,
                      const nst_sockaddr_t *sockaddr1)
{
    if(sockaddr0->addr.inet.sin_family != sockaddr1->addr.inet.sin_family)
        return FALSE;
    else if(sockaddr0->addr.inet.sin_family == AF_UNSPEC)
        return TRUE;

    nst_assert(sockaddr0->addr.inet.sin_family == AF_INET && "Only AF_INET is supported");


    if(memcmp(&sockaddr0->addr.inet.sin_addr,
              &sockaddr1->addr.inet.sin_addr,
              sizeof(sockaddr0->addr.inet.sin_addr))
       ||
       memcmp(&sockaddr0->addr.inet.sin_port,
              &sockaddr1->addr.inet.sin_port,
              sizeof(sockaddr0->addr.inet.sin_port))) {
        return FALSE;
    } else {
        return TRUE;
    }
}
