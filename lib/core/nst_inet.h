
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_INET_H_INCLUDED_
#define _NST_INET_H_INCLUDED_


#include <nst_core.h>


typedef struct {
    in_addr_t         addr;
    in_addr_t         mask;
} nst_inet_cidr_t;


typedef union {
    in_addr_t         in_addr;
} nst_url_addr_t;


typedef struct {
    struct sockaddr  *sockaddr;
    socklen_t         socklen;
    nst_str_t         name;
} nst_peer_addr_t;


typedef struct {
    nst_int_t         type;

    nst_str_t         url;
    nst_str_t         host;
    nst_str_t         port_text;
    nst_str_t         uri;

    in_port_t         port;
    in_port_t         default_port;

    unsigned          listen:1;
    unsigned          uri_part:1;
    unsigned          no_resolve:1;
    unsigned          one_addr:1;

    unsigned          wildcard:1;
    unsigned          no_port:1;
    unsigned          unix_socket:1;

    nst_url_addr_t    addr;

    nst_peer_addr_t  *addrs;
    nst_uint_t        naddrs;

    char             *err;
} nst_url_t;


in_addr_t nst_inet_addr(u_char *text, size_t len);
size_t nst_sock_ntop(int family, struct sockaddr *sa, u_char *text, size_t len);
size_t nst_inet_ntop(int family, void *addr, u_char *text, size_t len);
nst_int_t nst_ptocidr(nst_str_t *text, void *cidr);
nst_int_t nst_parse_url(nst_pool_t *pool, nst_url_t *u);
nst_int_t nst_inet_resolve_host(nst_pool_t *pool, nst_url_t *u);



#endif /* _NST_INET_H_INCLUDED_ */
