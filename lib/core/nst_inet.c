
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


static size_t nst_sprint_uchar(u_char *text, u_char c, size_t len);


/* AF_INET only */

in_addr_t
nst_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    in_addr_t    addr;
    nst_uint_t   octet, n;

    addr = 0;
    octet = 0;
    n = 0;

    for (p = text; p < text + len; p++) {

        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            continue;
        }

        if (c == '.' && octet < 256) {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }

        return INADDR_NONE;
    }

    if (n != 3) {
        return INADDR_NONE;
    }

    if (octet < 256) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}


/*
 * nst_sock_ntop() and nst_inet_ntop() may be implemented as
 * "nst_sprintf(text, "%ud.%ud.%ud.%ud", p[0], p[1], p[2], p[3])", however,
 * they had been implemented long before the nst_sprintf() had appeared
 * and they are faster by 1.5-2.5 times, so it is worth to keep them.
 *
 * By the way, the implementation using nst_sprintf() is faster by 2.5-3 times
 * than using FreeBSD libc's snprintf().
 */

/* AF_INET only */

size_t
nst_sock_ntop(int family, struct sockaddr *sa, u_char *text, size_t len)
{
    u_char              *p;
    size_t               n;
    nst_uint_t           i;
    struct sockaddr_in  *sin;

    if (len == 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    sin = (struct sockaddr_in *) sa;
    p = (u_char *) &sin->sin_addr;

    if (len > INET_ADDRSTRLEN) {
        len = INET_ADDRSTRLEN;
    }

    n = nst_sprint_uchar(text, p[0], len);

    i = 1;

    do {
        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        text[n++] = '.';

        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        n += nst_sprint_uchar(&text[n], p[i++], len - n);

    } while (i < 4);

    if (len == n) {
        text[n] = '\0';
        return n;
    }

    text[n] = '\0';

    return n;
}


size_t
nst_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    u_char      *p;
    size_t       n;
    nst_uint_t   i;

    if (len == 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    p = (u_char *) addr;

    if (len > INET_ADDRSTRLEN) {
        len = INET_ADDRSTRLEN;
    }

    n = nst_sprint_uchar(text, p[0], len);

    i = 1;

    do {
        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        text[n++] = '.';

        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        n += nst_sprint_uchar(&text[n], p[i++], len - n);

    } while (i < 4);

    if (len == n) {
        text[n] = '\0';
        return n;
    }

    text[n] = '\0';

    return n;
}


static size_t
nst_sprint_uchar(u_char *text, u_char c, size_t len)
{
    size_t      n;
    nst_uint_t  c1, c2;

    n = 0;

    if (len == n) {
        return n;
    }

    c1 = c / 100;

    if (c1) {
        *text++ = (u_char) (c1 + '0');
        n++;

        if (len == n) {
            return n;
        }
    }

    c2 = (c % 100) / 10;

    if (c1 || c2) {
        *text++ = (u_char) (c2 + '0');
        n++;

        if (len == n) {
            return n;
        }
    }

    c2 = c % 10;

    *text = (u_char) (c2 + '0');
    n++;

    return n;
}


/* AF_INET only */

nst_int_t
nst_ptocidr(nst_str_t *text, void *cidr)
{
    nst_int_t         m;
    nst_uint_t        i;
    nst_inet_cidr_t  *in_cidr;

    in_cidr = cidr;

    for (i = 0; i < text->len; i++) {
        if (text->data[i] == '/') {
            break;
        }
    }

    if (i == text->len) {
        return NST_ERROR;
    }

    text->data[i] = '\0';
    in_cidr->addr = inet_addr((char *) text->data);
    text->data[i] = '/';
    if (in_cidr->addr == INADDR_NONE) {
        return NST_ERROR;
    }

    m = nst_atoi(&text->data[i + 1], text->len - (i + 1));
    if (m == NST_ERROR) {
        return NST_ERROR;
    }

    if (m == 0) {

        /* the x86 compilers use the shl instruction that shifts by modulo 32 */

        in_cidr->mask = 0;
        return NST_OK;
    }

    in_cidr->mask = htonl((nst_uint_t) (0 - (1 << (32 - m))));

    if (in_cidr->addr == (in_cidr->addr & in_cidr->mask)) {
        return NST_OK;
    }

    in_cidr->addr &= in_cidr->mask;

    return NST_DONE;
}


nst_int_t
nst_parse_url(nst_pool_t *pool, nst_url_t *u)
{
    u_char              *p, *host, *port_start;
    size_t               len, port_len;
    nst_int_t            port;
    nst_uint_t           i;
    struct hostent      *h;
#if (NST_HAVE_UNIX_DOMAIN)
    struct sockaddr_un  *saun;
#endif

    len = u->url.len;
    p = u->url.data;

    if (nst_strncasecmp(p, (u_char *) "unix:", 5) == 0) {

#if (NST_HAVE_UNIX_DOMAIN)

        p += 5;
        len -= 5;

        u->uri.len = len;
        u->uri.data = p;

        if (u->uri_part) {
            for (i = 0; i < len; i++) {

                if (p[i] == ':') {
                    len = i;

                    u->uri.len -= len + 1;
                    u->uri.data += len + 1;

                    break;
                }
            }
        }

        if (len == 0) {
            u->err = "no path in the unix domain socket";
            return NST_ERROR;
        }

        if (len + 1 > sizeof(saun->sun_path)) {
            u->err = "too long path in the unix domain socket";
            return NST_ERROR;
        }

        u->addrs = nst_pcalloc(pool, sizeof(nst_peer_addr_t));
        if (u->addrs == NULL) {
            return NST_ERROR;
        }

        saun = nst_pcalloc(pool, sizeof(struct sockaddr_un));
        if (saun == NULL) {
            return NST_ERROR;
        }

        u->naddrs = 1;

        saun->sun_family = AF_UNIX;
        (void) nst_cpystrn((u_char *) saun->sun_path, p, len + 1);

        u->addrs[0].sockaddr = (struct sockaddr *) saun;
        u->addrs[0].socklen = sizeof(struct sockaddr_un);
        u->addrs[0].name.len = len + 5;
        u->addrs[0].name.data = u->url.data;

        u->host.len = len;
        u->host.data = p;

        u->unix_socket = 1;

        return NST_OK;

#else
        u->err = "the unix domain sockets are not supported on this platform";

        return NST_ERROR;

#endif
    }

    if ((p[0] == ':' || p[0] == '/') && !u->listen) {
        u->err = "invalid host";
        return NST_ERROR;
    }

    u->host.data = p;

    port_start = NULL;
    port_len = 0;

    for (i = 0; i < len; i++) {

        if (p[i] == ':') {
            port_start = &p[i + 1];
            u->host.len = i;

            if (!u->uri_part) {
                port_len = len - (i + 1);
                break;
            }
        }

        if (p[i] == '/') {
            u->uri.len = len - i;
            u->uri.data = &p[i];

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (port_start == NULL) {
                u->no_port = 1;
                goto no_port;
            }

            port_len = &p[i] - port_start;

            if (port_len == 0) {
                u->err = "invalid port";
                return NST_ERROR;
            }

            break;
        }
    }

    if (port_start) {

        if (port_len == 0) {
            port_len = &p[i] - port_start;

            if (port_len == 0) {
                u->err = "invalid port";
                return NST_ERROR;
            }
        }

        port = nst_atoi(port_start, port_len);

        if (port == NST_ERROR || port < 1 || port > 65536) {
            u->err = "invalid port";
            return NST_ERROR;
        }

        u->port_text.len = port_len;
        u->port_text.data = port_start;

    } else {
        port = nst_atoi(p, len);

        if (port == NST_ERROR) {
            u->host.len = len;
            u->no_port = 1;

            goto no_port;
        }

        u->wildcard = 1;
    }

    u->port = (in_port_t) port;

no_port:

    if (u->listen) {

        if (u->port == 0) {
            if (u->default_port == 0) {
                u->err = "no port";
                return NST_ERROR;
            }

            u->port = u->default_port;
        }

        if (u->host.len == 1 && u->host.data[0] == '*') {
            u->host.len = 0;
        }

        /* AF_INET only */

        if (u->host.len) {

            host = nst_alloc(u->host.len + 1, pool->log);
            if (host == NULL) {
                return NST_ERROR;
            }

            (void) nst_cpystrn(host, u->host.data, u->host.len + 1);

            u->addr.in_addr = inet_addr((const char *) host);

            if (u->addr.in_addr == INADDR_NONE) {
                h = gethostbyname((const char *) host);

                if (h == NULL || h->h_addr_list[0] == NULL) {
                    nst_free(host);
                    u->err = "host not found";
                    return NST_ERROR;
                }

                u->addr.in_addr = *(in_addr_t *) (h->h_addr_list[0]);
            }

            nst_free(host);

        } else {
            u->addr.in_addr = INADDR_ANY;
        }

        return NST_OK;
    }

    if (u->host.len == 0) {
        u->err = "no host";
        return NST_ERROR;
    }

    if (u->no_resolve) {
        return NST_OK;
    }

    if (u->no_port) {
        u->port = u->default_port;
    }

    if (u->port == 0) {
        u->err = "no port";
        return NST_ERROR;
    }

    if (nst_inet_resolve_host(pool, u) != NST_OK) {
        return NST_ERROR;
    }

    return NST_OK;
}


nst_int_t
nst_inet_resolve_host(nst_pool_t *pool, nst_url_t *u)
{
    u_char              *p, *host;
    size_t               len;
    in_addr_t            in_addr;
    nst_uint_t           i;
    struct hostent      *h;
    struct sockaddr_in  *sin;

    host = nst_alloc(u->host.len + 1, pool->log);
    if (host == NULL) {
        return NST_ERROR;
    }

    (void) nst_cpystrn(host, u->host.data, u->host.len + 1);

    /* AF_INET only */

    in_addr = inet_addr((char *) host);

    if (in_addr == INADDR_NONE) {
        h = gethostbyname((char *) host);

        nst_free(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            u->err = "host not found";
            return NST_ERROR;
        }

        if (u->one_addr == 0) {
            for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        } else {
            i = 1;
        }

        /* TP: nst_shared_palloc() */

        u->addrs = nst_pcalloc(pool, i * sizeof(nst_peer_addr_t));
        if (u->addrs == NULL) {
            return NST_ERROR;
        }

        u->naddrs = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {

            sin = nst_pcalloc(pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NST_ERROR;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = htons(u->port);
            sin->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            u->addrs[i].sockaddr = (struct sockaddr *) sin;
            u->addrs[i].socklen = sizeof(struct sockaddr_in);

            len = INET_ADDRSTRLEN - 1 + 1 + sizeof(":65536") - 1;

            p = nst_palloc(pool, len);
            if (p == NULL) {
                return NST_ERROR;
            }

            len = nst_sock_ntop(AF_INET, (struct sockaddr *) sin, p, len);

            u->addrs[i].name.len = nst_sprintf(&p[len], ":%d", u->port) - p;
            u->addrs[i].name.data = p;
        }

    } else {

        nst_free(host);

        /* TP: nst_shared_palloc() */

        u->addrs = nst_pcalloc(pool, sizeof(nst_peer_addr_t));
        if (u->addrs == NULL) {
            return NST_ERROR;
        }

        sin = nst_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NST_ERROR;
        }

        u->naddrs = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(u->port);
        sin->sin_addr.s_addr = in_addr;

        u->addrs[0].sockaddr = (struct sockaddr *) sin;
        u->addrs[0].socklen = sizeof(struct sockaddr_in);

        p = nst_palloc(pool, u->host.len + sizeof(":65536") - 1);
        if (p == NULL) {
            return NST_ERROR;
        }

        u->addrs[0].name.len = nst_sprintf(p, "%V:%d", &u->host, u->port) - p;
        u->addrs[0].name.data = p;
    }

    return NST_OK;
}
