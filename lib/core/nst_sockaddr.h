#ifndef _NST_SOCKADDR_H_
#define _NST_SOCKADDR_H_

/* libcore includes */
#include <nst_string.h>
#include <nst_genhash.h>
#include <nst_limits.h>
#include <nst_types.h>

/* system includes */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct nst_sockaddr_s nst_sockaddr_t;

/* Always!! Always!! Always!! store BIG ENDIAN into this
 * data struct.  There is NO EXCEPTION even if the native machine endian
 * gives us 1000000...0000x faster performance.
 */
struct nst_sockaddr_s {
    union {
        struct sockaddr_in inet;
        /* struct sockaddr_in6 inet6; */
    } addr;

    char ip_str[NST_MAX_IP_STR_BUF_SIZE];
    char port_str[NST_MAX_PORT_STR_BUF_SIZE];
    nst_str_t ip_mstr;
    nst_str_t port_mstr;
};

void nst_sockaddr_reset(nst_sockaddr_t *nst_sockaddr);

int nst_sockaddr_init(nst_sockaddr_t *nst_sockaddr,
                      const char *ipstr,
                      in_port_t porth,
                      sa_family_t family);

void nst_sockaddr_init_by_sa(nst_sockaddr_t *nst_sockaddr,
                             const struct sockaddr *sa,
                             socklen_t addrlen);

void nst_sockaddr_init_by_sockaddr(nst_sockaddr_t *sockaddr,
                                   const nst_sockaddr_t *src_sockaddr);

void nst_sockaddr_set_ip(nst_sockaddr_t *nst_sockaddr,
                         sa_family_t family,
                         void *ipn);

void nst_sockaddr_set_port(nst_sockaddr_t *nst_sockaddr, in_port_t portn);

int nst_sockaddr_get_family(const nst_sockaddr_t *nst_sockaddr);

const struct sockaddr *
nst_sockaddr_get_sys_sockaddr(const nst_sockaddr_t *nst_sockaddr);

socklen_t nst_sockaddr_get_sys_socklen(const nst_sockaddr_t *nst_sockaddr);

const nst_str_t *nst_sockaddr_get_ip_mstr(const nst_sockaddr_t *sockaddr);
const nst_str_t *nst_sockaddr_get_port_mstr(const nst_sockaddr_t *sockaddr);

const char *nst_sockaddr_get_ip_str(const nst_sockaddr_t *sockaddr);
size_t nst_sockaddr_get_ip_strlen(const nst_sockaddr_t *sockaddr);
const char *nst_sockaddr_get_port_str(const nst_sockaddr_t *sockaddr);
size_t nst_sockaddr_get_port_strlen(const nst_sockaddr_t *sockaddr);

in_port_t nst_sockaddr_get_port(const nst_sockaddr_t *nst_sockaddr);

nst_genhash_key_t nst_genhash_sockaddr(const void *key);

nst_genhash_key_t nst_genhash_sockaddr_ip(const void *key);

int nst_sockaddr_cmp(const void *s1, const void *s2);

int nst_sockaddr_cmp_ip(const void *s1, const void *s2);

nst_status_e
nst_sockaddr_next(nst_sockaddr_t *next, const nst_sockaddr_t *current);

bool nst_sockaddr_is_equal(const nst_sockaddr_t *sockaddr0,
                          const nst_sockaddr_t *sockaddr1);
#endif
