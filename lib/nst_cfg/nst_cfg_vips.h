#ifndef __NST_CFG_VIPS_H_
#define __NST_CFG_VIPS_H_

#include <nst_sockaddr.h>
#include <nst_genhash.h>

#include <expat.h>

typedef struct nst_cfg_vip_s nst_cfg_vip_t;
typedef struct nst_cfg_vips_s nst_cfg_vips_t;

struct nst_cfg_vip_s
{
    uint32_t index;              /* key to ghash, so using uint32_t */
    nst_sockaddr_t sockaddr;
};

struct nst_cfg_vips_s
{
    nst_genhash_t *ip_ghash;   /* hashed by IP (port is excluded) */
    nst_genhash_t *index_ghash; /* hashed by vip-index */
};

nst_status_e
nst_cfg_vips_capture(void *udata,
                     const XML_Char *name,
                     const XML_Char **attrs,
                     void **ret_obj, void **unused1,
                     void **unused2, void **unused3);

void nst_cfg_vips_free(void *cfg_vips);

bool nst_cfg_vips_is_equal(const nst_cfg_vips_t *vips0,
                           const nst_cfg_vips_t *vips1);

#endif
