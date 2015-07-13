#ifndef _NST_CFG_CUSTOMER_H_
#define _NST_CFG_CUSTOMER_H_

#include <nst_config.h>

#include <nst_refcount.h>
#include <nst_limits.h>

#include <expat.h>

#define CUSTOMER_TAG "application"

typedef struct nst_cfg_application_s nst_cfg_application_t;

struct nst_vector_s;
struct nst_cpt_node_s;

struct nst_cfg_application_s
{
    char name[NST_MAX_CFG_NAME_ELT_BUF_SIZE];
    struct nst_vector_s *origin_sites; /* internal origin server nodes */
    struct nst_vector_s *domains;
    int is_removed_from_nst_cfg_system;

    NST_REFC_CTX_DEF
};

int nst_cfg_application_capture(void *udata,
                             const XML_Char *name,
                             const XML_Char **attrs,
                             void **ppapplication, void **my_dc_name,
                             void **unused2, void **unused3);

void nst_cfg_application_free(nst_cfg_application_t *application);

#endif
