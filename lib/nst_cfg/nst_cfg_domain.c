/* its own header file */
#include "nst_cfg_domain.h"

/* nst_cfg headers */
#include "nst_cfg_application.h"
#include "nst_cfg_domain_monitor.h"
#include "nst_cfg_cpt.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_common.h"

/* libnst_cpt headers */
#include <nst_cpt_walk.h>
#include <nst_cpt_osite_node.h>
#include <nst_cpt_node.h>

/* libcore headers */
#include <nst_genhash.h>
#include <nst_string.h>
#include <nst_log.h>
#include <nst_vector.h>
#include <nst_limits.h>
#include <nst_errno.h>
#include <nst_types.h>

/* std library and 3rd party library header files */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>

#define DOMAIN_TAG    "domain"
#define NAME_TAG      "name"
#define ALIAS_TAG     "alias"
#define SERVICE_TAG   "service"
#define DMON_TAG      "monitor"
#define HTTP_ACCESS_LOG_FORMAT_TAG "http-access-log-format"
#define NOC_LOG_LEVEL_TAG  "noc-log-level"
#define DBG_LOG_LEVEL_TAG  "debug-log-level"

#define NST_MAX_LOG_FORMAT_BUF_SIZE 1024

typedef struct domain_frame_data_s domain_frame_data_t;

struct domain_frame_data_s
{
    nst_cfg_application_t *application;
    nst_cfg_domain_t *new_domain;
    char tmp_elt_data[NST_MAX_LOG_FORMAT_BUF_SIZE];

    bool is_name_captured;
};

static nst_cfg_domain_t *nst_cfg_domain_new(void);
static void domain_start_handler(void *udata,
                                 const XML_Char *name,
                                 const XML_Char **attrs);
static void domain_end_handler(void *udata, const XML_Char *name);
static nst_status_e
cpt_walk_to_find_dmon_site(nst_cpt_node_t *node, void *data);

static void
domain_extra_free(domain_frame_data_t *frame_data)
{
    if(!frame_data)
        return;

    nst_cfg_domain_do_free(frame_data->new_domain);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(domain, domain_extra_free)

nst_status_e
nst_cfg_domain_capture(void *udata,
                       const XML_Char *name,
                       const XML_Char **attrs,
                       void **papplication, void **unused1,
                       void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(domain);

    nst_assert(papplication);
    domain_frame_data->application = (nst_cfg_application_t *)papplication;
    domain_frame_data->new_domain = nst_cfg_domain_new();
    if(domain_frame_data->new_domain) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }

    return NST_OK;
}

static nst_status_e
nst_cfg_domain_set_service(void *cfg_obj,
                           const nst_cfg_tag_action_t *action,
                           nst_expat_stack_frame_t *current,
                           const char *value,
                           size_t value_len)
{
    nst_cfg_domain_t *domain = (nst_cfg_domain_t *)cfg_obj;
    char *service;

    if(value_len + 1 > action->text_buf_size) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "<%s> parsing error: <%s> %s length is too long > %ud "
                    "at around line %ud",
                    current->name,
                    action->tag,
                    value,
                    action->text_buf_size -  1,
                    XML_GetCurrentLineNumber(current->parser));

        return NST_ERROR;
    }

    service = nst_allocator_malloc(&nst_cfg_allocator,
                                                  value_len + 1);
    if(!service) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot allocate memory for service string \"%s\" "
                    "at around line %ud",
                    value,
                    XML_GetCurrentLineNumber(current->parser));
        return NST_ERROR;
    }

    if(nst_vector_append(domain->services, &service, 1)) {
        nst_allocator_free(&nst_cfg_allocator, service);
        return NST_ERROR;
    }

    nst_memcpy(service, value, value_len + 1);

    return NST_OK;
}

static nst_status_e
nst_cfg_domain_set_alias(void *cfg_obj,
                         const nst_cfg_tag_action_t *action,
                         nst_expat_stack_frame_t *current,
                         const char *value,
                         size_t value_len)
{
    nst_cfg_domain_t *domain = (nst_cfg_domain_t *)cfg_obj;
    domain_frame_data_t *domain_frame_data;
    nst_str_t *alias;

    nst_assert(!strcmp(current->name, DOMAIN_TAG));
    domain_frame_data = (domain_frame_data_t *)current->data;
    
    if(strcmp(action->tag, NAME_TAG)) {
        if(!domain_frame_data->is_name_captured) {
            /* error case */
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "<%s> parsing error: <%s> must be specified before any "
                        "<%s> at around line %ud",
                        current->name,
                        NAME_TAG,
                        ALIAS_TAG,
                        XML_GetCurrentLineNumber(current->parser));
            return NST_ERROR;
        }
    } else {
        if(domain_frame_data->is_name_captured) {
            /* error case */
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "<%s> parsing error: multiple <%s> has been specified "
                        "for a domain at around line %ud. please use "
                        "<%s> instead",
                        current->name,
                        NAME_TAG,
                        XML_GetCurrentLineNumber(current->parser),
                        ALIAS_TAG);
            return NST_ERROR;
        } else {
            domain_frame_data->is_name_captured = TRUE;
        }
    }
        
    alias = (nst_str_t *)nst_vector_push(domain->aliases);
    if(!alias)
        return NST_ERROR;

    alias->data = nst_allocator_malloc(&nst_cfg_allocator, value_len + 1);
    if(!alias->data) {
        nst_vector_pop(domain->aliases);
        return NST_ERROR;
    }

    nst_memcpy(alias->data, value, value_len + 1);
    alias->len = value_len;
    
    return NST_OK;
}

static nst_cfg_tag_action_t domain_tag_actions[] = {
    { NAME_TAG,
      nst_cfg_domain_set_alias,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },

    { ALIAS_TAG,
      nst_cfg_domain_set_alias,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },

    { SERVICE_TAG,
      nst_cfg_domain_set_service,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      0,
      0,
      0,
      0,
    },

    { DOMAIN_TIMEOUT_TAG,
      NULL,
      nst_cfg_domain_timeout_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_t, timeout),
      0,
      0,
      0,
    },

    { DMON_TAG,
      NULL,
      nst_cfg_domain_monitor_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_t, dmon),
      0,
      0,
      0,
    },

    { HTTP_ACCESS_LOG_FORMAT_TAG,
      nst_cfg_tag_action_set_mstr_with_alloc,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      NST_MAX_LOG_FORMAT_BUF_SIZE,
      offsetof(nst_cfg_domain_t, http_access_log_format),
      0,
      0,
      0,
    },

    { NOC_LOG_LEVEL_TAG,
      nst_cfg_tag_action_set_int,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_t, noc_log_lvl),
      0,
      0,
      0,
    },

    { DBG_LOG_LEVEL_TAG,
      nst_cfg_tag_action_set_int,
      NULL,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      offsetof(nst_cfg_domain_t, dbg_log_lvl),
      0,
      0,
      0,
    },
};

static void
domain_start_handler(void *udata,
                     const XML_Char *name,
                     const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(domain, TRUE);

    if(!strcmp(name, NEXT_HOP_TREE_TAG)) {
        nst_cfg_application_t *application   = domain_frame_data->application;
        nst_cfg_domain_t   *new_domain = domain_frame_data->new_domain;
        if(nst_cfg_cpt_capture(udata, name, attrs,
                               &new_domain->cpt,
                               application->origin_sites))
            current->skip_on_error = 1;

        return;

    }

    ret = nst_cfg_tag_action_start_handler(
                   domain_tag_actions,
                   sizeof(domain_tag_actions)/sizeof(domain_tag_actions[0]),
                   current, udata,
                   domain_frame_data->tmp_elt_data,
                   sizeof(domain_frame_data->tmp_elt_data),
                   domain_frame_data->new_domain, NULL,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
domain_end_handler(void *udata, const XML_Char *name)
{
    nst_cfg_domain_t *new_domain;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(domain);

    new_domain = domain_frame_data->new_domain;

    ret = nst_cfg_tag_action_end_handler(
                   domain_tag_actions,
                   sizeof(domain_tag_actions)/sizeof(domain_tag_actions[0]),
                   current,
                   domain_frame_data->tmp_elt_data, current->child_ret,
                   new_domain, name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        parent->child_ret = NST_ERROR;
    } else {
        nst_cfg_application_t *application;
        nst_cfg_domain_t   *new_domain;
        nst_str_t          *domain_id;

        application = domain_frame_data->application;
        new_domain = domain_frame_data->new_domain;
        domain_id = nst_vector_get_elt_at(new_domain->aliases, 0);

        new_domain->application = application;

        if(nst_cpt_walk(new_domain->cpt,
                        cpt_walk_to_find_dmon_site,
                        (void *)new_domain) == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "error when figuring out my dmon site for domain "
                        "\"%s\" under application \"%s\". %s(%d)",
                        domain_id->data, application->name,
                        nst_strerror(errno), errno);
            parent->child_ret = NST_ERROR;
        } else if(nst_vector_append(application->domains, &new_domain, 1)) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add domain \"%s\" under application \"%s\". "
                        "%s(%d)",
                        domain_id->data, application->name,
                        nst_strerror(errno), errno);
            parent->child_ret = NST_ERROR;
        } else {
            domain_frame_data->new_domain = NULL; /* ownership has been taken */
            parent->child_ret = NST_OK;
        }
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

static nst_status_e
cpt_walk_to_find_dmon_site(nst_cpt_node_t *node, void *data)
{
    nst_cfg_domain_t *domain = (nst_cfg_domain_t *)data;

    if(node->type != NST_CPT_NODE_TYPE_OSITE)
        return NST_OK;

    if(nst_cpt_osite_node_am_i_responsible(node)) {
        if(nst_cfg_domain_add_dmon_site(domain, node) == NST_ERROR) {
            return NST_ERROR;
        }
    }

    return NST_DONE;
}
                           
static nst_cfg_domain_t *
nst_cfg_domain_new(void)
{
    nst_cfg_domain_t *new_domain = NULL;

    new_domain = nst_allocator_calloc(&nst_cfg_allocator,
                                        1,
                                        sizeof(nst_cfg_domain_t));
    if(!new_domain)
        return NULL;

    nst_cfg_domain_timeout_init(&new_domain->timeout);

    new_domain->aliases = 
        nst_vector_new(&nst_cfg_allocator,
                       NULL,
                       4,
                       sizeof(nst_str_t));

    new_domain->services = 
        nst_vector_new(&nst_cfg_allocator,
                       nst_cfg_cstr_vec_free,
                       4,
                       sizeof(char *));

    if(!new_domain->aliases || !new_domain->services) {
        nst_cfg_domain_do_free(new_domain);
        return NULL;
    }

    if(!new_domain->aliases) {
        nst_cfg_domain_do_free(new_domain);
        return NULL;
    }

    return new_domain;
}

void nst_cfg_domain_do_vec_free(nst_cfg_domain_t **ppdomain)
{
    nst_assert(ppdomain);
    nst_cfg_domain_do_free(*ppdomain);
}

void
nst_cfg_domain_do_free(nst_cfg_domain_t *domain)
{
    size_t i;
    size_t naliases;

    if(!domain)
        return;

    /* free the aliases string */
    naliases = nst_vector_get_nelts(domain->aliases);
    for(i = 0; i < naliases; i++) {
        nst_str_t *alias;
        alias = (nst_str_t *)nst_vector_get_elt_at(domain->aliases, i);
        nst_allocator_free(&nst_cfg_allocator, alias->data);
    }
    nst_vector_free(domain->aliases);
    nst_vector_free(domain->services);

    /* free the cpt */
    nst_cpt_node_free(domain->cpt);

    nst_cfg_domain_monitor_reset(&domain->dmon);

    nst_vector_free(domain->dmon_sites);

    nst_vector_free(domain->http_access_log_vars);
    
    nst_allocator_free(&nst_cfg_allocator,
                       domain->http_access_log_format.data);

    /* free domain itself */
    nst_allocator_free(&nst_cfg_allocator, domain);
}

const nst_str_t *
nst_cfg_domain_get_name(const nst_cfg_domain_t *domain)
{
    return (const nst_str_t *)nst_vector_get_elt_at(domain->aliases, 0);
}

void
nst_cfg_domain_get(nst_cfg_domain_t *domain)
{
    NST_REFC_GET(domain->application);
}

void
nst_cfg_domain_free(nst_cfg_domain_t *domain)
{
    if(domain)
        NST_REFC_PUT(domain->application);
}

const char *
nst_cfg_domain_get_name_as_just_plain_string (const nst_cfg_domain_t *domain)
{
    const nst_str_t             * dname;

    dname = nst_cfg_domain_get_name((const nst_cfg_domain_t *)domain);
    if (dname) {
        return (char *)dname->data;
    }

    return NULL;
}

nst_status_e
nst_cfg_domain_add_dmon_site(nst_cfg_domain_t *domain, nst_cpt_node_t *osite)
{
    if(!domain->dmon_sites) {
        domain->dmon_sites = nst_vector_new(&nst_cfg_allocator,
                                            NULL,
                                            4,
                                            sizeof(nst_cpt_node_t *));
        if(!domain->dmon_sites) {
            return NST_ERROR;
        }
    }

    return nst_vector_append(domain->dmon_sites, &osite, 1);
}
