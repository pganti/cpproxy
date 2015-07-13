/* its own header file */
#include "nst_cfg_application.h"

/* application header files */

/* nst_cfg headers */
#include "nst_cfg_origin_site.h"
#include "nst_cfg_domain.h"
#include "nst_cfg_cpt.h"
#include "nst_cfg_elt_data.h"
#include "nst_cfg_tag_action.h"
#include "nst_cfg_common.h"

/* nst_cpt headers */
#include <nst_cpt_node.h>

/* nst_lib headers */
#include <nst_log.h>
#include <nst_vector.h>
#include <nst_genhash.h>
#include <nst_limits.h>
#include <nst_errno.h>
#include <nst_types.h>

/* std library and 3rd party library header files */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>

#define NAME_TAG   "name"
#define DOMAIN_TAG "domain"
typedef struct application_frame_data_s application_frame_data_t;

struct application_frame_data_s
{
    nst_cfg_application_t **ret_application;
    nst_cfg_application_t *new_application;
    nst_cpt_node_t *new_os;
    const char *my_dc_name;
};

static nst_cfg_application_t *nst_cfg_application_new(void);
static void nst_cfg_application_do_free(nst_cfg_application_t *application);
static void application_start_handler(void *udata,
                                   const XML_Char *name,
                                   const XML_Char **attrs);
static void application_end_handler(void *udata,
                                 const XML_Char *name);

static void
application_extra_free(application_frame_data_t *frame_data)
{
    if(!frame_data)
        return;

    nst_cpt_node_free(frame_data->new_os);
    nst_cfg_application_free(frame_data->new_application);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(application, application_extra_free)

int nst_cfg_application_capture(void *udata,
                             const XML_Char *name,
                             const XML_Char **attrs,
                             void **ppapplication, void **my_dc_name,
                             void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(application);

    nst_assert(ppapplication);
    nst_assert(my_dc_name);
    application_frame_data->ret_application = (nst_cfg_application_t **)ppapplication;
    application_frame_data->my_dc_name = (char *)my_dc_name;
    application_frame_data->new_application = nst_cfg_application_new();
    if(application_frame_data->new_application) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }

    return 0;
}

static nst_cfg_tag_action_t application_tag_actions[] = {
    { NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cfg_application_t, name),
      0,
      0,
      0,
    },

    { ORIGIN_SITE_TAG,
      NULL,
      nst_cfg_origin_site_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,                              /* text_buf_size */
      0,                              /* offset0 */
      0,                              /* offset1 */
      0,                              /* offset2 */
      0,                              /* offset3 */
    },

    { DOMAIN_TAG,
      NULL,
      nst_cfg_domain_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,                              /* text_buf_size */
      0,                              /* offset0 */
      0,                              /* offset1 */
      0,                              /* offset2 */
      0,                              /* offset3 */
    },
};

static void
application_start_handler(void *udata,
                       const XML_Char *name,
                       const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(application, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                   application_tag_actions,
                   sizeof(application_tag_actions)/sizeof(application_tag_actions[0]),
                   current, udata,
                   current->tmp_elt_data, sizeof(current->tmp_elt_data),
                   application_frame_data->new_application,
                   (void **)application_frame_data->my_dc_name,
                   NULL, NULL,
                   name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static
void application_end_handler(void *udata, const XML_Char *name)
{
    nst_cfg_application_t *new_application;
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(application);

    new_application = application_frame_data->new_application;

    ret = nst_cfg_tag_action_end_handler(
                   application_tag_actions,
                   sizeof(application_tag_actions)/sizeof(application_tag_actions[0]),
                   current,
                   current->tmp_elt_data,
                   current->child_ret,
                   application_frame_data->new_application,
                   name);

    if(ret == NST_ERROR && errno != ENOENT && errno != EPROTONOSUPPORT)
        current->skip_on_error = TRUE;

    return;

 RET_TO_PARENT:

    /* TODO: final check on application object */

    if(current->skip_on_error) {
        *(application_frame_data->ret_application) = NULL;
        parent->child_ret = NST_ERROR;
    } else {
        nst_cfg_application_t *new_application;
        new_application = *(application_frame_data->ret_application) = application_frame_data->new_application;
        application_frame_data->new_application = NULL; /* ownership has been taken */
        parent->child_ret = NST_OK;
    }

    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}

nst_cfg_application_t *
nst_cfg_application_new(void)
{
    nst_cfg_application_t *new_application = NULL;
    int error = 0;

    new_application = nst_allocator_calloc(&nst_cfg_allocator,
                                        1,
                                        sizeof(nst_cfg_application_t));
    if(!new_application)
        return NULL;

    new_application->origin_sites = 
        nst_vector_new(&nst_cfg_allocator,
                       (nst_gen_destructor_f)nst_cpt_node_vec_free,
                       4,
                       sizeof(nst_cpt_node_t *));

    if(!new_application->origin_sites) {
        error = 1;
        goto DONE;
    }

    new_application->domains =
        nst_vector_new(&nst_cfg_allocator,
                       (nst_gen_destructor_f)nst_cfg_domain_do_vec_free,
                       4,
                       sizeof(nst_cfg_domain_t *));

    if(!new_application->domains) {
        error = 1;
        goto DONE;
    }

    NST_REFC_INIT(new_application, (nst_gen_destructor_f)nst_cfg_application_do_free);

 DONE:
    if(error) {
        nst_vector_free(new_application->origin_sites);
        nst_vector_free(new_application->domains);
        nst_allocator_free(&nst_cfg_allocator, new_application);
        return NULL;
    } else {
        return new_application;
    }
}

void
nst_cfg_application_free(nst_cfg_application_t *application)
{
    NST_REFC_PUT(application);
}

static void
nst_cfg_application_do_free(nst_cfg_application_t *application)
{
    if(!application)
        return;

    nst_vector_free(application->origin_sites);

    nst_vector_free(application->domains);

    nst_allocator_free(&nst_cfg_allocator, application);
}
