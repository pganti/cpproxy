/* always include myself first */
#include "nst_cpproxy_cfg_application.h"

/* local includes */
#include "nst_cpproxy_cfg_domain.h"
#include "nst_cpproxy_cfg.h"

/* cpproxy/http includes */
#include <nst_http_access_log.h>

/* libnstcfg includes */
#include <nst_cfg_diff_data.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_application.h>
#include <nst_cfg_domain.h>
#include <nst_cfg_common.h>

/* libcore includes */
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_assert.h>
#include <nst_vector.h>

static bool
nst_cpproxy_cfg_application_am_i_responsible(const nst_cfg_application_t *application)
{
    size_t i, ndomains;

    if(!nst_cpproxy_cfg_am_i_private_spc())
        /* I am a public CPC. I need to pay attention to all applications */
        return TRUE;

    ndomains = nst_vector_get_nelts(application->domains);
    for(i = 0; i < ndomains; i++) {
        nst_cfg_domain_t *domain;

        domain = *(nst_cfg_domain_t **)
            nst_vector_get_elt_at (application->domains, i);

        if(nst_cfg_domain_am_i_responsible(domain))
            return TRUE;
    }

    return FALSE;
}

static nst_status_e
nst_cpproxy_cfg_application_file_done(nst_cfg_application_t *application,
                                   nst_cfg_diff_data_t *diff_data)
{

    if(strcmp(diff_data->name, application->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "the application name \"%s\" does not match the "
                    "config file name \"%s%s\"",
                    application->name,
                    diff_data->name,
                    NST_CFG_FILENAME_EXT);
        return NST_ERROR;
    }

    diff_data->data = application;
    diff_data->data_free = (nst_gen_destructor_f)nst_cfg_application_free;

    return NST_OK;
}

static nst_status_e
nst_cpproxy_cfg_application_add(nst_cpproxy_cfg_t *cpproxy_cfg,
                             nst_cfg_application_t *application)
{                            
    nst_status_e ret = NST_OK;
    size_t i, ndomains;

    /* b4 we add, we should check if we are interested to this application */
    if(!nst_cpproxy_cfg_application_am_i_responsible(application)) {
        /* free it */
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "I am not interested to application \"%s\". ignored",
                    application->name);
        nst_cfg_application_free(application);
        return NST_OK;
    }

    if(nst_genhash_add(cpproxy_cfg->application_ghash,
                       application->name,
                       application) == NST_ERROR) {
        if(errno == EEXIST) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "duplicate application name \"%s\" found",
                        application->name);
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add application name \"%s\" to application_ghash "
                        "%s(%d)",
                        nst_strerror(errno), errno);
        }
        ret = NST_ERROR;
        goto DONE;
    }

    ndomains = nst_vector_get_nelts(application->domains);
    for(i = 0; i < ndomains; i++) {
        nst_cfg_domain_t *domain;
        domain = *(nst_cfg_domain_t **)
            nst_vector_get_elt_at (application->domains, i);
        if( nst_http_access_log_compile(domain) == NST_ERROR ) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "error when compiling http-access-log-format for "
                        "domain %V. default is used.",
                        nst_cfg_domain_get_name(domain));
        }
                
        if(nst_cpproxy_cfg_domain_add(cpproxy_cfg, domain) == NST_ERROR) {
            ret = NST_ERROR;
            break;
        }
    }

 DONE:
                              
    return ret;
}

static void
nst_cpproxy_cfg_application_del(nst_cpproxy_cfg_t *cpproxy_cfg,
                             const char *application_name,
                             bool set_domain_down)
{
    nst_cfg_application_t *application;
    size_t i, ndomains;

    application = nst_genhash_find(cpproxy_cfg->application_ghash,
                                application_name);
    if(!application)
        return;

    ndomains = nst_vector_get_nelts(application->domains);
    for(i = 0; i < ndomains; i++) {
        nst_cfg_domain_t *domain;
        domain = *(nst_cfg_domain_t **)
            nst_vector_get_elt_at (application->domains, i);
        nst_cpproxy_cfg_domain_del(cpproxy_cfg, domain, set_domain_down);
    }

    nst_genhash_del(cpproxy_cfg->application_ghash, application_name);
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_application_apply_modified(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_genhash_t *modified_application_ghash;
    nst_cfg_diff_data_t *diff_data;
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    modified_application_ghash = cpproxy_cfg->diff.modified.applications;
    nst_genhash_iter_init(modified_application_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        nst_cfg_application_t *old_application;
        nst_cfg_application_t *new_application;

        new_application = diff_data->data;
        nst_assert(new_application);
        old_application = nst_genhash_find(cpproxy_cfg->application_ghash, 
                                        new_application->name);

        if(!old_application) {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "modified application \"%s\" is not found "
                        "(or was ignored) in the old config. adding it",
                        new_application->name);
            goto ADD;
        }

        nst_cpproxy_cfg_domain_inherit(new_application->domains,
                                       old_application->domains,
                                       cpproxy_cfg->test_only_mode);

        nst_cpproxy_cfg_application_del(cpproxy_cfg,
                                     old_application->name,
                                     FALSE);

        reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        
    ADD:
        if(nst_cpproxy_cfg_application_add(cpproxy_cfg, new_application)) {
            nst_assert(errno != EEXIST);
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add application \"%s\". %s(%d)",
                        new_application->name, 
                        nst_strerror(errno), errno);
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        } else {
            diff_data->data = NULL;
        }
    }
    return reload_status;

}

void
nst_cpproxy_cfg_application_apply_removed(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_genhash_t *removed_application_ghash;
    nst_cfg_diff_data_t *diff_data;

    removed_application_ghash = cpproxy_cfg->diff.removed.applications;
    nst_genhash_iter_init(removed_application_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        nst_cpproxy_cfg_application_del(cpproxy_cfg, diff_data->name,  TRUE);
    }
}

nst_status_e
nst_cpproxy_cfg_application_apply_added(struct nst_cpproxy_cfg_s *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_cfg_application_t *application;
    nst_cfg_diff_data_t *diff_data;

    nst_genhash_iter_init(cpproxy_cfg->diff.added.applications, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        application = diff_data->data;
        nst_assert(application);
        diff_data->data = NULL;
        if(nst_cpproxy_cfg_application_add(cpproxy_cfg, application)) {
            if(nst_genhash_find(cpproxy_cfg->application_ghash, application->name)) {
                nst_cpproxy_cfg_application_del(cpproxy_cfg,
                                             application->name,
                                             TRUE);
            } else {
                nst_cfg_application_free(application);
            }
            return NST_ERROR;
        }
    }

    return NST_OK;
}

nst_status_e
nst_cpproxy_cfg_application_refresh_all(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    uint32_t napplication;

    nst_assert(nst_genhash_get_nelts(cpproxy_cfg->diff.added.applications) == 0);

    if(nst_cfg_dir_read(cpproxy_cfg->dir_names.applications,
                        cpproxy_cfg->diff.added.applications) == NST_ERROR)
        return NST_ERROR;

    
    napplication = nst_genhash_get_nelts(cpproxy_cfg->diff.added.applications);
    if(napplication) {
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "detected %ud application cfg files under \"%s\"",
                    napplication,
                    cpproxy_cfg->dir_names.applications);
        return NST_OK;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot find any application cfg file under dir \"%s\"",
                    cpproxy_cfg->dir_names.applications);
        return NST_ERROR;
    }
}

nst_status_e
nst_cpproxy_cfg_application_read(nst_cfg_diff_t *diff,
                              const nst_cpproxy_cfg_dir_names_t *dir_names,
                              const char *my_dc_name)
{
    size_t  max_application_filename_len;
    u_char  full_application_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];
    u_char *start_application_filename;
    u_char *last; 
    size_t  i;
    nst_cfg_application_t *application;
    nst_genhash_t *application_ghashes[] = {
        diff->modified.applications,
        diff->added.applications,
    };
    nst_cfg_file_read_ctx_t application_read_ctx = {
        .done_cb = NULL,
        .entity_start_tag = CUSTOMER_TAG,
        .capture = nst_cfg_application_capture,
        .capture_data0 = (void **)&application,
        .capture_data1 = (void **)(my_dc_name),
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_data = NULL,
    };

    last = full_application_filename + sizeof(full_application_filename);
    start_application_filename = nst_snprintf(full_application_filename,
                                      sizeof(full_application_filename),
                                      "%s%c",
                                      dir_names->applications,
                                      NST_DIR_DELIMITER_CHAR);
    max_application_filename_len = last - start_application_filename;


    for(i = 0; i < sizeof(application_ghashes)/sizeof(application_ghashes[0]); i++) {
        nst_genhash_t *application_ghash;
        nst_genhash_iter_t iter;
        nst_cfg_diff_data_t *diff_data;

        application_ghash = application_ghashes[i];
        nst_genhash_iter_init(application_ghash, &iter);
        while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
            application = NULL;
            if(nst_snprintf(start_application_filename,
                            max_application_filename_len,
                            "%s%s",
                            diff_data->name,
                            NST_CFG_FILENAME_EXT) >= last) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "dir length \"%s%c%s%s\" is too long > %ud",
                            dir_names->dcs,
                            NST_DIR_DELIMITER_CHAR,
                            diff_data->name,
                            NST_CFG_FILENAME_EXT,
                            sizeof(full_application_filename));
                return NST_ERROR;
            } else if(nst_cfg_file_read((char *)full_application_filename,
                                        &application_read_ctx)) {
                return NST_ERROR;
            } else if(nst_cpproxy_cfg_application_file_done(application,
                                                         diff_data)) {
                nst_cfg_application_free(application);
                return NST_ERROR;
            }
        }
    }

    return NST_OK;

}
