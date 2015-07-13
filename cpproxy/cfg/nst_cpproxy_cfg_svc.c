/* always include myself first */
#include "nst_cpproxy_cfg_svc.h"

/* local includes */
#include "nst_cpproxy_cfg.h"
#include "nst_cpproxy_cfg_local_dc.h"
#include "nst_cpproxy_cfg_local_proc.h"
#include "nst_cpproxy_cfg_box.h"
#include "nst_http_tcp_ext.h"

/* libnstcfg includes */
#include <nst_cfg_diff_data.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_vips.h>
#include <nst_cfg_common.h>

/* libevent includes */
#include <nst_tp_connection.h>
#include <nst_accept.h>
#include <nst_cfg_svc.h>

/* libcore includes */
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_assert.h>
#include <nst_refcount.h>

#define TP_PORT   8888 /* plain text TP port    */
#define STP_PORT  8889 /* SSL encrypted TP port */

/* forward declaration to avoid including http/nst_http_transaction.h */
void nst_http_transaction_init_connection(nst_connection_t *cli_c);

static nst_status_e
nst_cpproxy_cfg_svc_file_done(nst_cfg_svc_t *svc,
                              nst_cfg_diff_data_t *diff_data)
{
    if(strcmp(diff_data->name, svc->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "the service name \"%s\" does not match the "
                    "config file name \"%s%s\"",
                    svc->name, diff_data->name, NST_CFG_FILENAME_EXT);
        nst_cfg_svc_free(svc);
        return NST_ERROR;
    }

    switch(svc->type) {
    case NST_SVC_TYPE_TUNNEL:
    case NST_SVC_TYPE_HTTP:
        svc->handler = nst_http_transaction_init_connection;
        svc->tcp_ext = NST_HTTP_TCP_EXT_PASSIVE_END_USER;
        break;
    case NST_SVC_TYPE_TP:
        if(nst_sockaddr_get_port(&svc->listen_sockaddr) != htons(TP_PORT)
           || !svc->public_ip) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "TP service must be listening on public IP port %ud",
                        TP_PORT);
            nst_cfg_svc_free(svc);
            return NST_ERROR;
        }

        svc->handler = nst_tp_passive_accept_handler;
        svc->tcp_ext = NST_HTTP_TCP_EXT_PASSIVE_TP;
        break;
    default:
        nst_assert(0 && "unhandled svc->type");
    }

    diff_data->data = svc;
    svc = NULL;
    diff_data->data_free = nst_cfg_svc_free;

    return NST_OK;
}

static nst_status_e
nst_cpproxy_cfg_svc_add(nst_cpproxy_cfg_t *cpproxy_cfg, nst_cfg_svc_t *svc)
{

    if(!nst_cfg_svc_is_http_like(svc)) {
        // We are only interested in http like service 
        NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                    "ignore <%s> \"%s\". not interested.",
                    SERVICE_TAG,
                    svc->name);
        nst_cfg_svc_free(svc);
        return NST_OK;
    }


    if(nst_genhash_add(cpproxy_cfg->svc_ghash,
                       svc->name,
                       svc) == NST_ERROR) {
        if(errno == EEXIST) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "duplicate service \"%s\" found",
                        svc->name);
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add service \"%s\" to "
                        "current_svc_ghash %s(%d)",
                        nst_strerror(errno), errno);
            cpproxy_cfg->nerrors++;
        }

        return NST_ERROR;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "added service \"%s\"",
                    svc->name);
        return NST_OK;
    }
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_svc_apply_added(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_cfg_svc_t *svc;
    nst_cfg_diff_data_t *diff_data;
    nst_genhash_iter_t iter;
    nst_genhash_t *svc_ghash = cpproxy_cfg->diff.added.services;
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    nst_genhash_iter_init(svc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        svc = diff_data->data;
        if(!svc) {
            printf("not service");
            /* we are not interested to this service */
            continue;
        }

        if(nst_cpproxy_cfg_svc_add(cpproxy_cfg, svc)) {
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            break;
        } else {
            reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
            diff_data->data = NULL;
        }
    }

    return reload_status;
}

nst_status_e
nst_cpproxy_cfg_svc_refresh_all(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_t *svc_ghash = cpproxy_cfg->diff.added.services;
    nst_assert(nst_genhash_get_nelts(svc_ghash) == 0);

    if(nst_cfg_dir_read(cpproxy_cfg->dir_names.services, svc_ghash)
       == NST_ERROR)
        return NST_ERROR;

    NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                "detected %ud service files under \"%s\"",
                nst_genhash_get_nelts(svc_ghash),
                cpproxy_cfg->dir_names.services);

    return NST_OK;
}

nst_status_e
nst_cpproxy_cfg_svc_read(nst_cfg_diff_t *diff,
                         const nst_cpproxy_cfg_dir_names_t *dir_names)
{
    size_t i;
    size_t max_svc_filename_len;
    u_char full_svc_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];
    u_char *start_svc_filename;
    u_char *last;
    nst_cfg_svc_t *new_svc;
    nst_status_e ret = NST_OK;
    nst_genhash_t *svc_ghashes[] = {
        diff->modified.services,
        diff->added.services,
    };
    nst_cfg_file_read_ctx_t service_read_ctx = {
        .done_cb = NULL,
        .entity_start_tag = SERVICE_TAG,
        .capture = nst_cfg_svc_capture,
        .capture_data0 = (void **)&new_svc,
        .capture_data1 = NULL,
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_data = NULL,
    };

    last = full_svc_filename + sizeof(full_svc_filename);
    start_svc_filename = nst_snprintf(full_svc_filename,
                                      sizeof(full_svc_filename),
                                      "%s%c",
                                      dir_names->services,
                                      NST_DIR_DELIMITER_CHAR);
    max_svc_filename_len = last - start_svc_filename;

    for(i = 0; i < sizeof(svc_ghashes)/sizeof(svc_ghashes[0]); i++) {
        nst_genhash_t *svc_ghash;
        nst_genhash_iter_t iter;
        nst_cfg_diff_data_t *diff_data;

        svc_ghash = svc_ghashes[i];
        nst_genhash_iter_init(svc_ghash, &iter);
        while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
            new_svc = NULL;

            nst_assert(!diff_data->data);
            if(nst_snprintf(start_svc_filename,
                            max_svc_filename_len,
                            "%s%s",
                            diff_data->name,
                            NST_CFG_FILENAME_EXT) >= last) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "length \"%s%c%s%s\" is too long > %ud",
                            dir_names->services,
                            NST_DIR_DELIMITER_CHAR,
                            diff_data->name,
                            NST_CFG_FILENAME_EXT,
                            sizeof(full_svc_filename));
                return NST_ERROR;
            }

            ret = nst_cfg_file_read((char *)full_svc_filename, &service_read_ctx);
            if(ret == NST_ERROR
               ||
               nst_cpproxy_cfg_svc_file_done(new_svc, diff_data)) {
                return NST_ERROR;
            }
        }
    }

    return NST_OK;
}

static void
nst_cpproxy_cfg_svc_close(nst_cfg_svc_t *svc,
                          nst_cpproxy_cfg_t *cpproxy_cfg)
{
    if(!svc->listener)
        return;

    nst_assert(NST_REFC_VALUE(svc) >= 1);
    nst_event_del_listener(svc);

    nst_genhash_del(cpproxy_cfg->listening_svc_ghash, &svc->listen_sockaddr);
}

static void
nst_cpproxy_cfg_svc_del(nst_cpproxy_cfg_t *cpproxy_cfg, const char *svc_name)
{
    
    nst_cfg_svc_t *svc;

    svc = nst_genhash_find(cpproxy_cfg->svc_ghash, svc_name);
    if(!svc)
        return;

    if(nst_genhash_find(cpproxy_cfg->listening_svc_ghash,
                        &svc->listen_sockaddr)) {
        nst_status_e ret;
        nst_assert(NST_REFC_VALUE(svc) >= 1);
        nst_event_del_listener(svc);
        ret = nst_genhash_del(cpproxy_cfg->listening_svc_ghash,
                              &svc->listen_sockaddr);
        nst_assert(ret == NST_OK);
    } else {
        nst_assert(NST_REFC_VALUE(svc) == 1);
    }

    NST_NOC_LOG(NST_LOG_LEVEL_INFO, "service \"%s\" is removed", svc->name);
    nst_genhash_del(cpproxy_cfg->svc_ghash, svc->name);
}

/* for all services in cpproxy->cuurent_svc_ghash, figure out
 * which one I am responsible to listen
 *
 * For example, for SPC, it is only responsible for TP services.
 */
nst_status_e
nst_cpproxy_cfg_svc_listen(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t ghash_iter;
    nst_cfg_svc_t *svc;

    nst_cpproxy_cfg_local_dc_t *my_dc = cpproxy_cfg->my_dc;
    nst_cpproxy_cfg_local_proc_t *my_proc = my_dc->my_proc;

    bool all_vip_http = my_proc->listen.all_vip_http;
    bool all_public_http = my_proc->listen.all_vip_http;

    nst_uint_t old_nerrors = cpproxy_cfg->nerrors;

    const nst_sockaddr_t *my_public_ip =
        nst_cpproxy_cfg_box_get_natted_frontend_ip(&my_proc->box);
    
    nst_genhash_iter_init(cpproxy_cfg->svc_ghash, &ghash_iter);
    while(nst_genhash_iter_next(&ghash_iter, NULL, (void **)&svc)) {
        /* nst_cfg_svc_t *old_svc; */
        const nst_sockaddr_t *ip;
        nst_sockaddr_t tmp_listen_sockaddr;
        bool found_at_ref_name_ghash;
        nst_cfg_svc_t *old_svc;

        if(nst_genhash_find(my_proc->listen.ref_name_ghash, svc->name))
            /* under my <process>, the service name has been specified */
            found_at_ref_name_ghash = TRUE;
        else
            found_at_ref_name_ghash = FALSE;

        if(svc->public_ip
           && (all_public_http || found_at_ref_name_ghash)) {
            ip = my_public_ip;
        } else if(svc->vip_index > 0
                  && (all_vip_http || found_at_ref_name_ghash)
                  && my_dc->vips) {
            nst_cfg_vip_t *vip;
            vip = nst_genhash_find(my_dc->vips->index_ghash,
                                   (void *)&svc->vip_index);
            if(!vip) {
                nst_log_level_t log_lvl;
                
                if(found_at_ref_name_ghash) {
                    log_lvl = NST_LOG_LEVEL_ERROR;
                    cpproxy_cfg->nerrors++;
                } else {
                    log_lvl = NST_LOG_LEVEL_INFO;
                }

                NST_NOC_LOG(log_lvl,
                            "ignore <%s> \"%s\" because vip-index %ud "
                            "is missing in my cluster",
                            SERVICE_TAG,
                            svc->name,
                            svc->vip_index);
                continue;
            }

            ip = &vip->sockaddr;
        } else {
            NST_NOC_LOG(NST_LOG_DEBUG,
                        "ignore <%s> \"%s\". not interested",
                        SERVICE_TAG,
                        svc->name);
            nst_cpproxy_cfg_svc_close(svc, cpproxy_cfg);
            continue;
        } /* if(adding_svc->public_ip && */

        nst_sockaddr_init_by_sockaddr(&tmp_listen_sockaddr, ip);
        nst_sockaddr_set_port(&tmp_listen_sockaddr,
                              nst_sockaddr_get_port(&svc->listen_sockaddr));

        /* the following are mostly the SIGHUP reload */
        if((old_svc = nst_genhash_find(cpproxy_cfg->listening_svc_ghash,
                                       &tmp_listen_sockaddr))) {
            if(old_svc == svc) {
                if(nst_sockaddr_is_equal(&old_svc->listen_sockaddr,
                                         &tmp_listen_sockaddr)) {
                    NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                            "service \"%s\" is already listening on %s:%s",
                            old_svc->name,    
                            nst_sockaddr_get_ip_str(&svc->listen_sockaddr),
                            nst_sockaddr_get_port_str(&svc->listen_sockaddr));
                    continue;
                } else {
                    nst_cpproxy_cfg_svc_close(svc, cpproxy_cfg);
                }
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "another service \"%s\" is also listening on "
                            "%s:%s while adding service \"%s\"",
                            old_svc->name,
                            nst_sockaddr_get_ip_str(&tmp_listen_sockaddr),
                            nst_sockaddr_get_port_str(&tmp_listen_sockaddr),
                            svc->name);
                return NST_ERROR;
            }
        }

        nst_sockaddr_init_by_sockaddr(&svc->listen_sockaddr,
                                      &tmp_listen_sockaddr);

        if(!cpproxy_cfg->test_only_mode) {
            if(nst_event_add_listener(svc) == NST_ERROR) {
                return NST_ERROR;
            }
        }

        if(nst_genhash_add(cpproxy_cfg->listening_svc_ghash,
                           &svc->listen_sockaddr, svc)) {
            nst_assert(errno != EEXIST);
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add service \"%s\" listening on %s:%s "
                        "to listening service hash table. %s(%d)",
                        svc->name,
                        nst_sockaddr_get_ip_str(&tmp_listen_sockaddr),
                        nst_sockaddr_get_port_str(&tmp_listen_sockaddr),
                        nst_strerror(errno), errno);
        } else if(cpproxy_cfg->test_only_mode) {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "service \"%s\" is listening on %s:%s",
                        svc->name,
                        nst_sockaddr_get_ip_str(&tmp_listen_sockaddr),
                        nst_sockaddr_get_port_str(&tmp_listen_sockaddr));
        }
                        

    } /* while(nst_genhash_iter_next(&ghash_iter, &svc)) */

    if(old_nerrors == cpproxy_cfg->nerrors)
        return NST_OK;
    else
        return NST_ERROR;
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_svc_apply_modified(nst_cpproxy_cfg_t *cpproxy_cfg,
                                   bool *relisten)
{
    nst_genhash_iter_t iter;
    nst_cfg_diff_data_t *diff_data;
    nst_cfg_svc_t *svc;
    nst_cfg_svc_t *new_svc;
    nst_genhash_t *modified_svc_ghash = cpproxy_cfg->diff.modified.services;
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    nst_genhash_iter_init(modified_svc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        nst_cfg_reload_status_e tmp_reload_status;

        new_svc = diff_data->data;
        nst_assert(new_svc);

        svc = nst_genhash_find(cpproxy_cfg->svc_ghash, new_svc->name);
        if(!svc) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "modified service \"%s\" is not found (or was ignored) "
                        "in the old config. adding it",
                        new_svc->name);
            if(nst_cpproxy_cfg_svc_add(cpproxy_cfg, new_svc) != NST_OK) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "cannot add service \"%s\". %s(%d)",
                            new_svc->name,
                            nst_strerror(errno), errno);
                reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
                break;
            } else {
                diff_data->data = NULL;
                reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
                *relisten = TRUE;
                continue;
            }
        }

        tmp_reload_status = nst_cfg_svc_apply_modified(svc, new_svc,
                                               cpproxy_cfg->test_only_mode);

        if(tmp_reload_status & NST_CFG_RELOAD_STATUS_ERROR_BIT) {
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            break;
        } else if(tmp_reload_status & NST_CFG_RELOAD_STATUS_RESTART_NEEDED) {
            reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
            break;
        } else if(tmp_reload_status & NST_CFG_RELOAD_STATUS_READD) {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "modifying service \"%s\" requires a removal and then "
                        "addition",
                        svc->name);

            *relisten = TRUE;

            nst_cpproxy_cfg_svc_del(cpproxy_cfg, svc->name);
            if(nst_cpproxy_cfg_svc_add(cpproxy_cfg, new_svc)) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "cannot re-add service \"%s\". %s(%d)",
                            new_svc->name,
                            nst_strerror(errno), errno);
                reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
                break;
            } else {
                reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
                diff_data->data = NULL;
            }   
        } else if(tmp_reload_status & NST_CFG_RELOAD_STATUS_CHANGED) {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "successfully applied config changes to service \"%s\"",
                        svc->name);
            reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "nothing changed to service \"%s\"",
                        svc->name);
        }
    } /* while(nst_genhash_iter_next(...)) */

    /* WARNING: svc may have been deleted at this point */

    return reload_status;
}

void
nst_cpproxy_cfg_svc_apply_removed(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_genhash_t *removed_svc_ghash;
    nst_cfg_diff_data_t *diff_data;

    removed_svc_ghash = cpproxy_cfg->diff.removed.services;

    nst_genhash_iter_init(removed_svc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        nst_cpproxy_cfg_svc_del(cpproxy_cfg, diff_data->name);
    }
}
