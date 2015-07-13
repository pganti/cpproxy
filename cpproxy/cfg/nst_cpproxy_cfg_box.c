#include "nst_cpproxy_cfg_box.h"

#include <nst_log.h>

nst_cfg_reload_status_e
nst_cpproxy_cfg_box_apply_modified(nst_cpproxy_cfg_box_t *box,
                                   nst_cpproxy_cfg_box_t *new_box,
                                   bool *allow_ip_changed)
{
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;
    bool any_ip_changed = FALSE;

    if(strcmp(box->name, new_box->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "apply box differences while the new box name \"%s\" "
                    "is not equal to the old box name \"%s\"",
                    new_box->name,
                    box->name);
        return NST_CFG_RELOAD_STATUS_HARD_ERROR;
    }

    box->type = new_box->type;
    
    if(!nst_sockaddr_is_equal(&box->natted_frontend_ip,
                              &new_box->natted_frontend_ip)) {
        any_ip_changed = TRUE;
        if(*allow_ip_changed) {
            nst_sockaddr_init_by_sockaddr(&box->natted_frontend_ip,
                                          &new_box->natted_frontend_ip);
            reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        } else {
            reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
            goto DONE;
        }
    }
            
    if(!nst_sockaddr_is_equal(&box->frontend_ip,
                              &new_box->frontend_ip)) {
        any_ip_changed = TRUE;
        if(*allow_ip_changed) {
            nst_sockaddr_init_by_sockaddr(&box->frontend_ip,
                                          &new_box->frontend_ip);
            reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        } else {
            reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
            goto DONE;
        }            
    }

    if(!nst_sockaddr_is_equal(&box->backend_ip,
                              &new_box->backend_ip)) {
        any_ip_changed = TRUE;
        if(*allow_ip_changed) {
            nst_sockaddr_init_by_sockaddr(&box->backend_ip,
                                      &new_box->backend_ip);
            reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;
        } else {
            reload_status |= NST_CFG_RELOAD_STATUS_RESTART_NEEDED;
            goto DONE;
        }
    }

 DONE:
    if(reload_status & NST_CFG_RELOAD_STATUS_RESTART_NEEDED) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "IP of local box \"%s\" is changed. restart is needed",
                    box->name);
    }
            
    *allow_ip_changed = any_ip_changed;

    return reload_status;
    
}
