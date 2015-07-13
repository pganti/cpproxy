#include "nst_cpproxy_cfg_remote_dc.h"

#include "nst_cpproxy_cfg_remote_dc_box.h"
#include "nst_cpproxy_cfg_remote_proc.h"
#include "nst_cpproxy_cfg.h"

/* includes from libevent/ */
#include <nst_cfg_svc.h>
#include <nst_cfg_sproxy.h>

/* includes from libnst_cfg/ */
#include <nst_cfg_box.h>
#include <nst_cfg_dc.h>
#include <nst_cfg_diff_data.h>
#include <nst_cfg_tag_action.h>
#include <nst_cfg_file_read.h>
#include <nst_cfg_common.h>

/* includes from libcore */
#include <nst_vector.h>
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_errno.h>
#include <nst_assert.h>


#include <stddef.h>

static nst_status_e nst_cpproxy_cfg_remote_dc_capture(void *udata,
                                                      const XML_Char *name,
                                                      const XML_Char **attrs,
                                                      void **pp_new_cfg_obj,
                                                      void **unused1,
                                                      void **unused2,
                                                      void **unused3);
static void dc_start_handler(void *udata,
                             const XML_Char *name,
                             const XML_Char **attrs);
static void dc_end_handler(void *udata,
                           const XML_Char *name);

static int
sproxy_qsort_cmp(const void *data0, const void *data1)
{
    const nst_cfg_sproxy_t *sproxy0;
    const nst_cfg_sproxy_t *sproxy1;

    sproxy0 = *(const nst_cfg_sproxy_t **)data0;
    sproxy1 = *(const nst_cfg_sproxy_t **)data1;

    return strcmp(sproxy0->sysid, sproxy1->sysid);
}

static nst_status_e
nst_cpproxy_cfg_remote_dc_init_sproxy(nst_cpproxy_cfg_remote_dc_t *remote_dc,
                                      nst_cpproxy_cfg_remote_proc_t *remote_proc,
                                      const nst_genhash_t *svc_ghash)
{
    nst_cfg_svc_t *svc;
    nst_cfg_svc_t *mp_svc;
    nst_cfg_sproxy_t *sproxy;
    nst_genhash_iter_t iter;
    const char *svc_name;

    /* find the mp service of the remote proxy */
    nst_genhash_iter_init(remote_proc->listen.ref_name_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&svc_name)) {
        svc = nst_genhash_find((nst_genhash_t *)svc_ghash, svc_name);
        if(!svc) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "%s is listening on an undefined <%s> \"%s\"",
                        remote_proc->sysid,
                        SERVICE_TAG,
                        svc_name);
            continue;
        } else if(svc->type == NST_SVC_TYPE_TP) {
            /* we assume each remote cpproxy only listen on one mp svc.
             * it will not be true when we have ssl mp later
             */
            mp_svc = svc;
            break;
        }
    }

    if(!mp_svc) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot find \"%s\" service in remote proxy \"%s\"",
                    nst_cfg_svc_type_to_str(NST_SVC_TYPE_TP),
                    remote_proc->sysid);
        return NST_ERROR;
    }
                    
    sproxy = nst_cfg_sproxy_new();
    if(!sproxy) {
        return NST_ERROR;
    }
    nst_cfg_sproxy_init(sproxy,
                        remote_proc->sysid,
                        &remote_proc->box.frontend_ip,
                        nst_sockaddr_get_port(&mp_svc->listen_sockaddr));

    if(nst_vector_append(remote_dc->sproxy_vec, &sproxy, 1)) {
        nst_cfg_sproxy_free(sproxy);
        return NST_ERROR;
    }

    return NST_OK;
}

static nst_status_e
nst_cpproxy_cfg_remote_dc_init(nst_cpproxy_cfg_remote_dc_t *remote_dc,
                               const nst_genhash_t *svc_ghash)
{
    nst_genhash_iter_t iter;
    nst_cpproxy_cfg_remote_proc_t *remote_proc;

    nst_genhash_iter_init(remote_dc->sproxy_proc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&remote_proc)) {
        if(nst_cpproxy_cfg_remote_dc_init_sproxy(remote_dc, remote_proc,
                                                 svc_ghash)) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot init remote sproxy \"%s\"",
                        NST_CFG_DATA_CENTER_TAG, remote_proc->sysid);
            return NST_ERROR;
        }
    }

    qsort(remote_dc->sproxy_vec->elts,
          remote_dc->sproxy_vec->nelts,
          sizeof(nst_cfg_sproxy_t *),
          sproxy_qsort_cmp);

    return NST_OK;
}

static void
nst_cpproxy_cfg_remote_dc_del(nst_cpproxy_cfg_t *cpproxy_cfg,
                              const char *dc_name)
{
    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "removed remote cluster \"%s\"",
                dc_name);

    nst_genhash_del(cpproxy_cfg->remote_dc_ghash, dc_name);
}

static nst_status_e
nst_cpproxy_cfg_remote_dc_add(nst_cpproxy_cfg_remote_dc_t *remote_dc,
                              nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_cfg_sproxy_t *sproxy;
    size_t nsproxies;
    size_t i;

    if(nst_genhash_add(cpproxy_cfg->remote_dc_ghash,
                       remote_dc->name, remote_dc)) {
        if(errno == EEXIST) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add remote <%s> \"%s\". an existing entry "
                        "is found",
                        NST_CFG_DATA_CENTER_TAG, remote_dc->name);
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add remote <%s> \"%s\". %s(%d)",
                        NST_CFG_DATA_CENTER_TAG, remote_dc->name,
                        nst_strerror(errno), errno);
        }
        return NST_ERROR;
    }

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "added remote cluster \"%s\"",
                remote_dc->name);

    nsproxies = nst_vector_get_nelts(remote_dc->sproxy_vec);
    for(i = 0; i < nsproxies; i++) {
        sproxy = *(nst_cfg_sproxy_t **)nst_vector_get_elt_at(remote_dc->sproxy_vec, i);
        if(nst_genhash_add(cpproxy_cfg->sproxy_ip_ghash,
                           &sproxy->mp_listen_sockaddr,
                           sproxy) == NST_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add sporxy \"%s\" listening on \"%s:%s\" "
                        "to sproxy_ip_ghash. %s(%d).",
                        sproxy->sysid,
                        nst_sockaddr_get_ip_str(&sproxy->mp_listen_sockaddr),
                        nst_sockaddr_get_port_str(&sproxy->mp_listen_sockaddr),
                        nst_strerror(errno), errno);
            return NST_ERROR;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "added remote sproxy \"%s\" listening on %s:%s",
                        sproxy->sysid,
                        nst_sockaddr_get_ip_str(&sproxy->mp_listen_sockaddr),
                        nst_sockaddr_get_port_str(&sproxy->mp_listen_sockaddr));
        }
    }

    return NST_OK;
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_remote_dc_apply_modified(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_cfg_diff_data_t *diff_data;
    nst_cpproxy_cfg_remote_dc_t *remote_dc;
    nst_cpproxy_cfg_remote_dc_t *new_remote_dc;
    nst_genhash_t *modified_remote_dc_ghash = cpproxy_cfg->diff.modified.dcs;
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    nst_genhash_iter_init(modified_remote_dc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        size_t new_nsproxies;
        size_t old_nsproxies;
        size_t i;
        size_t j = 0;
        new_remote_dc = diff_data->data;
        remote_dc = nst_genhash_find(cpproxy_cfg->remote_dc_ghash,
                                     new_remote_dc->name);
        if(!remote_dc) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "modified cluster \"%s\" is not find in my "
                        "exisiting config",
                        new_remote_dc->name);
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            break;
        }

        /* merge the sproxy under remote_dc->sproxy_vec to 
         * new_remote_dc->sproxy_vec if possible.
         */
        new_nsproxies = nst_vector_get_nelts(new_remote_dc->sproxy_vec);
        old_nsproxies = nst_vector_get_nelts(remote_dc->sproxy_vec);
        for(i = 0; i < new_nsproxies; i++) {
            nst_cfg_sproxy_t *new_sproxy;

            new_sproxy = *(nst_cfg_sproxy_t **)nst_vector_get_elt_at(new_remote_dc->sproxy_vec, i);
            for(; j < old_nsproxies; j++) {
                nst_cfg_sproxy_t *sproxy;
                int ret;

                sproxy = *(nst_cfg_sproxy_t **)nst_vector_get_elt_at(remote_dc->sproxy_vec, j);
                ret = strcmp(sproxy->sysid, new_sproxy->sysid);
                if(ret < 0) {
                    /* old sproxy has been removed */
                    continue;
                } else if(ret > 0) {
                    /* new_sproxy is probably newly added */
                    break;
                } else {

                    /* ret == 0 */

                    if(nst_sockaddr_is_equal(&sproxy->mp_listen_sockaddr,
                                             &new_sproxy->mp_listen_sockaddr)) {
                        /* use the sproxy instead of the new_sproxy because
                         * we wanna keep the TP connections under the current
                         * sproxy.
                         */

                        /* swap the sproxy */
                        nst_vector_set_elt_at(new_remote_dc->sproxy_vec,
                                              &sproxy,
                                              i);
                        nst_vector_set_elt_at(remote_dc->sproxy_vec,
                                              &new_sproxy,
                                              j);
                    }

                    j++;
                    break;
                }

            } /* for(; j < old_nsproxies; j++) */
        } /* for(i = 0; i < new_nsproxies; i++) */

        nst_cpproxy_cfg_remote_dc_del(cpproxy_cfg,
                                      remote_dc->name);
        if(nst_cpproxy_cfg_remote_dc_add(new_remote_dc, cpproxy_cfg)) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot re-add remote cluster \"%s\". %s(%d)",
                        new_remote_dc->name,
                        nst_strerror(errno), errno);
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            goto DONE;
        } else {
            diff_data->data = NULL;
        }

    } /* while(nst_genhash_iter_next(... */


 DONE:
    reload_status |= NST_CFG_RELOAD_STATUS_CHANGED;

    return reload_status;
}


void
nst_cpproxy_cfg_remote_dc_apply_removed(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_iter_t iter;
    nst_genhash_t *removed_remote_dc_ghash;
    nst_cfg_diff_data_t *diff_data;

    removed_remote_dc_ghash = cpproxy_cfg->diff.removed.dcs;

    nst_genhash_iter_init(removed_remote_dc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        nst_cpproxy_cfg_remote_dc_del(cpproxy_cfg, diff_data->name);
    }
}
nst_status_e
nst_cpproxy_cfg_remote_dc_apply_added(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_cpproxy_cfg_remote_dc_t *remote_dc;
    nst_cfg_diff_data_t *diff_data;
    nst_genhash_iter_t iter;
    nst_genhash_t *dc_ghash = cpproxy_cfg->diff.added.dcs;
    nst_status_e ret = NST_OK;

    nst_genhash_iter_init(dc_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
        remote_dc = diff_data->data;
        nst_assert(remote_dc);
        diff_data->data = NULL;
        if(nst_cpproxy_cfg_remote_dc_add(remote_dc, cpproxy_cfg)) {

            if(nst_genhash_find(cpproxy_cfg->remote_dc_ghash,
                                remote_dc->name)) {
                nst_cpproxy_cfg_remote_dc_del(cpproxy_cfg,
                                              remote_dc->name);
            } else {
                nst_cpproxy_cfg_remote_dc_free(remote_dc);
            }
            return NST_ERROR;
        }
    }

    return ret;
}
                                      
static nst_status_e
nst_cpproxy_cfg_remote_dc_file_done(nst_cpproxy_cfg_remote_dc_t *new_remote_dc,
                                    nst_cfg_diff_data_t *diff_data,
                                    const nst_genhash_t *svc_ghash)
{
    if(strcmp(diff_data->name, new_remote_dc->name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "the remote cluster name \"%s\" does not match the "
                    "config file name \"%s%s\"",
                    new_remote_dc->name,
                    diff_data->name,
                    NST_CFG_FILENAME_EXT);
        return NST_ERROR;
    }

    if(nst_cpproxy_cfg_remote_dc_init(new_remote_dc, svc_ghash)) {
        return NST_ERROR;
    }

    diff_data->data = new_remote_dc;
    diff_data->data_free = nst_cpproxy_cfg_remote_dc_free;

    /* we don't need sproxy_proc_ghash any more */
    nst_genhash_free(new_remote_dc->sproxy_proc_ghash);
    new_remote_dc->sproxy_proc_ghash = NULL;

    return NST_OK;
}

static nst_cpproxy_cfg_remote_dc_t *
nst_cpproxy_cfg_remote_dc_new(void)
{
    nst_cpproxy_cfg_remote_dc_t *new_remote_dc;

    new_remote_dc = nst_allocator_calloc(&nst_cfg_allocator,
                                         1,
                                         sizeof(nst_cpproxy_cfg_remote_dc_t));
    if(!new_remote_dc)
        return NULL;

    new_remote_dc->sproxy_proc_ghash = 
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        8, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_cstr, nst_genhash_cstr_cmp,
                        NULL, nst_cpproxy_cfg_remote_proc_free,
                        NULL, NULL);
    if(!new_remote_dc->sproxy_proc_ghash) {
        nst_cpproxy_cfg_remote_dc_free(new_remote_dc);
        return NULL;
    }

    new_remote_dc->sproxy_vec = nst_vector_new(&nst_cfg_allocator,
                                               nst_cfg_sproxy_vec_free,
                                               4,
                                               sizeof(nst_cfg_sproxy_t*));
    if(new_remote_dc->sproxy_vec) {
        return new_remote_dc;
    } else {
        nst_cpproxy_cfg_remote_dc_free(new_remote_dc);
        return NULL;
    }
}    
    
void nst_cpproxy_cfg_remote_dc_free(void *data)
{
    nst_cpproxy_cfg_remote_dc_t *remote_dc;
    size_t nsproxies;
    size_t i;

    if(!data)
        return;

    remote_dc = (nst_cpproxy_cfg_remote_dc_t *)data;
    nst_genhash_free(remote_dc->sproxy_proc_ghash);

    nsproxies = nst_vector_get_nelts(remote_dc->sproxy_vec);
    for(i = 0; i < nsproxies; i++) {
        nst_cfg_sproxy_t *sproxy;
        sproxy = *(nst_cfg_sproxy_t **)nst_vector_get_elt_at(remote_dc->sproxy_vec, i);
        nst_cfg_sproxy_remove_all_tp_conn(sproxy);
        nst_genhash_del(cpproxy_cfg.sproxy_ip_ghash, &sproxy->mp_listen_sockaddr);
    }
    nst_vector_free(remote_dc->sproxy_vec);
    nst_allocator_free(&nst_cfg_allocator, remote_dc);
}

nst_status_e
nst_cpproxy_cfg_remote_dc_refresh_all(nst_cpproxy_cfg_t *cpproxy_cfg)
{
    nst_genhash_t *dcs_ghash = cpproxy_cfg->diff.added.dcs;
    nst_assert(nst_genhash_get_nelts(dcs_ghash) == 0);

    if(nst_cfg_dir_read(cpproxy_cfg->dir_names.dcs, dcs_ghash) == NST_ERROR)
        return NST_ERROR;

    if(nst_genhash_del(dcs_ghash, cpproxy_cfg->my_dc_name) == NST_ERROR) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot find local cluster \"%s%c%s\" under dir \"%s\"",
                    cpproxy_cfg->dir_names.dcs,
                    NST_DIR_DELIMITER_CHAR,
                    cpproxy_cfg->my_dc_name,
                    cpproxy_cfg->dir_names.dcs);
        return NST_ERROR;
    }

    NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                "detected %ud remote clusters under \"%s\"",
                nst_genhash_get_nelts(dcs_ghash),
                cpproxy_cfg->dir_names.dcs);

    return NST_OK;

}

nst_status_e
nst_cpproxy_cfg_remote_dc_read(nst_cfg_diff_t *diff,
                               const nst_cpproxy_cfg_dir_names_t *dir_names,
                               const nst_genhash_t *svc_ghash)
{
    size_t max_dc_filename_len;
    u_char full_dc_filename[NST_MAX_CFG_FILENAME_BUF_SIZE];
    u_char *start_dc_filename;
    u_char *last; 
    size_t i;
    nst_cpproxy_cfg_remote_dc_t *remote_dc;
    nst_genhash_t *dc_ghashes[] = {
        diff->modified.dcs,
        diff->added.dcs,
    };
    nst_cfg_file_read_ctx_t remote_dc_read_ctx = {
        .entity_start_tag = NST_CFG_DATA_CENTER_TAG,
        .capture = nst_cpproxy_cfg_remote_dc_capture,
        .capture_data0 = (void **)&remote_dc,
        .capture_data1 = NULL,
        .capture_data2 = NULL,
        .capture_data3 = NULL,
        .done_cb = NULL,
        .done_data = NULL,
    };

    last = full_dc_filename + sizeof(full_dc_filename);
    start_dc_filename = nst_snprintf(full_dc_filename,
                                     sizeof(full_dc_filename),
                                     "%s%c",
                                     dir_names->dcs,
                                     NST_DIR_DELIMITER_CHAR);
    max_dc_filename_len = last - start_dc_filename;

    for(i = 0; i < sizeof(dc_ghashes)/sizeof(dc_ghashes[0]); i++) {
        nst_genhash_t *dc_ghash;
        nst_genhash_iter_t iter;
        nst_cfg_diff_data_t *diff_data;

        dc_ghash = dc_ghashes[i];
        nst_genhash_iter_init(dc_ghash, &iter);
        while(nst_genhash_iter_next(&iter, NULL, (void **)&diff_data)) {
            remote_dc = NULL;

            if(nst_snprintf(start_dc_filename,
                            max_dc_filename_len,
                            "%s%s",
                            diff_data->name,
                            NST_CFG_FILENAME_EXT) >= last) {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "length \"%s%c%s%s\" is too long > %ud",
                            dir_names->dcs,
                            NST_DIR_DELIMITER_CHAR,
                            diff_data->name,
                            NST_CFG_FILENAME_EXT,
                            sizeof(full_dc_filename));
                return NST_ERROR;
            } else if(nst_cfg_file_read((char *)full_dc_filename,
                                        &remote_dc_read_ctx)) {
                return NST_ERROR;
            } else if(nst_cpproxy_cfg_remote_dc_file_done(remote_dc,
                                                          diff_data,
                                                          svc_ghash)) {
                nst_cpproxy_cfg_remote_dc_free(remote_dc);
                return NST_ERROR;
            }
        }
    }

    return NST_OK;
}

typedef struct dc_frame_data_s dc_frame_data_t;
struct dc_frame_data_s
{
    nst_cpproxy_cfg_remote_dc_t **ret_remote_dc;
    nst_cpproxy_cfg_remote_dc_t *new_remote_dc;
};

void dc_frame_data_extra_free(void *data)
{
    dc_frame_data_t *fdata;

    if(!data)
        return;

    fdata = (dc_frame_data_t *)data;
    nst_cpproxy_cfg_remote_dc_free(fdata->new_remote_dc);
}

NST_CFG_UN_NESTED_FRAME_DATA_FUNC_DEF(dc, dc_frame_data_extra_free)

static nst_status_e
nst_cpproxy_cfg_remote_dc_capture(void *udata,
                                  const XML_Char *name,
                                  const XML_Char **attrs,
                                  void **ppnew_cfg_obj, void **unused1,
                                   void **unused2, void **unused3)
{
    NST_CFG_CAPTURE_PROLOGUE(dc);

    nst_assert(ppnew_cfg_obj);
    dc_frame_data->ret_remote_dc =
        (nst_cpproxy_cfg_remote_dc_t **)ppnew_cfg_obj;
    dc_frame_data->new_remote_dc = nst_cpproxy_cfg_remote_dc_new();

    if(dc_frame_data->new_remote_dc) {
        return NST_OK;
    } else {
        NST_EXPAT_STACK_FRAME_POP(udata);
        return NST_ERROR;
    }
}

static nst_cfg_tag_action_t dc_tag_actions[] = {
    { NST_CFG_DATA_CENTER_NAME_TAG,
      nst_cfg_tag_action_set_name,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      NST_MAX_CFG_NAME_ELT_BUF_SIZE,
      offsetof(nst_cpproxy_cfg_remote_dc_t, name),
      0,
      0,
      0,
    },

    { NST_CFG_DATA_CENTER_TYPE_TAG,
      nst_cfg_tag_action_set_dc_type,
      NULL,
      NST_CFG_TAG_ACTION_MODE_LOWER_CASE,
      0,
      offsetof(nst_cpproxy_cfg_remote_dc_t, type),
      0,
      0,
      0,
    },

    { BOX_TAG,
      NULL,
      nst_cpproxy_cfg_remote_dc_box_capture,
      NST_CFG_TAG_ACTION_MODE_NONE,
      0,
      0,
      0,
      0,
      0,
    },

};

static void
dc_start_handler(void *udata,
                 const XML_Char *name,
                 const XML_Char **attrs)
{
    NST_CFG_UN_NESTED_START_HANDLER_PROLOGUE(dc, TRUE);

    ret = nst_cfg_tag_action_start_handler(
                dc_tag_actions,
                sizeof(dc_tag_actions)/sizeof(dc_tag_actions[0]),
                current,udata,
                current->tmp_elt_data,
                sizeof(current->tmp_elt_data),
                dc_frame_data->new_remote_dc, NULL,
                NULL, NULL,
                name, attrs);

    NST_CFG_UN_NESTED_START_HANDLER_FINALE();
}

static void
dc_end_handler(void *udata,
               const XML_Char *name)
{
    NST_CFG_UN_NESTED_END_HANDLER_PROLOGUE(dc);

    if(current->skip_on_ignore)
        return;

    ret = nst_cfg_tag_action_end_handler(
                  dc_tag_actions,
                  sizeof(dc_tag_actions)/sizeof(dc_tag_actions[0]),
                  current,
                  current->tmp_elt_data,
                  current->child_ret,
                  dc_frame_data->new_remote_dc,
                  name);

    if(ret == NST_ERROR) {
        if(errno == ENOENT) {
            return;
        } else if(errno != EPROTONOSUPPORT) {
            current->skip_on_error = TRUE;
            return;
        }
    }

    if(!strcmp(name, NST_CFG_DATA_CENTER_TYPE_TAG)) {
        switch(dc_frame_data->new_remote_dc->type) {
        case NST_CFG_DC_TYPE_PUBLIC:
        case NST_CFG_DC_TYPE_PRIVATE:
            return;
        case NST_CFG_DC_TYPE_UNKNOWN:
        case _NUM_NST_CFG_DC_TYPE:
            break;
        }
        current->skip_on_ignore = TRUE;
        nst_cfg_log_ignore_tag(current->name,
                               name, TRUE,
                               line_num, "not interested");
    }

    return;

 RET_TO_PARENT:

    if(current->skip_on_error) {
        *(dc_frame_data->ret_remote_dc) = NULL;
        parent->child_ret = NST_ERROR;
    } else {
        if(!current->skip_on_ignore) {
            NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                        "captured remote <%s> %s with %ud sproxy "
                        "at around line %ud",
                        current->name,
                        dc_frame_data->new_remote_dc->name,
                        nst_genhash_get_nelts(dc_frame_data->new_remote_dc->sproxy_proc_ghash),
                        line_num);
                        
            *(dc_frame_data->ret_remote_dc) = dc_frame_data->new_remote_dc;
            dc_frame_data->new_remote_dc = NULL;
        } else {
            *(dc_frame_data->ret_remote_dc) = NULL;
        }
        parent->child_ret = NST_OK;
    }
    
    NST_CFG_UN_NESTED_END_HANDLER_FINALE();
}
