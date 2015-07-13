#include "nst_cpproxy_cfg.h"

#include "nst_cpproxy_cfg_version.h"
#include "nst_cpproxy_cfg_diff.h"
#include "nst_cpproxy_cfg_svc.h"
#include "nst_cpproxy_cfg_local_proc.h"
#include "nst_cpproxy_cfg_local_dc.h"
#include "nst_cpproxy_cfg_remote_dc.h"
#include "nst_cpproxy_cfg_domain.h"
#include "nst_cpproxy_cfg_application.h"
#include "nst_cpproxy_cfg_myproc.h"

/* libevent/ includes */
#include <nst_cfg_svc.h>
#include <nst_cfg_sproxy.h>
#include <nst_connection.h>

/* libnst_cfg/ includes */
#include <nst_cfg_domain.h>
#include <nst_cfg_application.h>
#include <nst_cfg_common.h>
#include <nst_cfg.h>

#include <nst_sockaddr.h>
#include <nst_genhash.h>
#include <nst_log.h>
#include <nst_allocator.h>
#include <nst_palloc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define NST_CFG_WORKING_DIR_NAME      "working"
#define NST_CFG_SERVICES_DIR_NAME     "services"
#define NST_CFG_DCS_DIR_NAME          "clusters"
#define NST_CFG_CUSTOMERS_DIR_NAME    "applications"
#define NST_CFG_VERSION_FILENAME      "version.xml"

#define NST_CPPROXY_CFG_MISC_POOL_SIZE 1024

/* nst_cfg_diff cpproxy_cfg_diff; */
nst_cpproxy_cfg_t cpproxy_cfg;
nst_pool_t *cpproxy_cfg_sticky_pool;

static nst_status_e
read_base_dir_name(nst_cpproxy_cfg_dir_names_t *dirs,
                   const char *symlink_filename)
{
    struct stat st;
    char full_symlink_filename[NST_MAX_DIR_NAME_BUF_SIZE];
    char base_dir_name[NST_MAX_DIR_NAME_BUF_SIZE];
    ssize_t base_dir_name_len;
    u_char *p;
    u_char *last_buf;

    /* read the symlink */
    if(nst_snprintf((u_char *)full_symlink_filename,
                    sizeof(full_symlink_filename),
                    "%s/%s",
                    dirs->cfg, symlink_filename)
       >= (u_char *)full_symlink_filename + sizeof(full_symlink_filename)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "the symlink file name \"%s/%s\" length is > %ud",
                    dirs->cfg, symlink_filename,
                    sizeof(full_symlink_filename) - 1);
        return NST_ERROR;
    }

    if(lstat(full_symlink_filename, &st)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "cannot read \"%s\". %s(%d)",
                    full_symlink_filename, nst_strerror(errno), errno);
        return NST_ERROR;
    }

    if(!(st.st_mode & S_IFLNK)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "\"%s\" is not a symbolic link",
                    full_symlink_filename);
        return NST_ERROR;
    }

    base_dir_name_len =  readlink(full_symlink_filename,
                                  base_dir_name,
                                  sizeof(base_dir_name));
    if(base_dir_name_len > 0) {
        if((size_t)base_dir_name_len < sizeof(base_dir_name)) {
            base_dir_name[base_dir_name_len] = '\0';
        } else {
            base_dir_name[sizeof(base_dir_name) - 1] = '\0';
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "%s is too long > %ud",
                        base_dir_name,
                        sizeof(base_dir_name) - 1);
            return NST_ERROR;
        }
    } else  {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "cannot read symlink \"%s\". %s(%d)",
                    full_symlink_filename, nst_strerror(errno), errno);
        return NST_ERROR;
    }

    last_buf = (u_char *)(dirs->base + sizeof(dirs->base));
    if(*base_dir_name == NST_DIR_DELIMITER_CHAR) {
        p = nst_snprintf((u_char *)dirs->base, sizeof(dirs->base),
                         "%s", base_dir_name);
        if(p >= last_buf) {
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "symlink \"%s\" is linking to directory \"%s\" where "
                        "its length is > %ud",
                        full_symlink_filename, base_dir_name, sizeof(dirs->base) - 1);
            return NST_ERROR;
        }
    } else {
        p = nst_snprintf((u_char *)dirs->base, sizeof(dirs->base),
                         "%s/%s", dirs->cfg, base_dir_name);
        if(p >= last_buf) {
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "symlink \"%s\" is linking to directory \"%s/%s\" "
                        "where its length is > %ud",
                        full_symlink_filename, dirs->cfg, base_dir_name,
                        sizeof(dirs->base) - 1);
            return NST_ERROR;
        }
    }

    base_dir_name_len = p - (u_char *)dirs->base;
    /* remove the tailing '/' */
    while(base_dir_name_len > 1 
          && dirs->base[base_dir_name_len - 1] == NST_DIR_DELIMITER_CHAR) {
        base_dir_name_len--;
    }
    dirs->base[base_dir_name_len] = '\0';

    if(stat(dirs->base, &st) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "cannot read \"%s\". %s(%d)",
                    dirs->base, nst_strerror(errno), errno);
        return NST_ERROR;
    } else if(!(st.st_mode & S_IFDIR)) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "\"%s\" (-> \"%s\") is not linking to a directory",
                    full_symlink_filename, dirs->base);
        return NST_ERROR;
    }

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "got base config dir \"%s\"",
                dirs->base);

    return NST_OK;  
}
                        
static nst_status_e
nst_cpproxy_cfg_set_dirs(nst_cpproxy_cfg_dir_names_t *dirs,
                         const char *cfg_dir_name,
                         const char *symlink_name)
{
    char *base_dir_name;
    size_t cfg_dir_name_len;
    size_t base_dir_name_len;
    size_t i;

    struct {
        const char *name;
        char *dst;
    } dir_names[] = {
        { NST_CFG_SERVICES_DIR_NAME, dirs->services},
        { NST_CFG_DCS_DIR_NAME, dirs->dcs},
        { NST_CFG_CUSTOMERS_DIR_NAME, dirs->applications},
    };
    
    cfg_dir_name_len = strlen(cfg_dir_name);

    /* it must be an absolute path ==> start with '/'*/
    if(cfg_dir_name_len == 0 || cfg_dir_name[0] != NST_DIR_DELIMITER_CHAR) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL, 
                    "invalid config dir \"%s\". "
                    "it must be an absolute path",
                    cfg_dir_name);
        return NST_ERROR;
    }

    /* remove the tailing '/' */
    while(cfg_dir_name_len > 1 
          && cfg_dir_name[cfg_dir_name_len - 1] == NST_DIR_DELIMITER_CHAR) {
        cfg_dir_name_len--;
    }

    if(cfg_dir_name_len + 1 > NST_MAX_DIR_NAME_BUF_SIZE) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "config dir \"%s\" length is > %ud",
                    cfg_dir_name,
                    NST_MAX_DIR_NAME_BUF_SIZE - 1);
        return NST_ERROR;
    }

    nst_memcpy(dirs->cfg, cfg_dir_name, cfg_dir_name_len + 1);

    if(read_base_dir_name(dirs, symlink_name)) {
        return NST_ERROR;
    }

    base_dir_name = dirs->base;
    base_dir_name_len = strlen(dirs->base);

    for(i = 0;
        i < sizeof(dir_names)/sizeof(dir_names[0]);
        i++) {
        size_t required_len;
        size_t dir_name_len = strlen(dir_names[i].name);

        required_len = base_dir_name_len + 1 + dir_name_len;
        if(required_len + 1 > NST_MAX_DIR_NAME_BUF_SIZE) {
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "\"%s\" config dir \"%s/%s\" is too long  > %ud",
                        dir_names[i].name,
                        base_dir_name,
                        dir_names[i].name,
                        NST_MAX_DIR_NAME_BUF_SIZE - 1);
            return NST_ERROR;
        } else {
            memcpy(dir_names[i].dst,
                   base_dir_name, base_dir_name_len);
            dir_names[i].dst[base_dir_name_len] = NST_DIR_DELIMITER_CHAR;
            memcpy(dir_names[i].dst + base_dir_name_len + 1,
                   dir_names[i].name,
                   dir_name_len);
            dir_names[i].dst[required_len] = '\0';
            NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                        "\"%s\" config dir is \"%s\"",
                        dir_names[i].name,
                        dir_names[i].dst);
        }
    }
       
    return NST_OK;
}

static nst_status_e
nst_cpproxy_cfg_set_sysid(const char *sysid)
{
    const char *at;
    size_t box_name_len;
    size_t dc_name_len;
    size_t cmd_len;
    size_t sysid_len = strlen(sysid);

    at = strchr(sysid, '@');
    if(!at)
        return NST_ERROR;

    cmd_len = at - sysid;
    if(cmd_len == 0 
       || cmd_len != strlen(NST_CPPROXY_CFG_CMD_NAME)
       || memcmp(sysid, NST_CPPROXY_CFG_CMD_NAME, cmd_len))
        return NST_ERROR;

    sysid = at + 1; /* pointing one passed the last @ */
    sysid_len = sysid_len - cmd_len - 1; /* recalc the sysid_len without
                                          * the leading cpproxy
                                          */
    at = strchr (sysid, '@');
    if(!at)
        return NST_ERROR;

    box_name_len = at - sysid;
    if(box_name_len == 0 || box_name_len + 1 > NST_MAX_CFG_NAME_ELT_BUF_SIZE) {
        return NST_ERROR;
    } else {
        memcpy(cpproxy_cfg.my_box_name, sysid, box_name_len);
        cpproxy_cfg.my_box_name[box_name_len] = '\0';
    }

    if(sysid_len <= box_name_len)
        return NST_ERROR;

    dc_name_len = sysid_len - box_name_len - 1;
    if(dc_name_len +1 >= NST_MAX_CFG_NAME_ELT_BUF_SIZE) {
        return NST_ERROR;
    } else {
        memcpy(cpproxy_cfg.my_dc_name, at + 1, dc_name_len);
        cpproxy_cfg.my_dc_name[dc_name_len] = '\0';
    }

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "my box name=%s",
                cpproxy_cfg.my_box_name);
    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "my cluster name=%s",
                cpproxy_cfg.my_dc_name);

    return NST_OK;
}

nst_status_e
nst_cpproxy_cfg_cold_start_part1(void)
{
    nst_status_e ret;
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    if(nst_cpproxy_cfg_version_read(&cpproxy_cfg.version,
                                    &cpproxy_cfg.dir_names)
       != NST_OK)
        return NST_ERROR;

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "starting with config version %ui",
                cpproxy_cfg.version);

    ret = nst_cpproxy_cfg_local_dc_read(&cpproxy_cfg.my_dc,
                                        cpproxy_cfg.my_dc_name,
                                        &cpproxy_cfg.dir_names);
    if(ret != NST_OK)
        return ret;
    cpproxy_cfg.my_proc = (cpproxy_cfg.my_dc)->my_proc;
    cpproxy_cfg.my_box = &((cpproxy_cfg.my_proc)->box);

    ret = nst_cpproxy_cfg_svc_refresh_all(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_svc_read(&cpproxy_cfg.diff,
                                   &cpproxy_cfg.dir_names);
    if(ret != NST_OK)
        return ret;

    reload_status |= nst_cpproxy_cfg_svc_apply_added(&cpproxy_cfg);
    if(reload_status & NST_CFG_RELOAD_STATUS_ERROR_BIT)
        return NST_ERROR;


    return NST_OK;
}

nst_status_e
nst_cpproxy_cfg_cold_start_part2(void)
{
    nst_status_e ret;

    ret = nst_cpproxy_cfg_svc_listen(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_remote_dc_refresh_all(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_remote_dc_read(&cpproxy_cfg.diff,
                                         &cpproxy_cfg.dir_names,
                                         cpproxy_cfg.svc_ghash);
    if(ret != NST_OK)
       return ret;

    ret = nst_cpproxy_cfg_remote_dc_apply_added(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_application_refresh_all(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_application_read(&cpproxy_cfg.diff,
                                        &cpproxy_cfg.dir_names,
                                        cpproxy_cfg.my_dc_name);
    if(ret != NST_OK)
        return ret;

    ret = nst_cpproxy_cfg_application_apply_added(&cpproxy_cfg);
    if(ret != NST_OK)
        return ret;

    return NST_OK;
}

static nst_status_e
nst_cpproxy_cfg_reload_pre_check(void)
{
    nst_memzero(&cpproxy_cfg.reload,
                sizeof(cpproxy_cfg.reload));
    if(nst_cpproxy_cfg_set_dirs(&cpproxy_cfg.reload.dir_names,
                                cpproxy_cfg.dir_names.cfg,
                                NST_CFG_LATEST_DIR_NAME)) {
        return NST_ERROR;
    }

    if(cpproxy_cfg.diff.old_version != cpproxy_cfg.version) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "the old version (%ui) in the diff file %s%c%s is not the "
                    "same as the working versions (%ui)",
                    cpproxy_cfg.diff.old_version,
                    cpproxy_cfg.reload.dir_names.base,
                    NST_DIR_DELIMITER_CHAR,
                    NST_CFG_DIFF_FILENAME,
                    cpproxy_cfg.version);
        return NST_ERROR;
    }
if(nst_cpproxy_cfg_version_read(&cpproxy_cfg.reload.version,
                                    &cpproxy_cfg.reload.dir_names)) {
        return NST_ERROR;
    }


    if(cpproxy_cfg.reload.version < cpproxy_cfg.version) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "reloading with an older version (%ud). "
                    "current version (%ud)",
                    cpproxy_cfg.reload.version,
                    cpproxy_cfg.version);
        return NST_ERROR;
    } else if(cpproxy_cfg.reload.version == cpproxy_cfg.version) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reloading with the same version (%ud)",
                    cpproxy_cfg.version);
        return NST_DONE;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reloading with new version (%ud)",
                    cpproxy_cfg.reload.version);
    }

    if(cpproxy_cfg.diff.removed.dcs
       &&
       nst_genhash_find(cpproxy_cfg.diff.removed.dcs, cpproxy_cfg.my_dc_name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "my cluster %s is removed in the laster config "
                    "(version: %ud) during reload?",
                    cpproxy_cfg.my_dc_name,
                    cpproxy_cfg.reload.version);
        return NST_ERROR;
    }

    if(cpproxy_cfg.diff.added.dcs
       &&
       nst_genhash_find(cpproxy_cfg.diff.added.dcs, cpproxy_cfg.my_dc_name)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "my cluster %s is added in the latest config "
                    "(version: %ud) during reload?",
                    cpproxy_cfg.my_dc_name,
                    cpproxy_cfg.reload.version);
        return NST_ERROR;
    }

    return NST_OK;
}

static nst_cfg_reload_status_e
nst_cpproxy_cfg_reload_local_dc(void)
{
    nst_cfg_reload_status_e reload_status
        = NST_CFG_RELOAD_STATUS_NO_CHANGE;
    return reload_status;
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_reload_part1(void)
{
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    switch(nst_cpproxy_cfg_reload_pre_check()) {
    case NST_OK:
        break;
    case NST_DONE:
        goto DONE;
    default:
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }

    reload_status |= nst_cpproxy_cfg_reload_local_dc();

 DONE:
    return reload_status;
}

void
nst_cpproxy_cfg_reload_reset(void)
{
    nst_cpproxy_cfg_local_dc_free(cpproxy_cfg.reload.my_new_dc);
    cpproxy_cfg.reload.my_new_dc = NULL;
    nst_cfg_diff_flush(&cpproxy_cfg.diff);
}

nst_cfg_reload_status_e
nst_cpproxy_cfg_reload_part2(void)
{
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;
    nst_cfg_reload_status_e svc_add_status;

    if(nst_cpproxy_cfg_svc_read(&cpproxy_cfg.diff,
                                &cpproxy_cfg.reload.dir_names)) {
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }
    if(nst_cpproxy_cfg_remote_dc_read(&cpproxy_cfg.diff,
                                      &cpproxy_cfg.reload.dir_names,
                                      cpproxy_cfg.svc_ghash)) {
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }
    if(nst_cpproxy_cfg_application_read(&cpproxy_cfg.diff,
                                     &cpproxy_cfg.reload.dir_names,
                                     cpproxy_cfg.my_dc_name)) {
        reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
        goto DONE;
    }

    /* - start - apply svc diff */
    reload_status = nst_cpproxy_cfg_svc_apply_modified(&cpproxy_cfg,
                                              &cpproxy_cfg.reload.relisten);
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;

    nst_cpproxy_cfg_svc_apply_removed(&cpproxy_cfg);

    svc_add_status = nst_cpproxy_cfg_svc_apply_added(&cpproxy_cfg);
    reload_status |= svc_add_status;
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;
    if(svc_add_status & NST_CFG_RELOAD_STATUS_CHANGED)
        cpproxy_cfg.reload.relisten = TRUE;
    /* - end - apply svc diff */

    if(cpproxy_cfg.reload.relisten) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO, "re-scan listening addresses");
        if(nst_cpproxy_cfg_svc_listen(&cpproxy_cfg) == NST_ERROR) {
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            goto DONE;
        }
    }

    /* - start - apply remote cluster diff */
    reload_status |= nst_cpproxy_cfg_remote_dc_apply_modified(&cpproxy_cfg);
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;

    nst_cpproxy_cfg_remote_dc_apply_removed(&cpproxy_cfg);

    reload_status |= nst_cpproxy_cfg_remote_dc_apply_added(&cpproxy_cfg);
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;
    /* - end - apply remote cluster diff */


    /* - start - apply application diff */
    reload_status |= nst_cpproxy_cfg_application_apply_modified(&cpproxy_cfg);
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;

    nst_cpproxy_cfg_application_apply_removed(&cpproxy_cfg);

    reload_status |= nst_cpproxy_cfg_application_apply_added(&cpproxy_cfg);
    if(reload_status
       & (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;
    /* - end - apply application diff */

 DONE:
    if(!(reload_status & NST_CFG_RELOAD_STATUS_ERROR_BIT)
       && !(reload_status & NST_CFG_RELOAD_STATUS_RESTART_NEEDED)) {
        /* promote to the latest version */
        memcpy(&cpproxy_cfg.dir_names,
               &cpproxy_cfg.reload.dir_names,
               sizeof(cpproxy_cfg.dir_names));
        cpproxy_cfg.version = cpproxy_cfg.reload.version;
    }

    return reload_status;
}

bool
nst_cpproxy_cfg_am_i_private_spc(void)
{
    if ((cpproxy_cfg.my_dc)->type == NST_CFG_DC_TYPE_PRIVATE)
        return TRUE;
    return FALSE;
}

bool
nst_cpproxy_cfg_tp_conn_acl(const nst_connection_t *c)
{
    if(nst_genhash_find(cpproxy_cfg.sproxy_ip_ghash, &c->peer_sockaddr)) {
        return TRUE;
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "accepted TP connection request from unknown IP \"%s\". "
                    "rejected",
                    nst_sockaddr_get_ip_str(&c->peer_sockaddr));
        return FALSE;
    }
}

nst_status_e
nst_cpproxy_cfg_init(const char *cfg_dir_name, 
                     const char *sys_id,
                     bool test_only_mode,
                     bool latest_cfg)
{
    nst_cfg_init();

    memset(&cpproxy_cfg, 0, sizeof(nst_cpproxy_cfg_t));

    cpproxy_cfg.test_only_mode = test_only_mode;

    if(nst_cpproxy_cfg_set_sysid(sys_id)) {
        return NST_ERROR;
    }

    if(nst_cpproxy_cfg_set_dirs(&cpproxy_cfg.dir_names,
                        cfg_dir_name,
                        latest_cfg ?
                        NST_CFG_LATEST_DIR_NAME : NST_CFG_WORKING_DIR_NAME)) {
        return NST_ERROR;
    }

    /* -start- init service cfg structures */
    cpproxy_cfg.listening_svc_ghash =
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        0, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_sockaddr, nst_sockaddr_cmp,
                        NULL, nst_cfg_svc_free,
                        NULL, NST_REFC_GENHASH_COPY_FUNC_NAME(nst_cfg_svc_s));
    cpproxy_cfg.svc_ghash =
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        0, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_cstr, nst_genhash_cstr_cmp,
                        NULL, nst_cfg_svc_free,
                        NULL, NULL);

    /* -end- init service cfg structures */

    /* -start- init remote cluster cfg structures */
    cpproxy_cfg.remote_dc_ghash =
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        0, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_cstr, nst_genhash_cstr_cmp,
                        NULL, nst_cpproxy_cfg_remote_dc_free,
                        NULL, NULL);
    cpproxy_cfg.sproxy_ip_ghash =
        nst_genhash_new(NST_GENHASH_MODE_NONE,
                        0, 0, 0,
                        &nst_cfg_allocator,
                        nst_genhash_sockaddr_ip, nst_sockaddr_cmp_ip,
                        NULL, NULL,
                        NULL, NULL);
    /* -end- init remote cluster cfg structures */

    /* -start- init application cfg structures */
    cpproxy_cfg.application_ghash
        = nst_genhash_new(NST_GENHASH_MODE_NONE,
                          0, 0, 0,
                          &nst_cfg_allocator,
                          nst_genhash_cstr, nst_genhash_cstr_cmp,
                          NULL, (nst_gen_destructor_f)nst_cfg_application_free,
                          NULL, NULL);

    cpproxy_cfg.domain_ghash = nst_genhash_new(NST_GENHASH_MODE_NONE,
                                               256, 0, 0,
                                               &nst_cfg_allocator,
                                               (nst_genhash_f)nst_genhash_mstr,
                                               (nst_compare_f)nst_str_cmp,
                                               NULL, NULL,
                                               NULL, NULL);

    /* -end- init application cfg structures */

    nst_cfg_diff_init(&cpproxy_cfg.diff);

    cpproxy_cfg_sticky_pool = nst_create_pool(NST_CPPROXY_CFG_MISC_POOL_SIZE,
                                              &nst_dl_logger);
    return NST_OK;
}

void
nst_cpproxy_cfg_reset(void)
{
    nst_cfg_application_t *application;
    nst_genhash_iter_t iter;

    nst_genhash_iter_init(cpproxy_cfg.application_ghash, &iter);
    while(nst_genhash_iter_next(&iter, NULL, (void **)&application)) {
        nst_cfg_domain_t *domain;
        size_t ndomains;
        size_t i;

        ndomains = nst_vector_get_nelts(application->domains);
        for(i = 0; i < ndomains; i++) {
            domain
                = *(nst_cfg_domain_t **)nst_vector_get_elt_at(application->domains,
                                                              i);
            nst_cpproxy_cfg_domain_del(&cpproxy_cfg, domain, TRUE);
        }
    }
    nst_genhash_free(cpproxy_cfg.domain_ghash);

    nst_genhash_free(cpproxy_cfg.application_ghash);

    nst_genhash_free(cpproxy_cfg.remote_dc_ghash);
    nst_genhash_free(cpproxy_cfg.sproxy_ip_ghash);

    nst_genhash_free(cpproxy_cfg.listening_svc_ghash);
    nst_genhash_free(cpproxy_cfg.svc_ghash);

    nst_cpproxy_cfg_local_dc_free(cpproxy_cfg.my_dc);
    cpproxy_cfg.my_dc = NULL;

    nst_cfg_diff_reset(&cpproxy_cfg.diff);

    if(cpproxy_cfg_sticky_pool)
        nst_destroy_pool(cpproxy_cfg_sticky_pool);

    nst_cfg_reset();
}
