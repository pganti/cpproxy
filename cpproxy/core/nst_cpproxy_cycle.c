/* always include myself first */
#include "nst_cpproxy_cycle.h"

/* cpproxy/cfg/ includes */
#include <nst_cpproxy_cfg.h>
#include <nst_cpproxy_cfg_local_proc.h>

/* cpproxy/http/ includes */
#include <nst_http.h>
#include <nst_http_transaction.h>

/* libevent includes */
#include <nst_event.h>
#include <nst_tp_connection.h>

/* libnst_cpt includes */
#include <nst_cpt.h>

/* libcore includes */
#include <nst_timer.h>
#include <nst_corelib.h>
#include <nst_log.h>
#include <nst_errno.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#define NST_TERMINATE_SIGNAL   SIGTERM
#define NST_RECONFIGURE_SIGNAL SIGHUP

static char pid_filename[NST_MAX_FILENAME_BUF_SIZE] = {
    [0] = '\0',
};

nst_cpproxy_cycle_t master_cycle;

static void nst_signal_handler(int signo);
static void nst_sigalrm_handler(int signo);
static nst_status_e nst_cpproxy_cycle_init_signals(void);
static void atexit_func(void);
static nst_status_e nst_cpproxy_cycle_create_pidfile(const nst_cpproxy_cycle_t *cycle);
static void nst_cpproxy_cycle_delete_pidfile(void);
static nst_status_e set_timer_resolution(const nst_cpproxy_cfg_local_proc_t *my_proc);
static nst_status_e setup_myproc(const nst_cpproxy_cycle_t *cycle,
                                 const nst_cpproxy_cfg_t *cpproxy,
                                 bool reset_log_cfg);

void
nst_cpproxy_cycle_init_b4_cmd_argv(nst_cpproxy_cycle_t *cycle)
{
    memset(cycle, 0, sizeof(*cycle));
}

void
nst_cpproxy_cycle_init_after_cmd_argv(nst_cpproxy_cycle_t *cycle)
{
    /* nst_corelib_init() should initialize the followings:
     * 1. nst_time_init()
     * 2. nst_log_init()
     *    => nginx compaitiable nst_dl_logger is availabe at this point
     *    => all NST_???_LOG() will be logger to stderr until the
     *       config file is read.
     * 3. nst_os_init()
     *    => init pagesize...for memory allocation functions
     */
    nst_corelib_init(cycle->parsed_cmd_argv.sys_id);

    if(cycle->parsed_cmd_argv.verbose) {
        nst_log_noc_set_level(NST_LOG_LEVEL_DEBUG);
        nst_log_debug_set_level(NST_LOG_LEVEL_DEBUG);
    }

    /* Initialize cpproxy expire timer context to
     * handle timeout event/action.
     */
    
    nst_timer_init(&cycle->timer_ctx);

    if(cycle->parsed_cmd_argv.stderr) {
        nst_log_set_stderr(&nst_access_logfac, TRUE);
        nst_log_set_stderr(&nst_debug_logfac, TRUE);
        nst_log_set_stderr(&nst_noc_logfac, TRUE);
        nst_log_set_stderr(&nst_audit_logfac, TRUE);
    } else {
        nst_log_set_stderr(&nst_access_logfac, FALSE);
        nst_log_set_stderr(&nst_debug_logfac, FALSE);
        nst_log_set_stderr(&nst_noc_logfac, FALSE);
        nst_log_set_stderr(&nst_audit_logfac, FALSE);
    }

    cycle->pid = getpid();

    if(nst_cpproxy_cycle_init_signals() != NST_OK) {
	printf("failed signal init\n");
        exit(-1);
   }

    if(nst_cpproxy_cycle_create_pidfile(cycle) != NST_OK)
        exit(-1);

    if(atexit(atexit_func) == -1)
        exit(-1);

    if(nst_cpproxy_cfg_init(cycle->parsed_cmd_argv.cfg_dir_name,
                            cycle->parsed_cmd_argv.sys_id,
                            cycle->parsed_cmd_argv.test_only_mode,
                            cycle->parsed_cmd_argv.latest_cfg))
        exit(NST_EXIT_CONFIG_FAILED);
}

void nst_cpproxy_cycle_reset(nst_cpproxy_cycle_t *cycle)
{
    int i;
    for(i = 0; i < cycle->argc; i++) {
        free(cycle->argv[i]);
    }
    free(cycle->argv);

    memset(cycle, 0, sizeof(*cycle));
}

static nst_status_e
nst_cpproxy_cycle_create_pidfile(const nst_cpproxy_cycle_t *cycle)
{
    ssize_t            len;
    int               fd;
    u_char            pid[NST_INT64_LEN + 2];

    if(cycle->parsed_cmd_argv.test_only_mode)
        return NST_OK;

    if(strlen(cycle->parsed_cmd_argv.pid_filename) + 1
       > NST_MAX_FILENAME_BUF_SIZE) {
        fprintf(stderr,
                "pid filename \"%s\" is too long > %ud",
                cycle->parsed_cmd_argv.pid_filename,
                NST_MAX_FILENAME_BUF_SIZE - 1);
    } else {
        strcpy(pid_filename, cycle->parsed_cmd_argv.pid_filename);
    }

    fd = open(cycle->parsed_cmd_argv.pid_filename, O_RDWR | O_CREAT, 0644);

    if(fd == -1) {
        fprintf(stderr,
                "Cannot open pid file \"%s\" for writing. %s(%d).\n"
                "Another process is running? If not, please delete it.",
                cycle->parsed_cmd_argv.pid_filename,
                nst_strerror(errno), errno);
        return NST_ERROR;
    }

    len = nst_snprintf(pid, NST_INT64_LEN + 2, "%P%N", cycle->pid) - pid;

    if (write(fd, pid, len) == len) {
        return NST_OK;
    } else {
        fprintf(stderr,
                "cannot write pid to file %s. %s(%d).",
                cycle->parsed_cmd_argv.pid_filename,
                nst_strerror(errno), errno);
        return NST_ERROR;
    }

    return NST_OK;
}

static void
nst_cpproxy_cycle_delete_pidfile(void)
{
    if(*pid_filename)
        unlink(pid_filename);
}

nst_status_e
nst_cpproxy_cycle_init_signals(void)
{
    size_t i;
    struct sigaction sa;
    int interested_signals[] = {
        NST_TERMINATE_SIGNAL,
        NST_RECONFIGURE_SIGNAL,
        SIGSEGV,
    };

    nst_memzero(&sa, sizeof(sa));
    sa.sa_flags = SA_RESTART;

    sigemptyset(&sa.sa_mask);
    for(i = 0;
        i < sizeof(interested_signals)/sizeof(interested_signals[0]);
        i++) {
        sa.sa_handler = nst_signal_handler;
        if(sigaction(interested_signals[i], &sa, NULL) == -1) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "sigaction(%d) failed. %s(%d)",
                        i,
                        nst_strerror(errno), errno);
            return NST_ERROR;
        }
    }

    sa.sa_handler = nst_sigalrm_handler;
    if(sigaction(SIGALRM, &sa, NULL) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "sigaction(SIGALRM) failed. %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    return NST_OK;
}

static void
nst_signal_handler(int signo)
{
    char *action = NULL;

    switch (signo) {
    case NST_TERMINATE_SIGNAL:
    case SIGINT:
        master_cycle.terminate = TRUE;
        action = "got exist signal";
        break;
    case NST_RECONFIGURE_SIGNAL:
        master_cycle.reload = TRUE;
        action = "got reconfigure signal";
        break;
    case SIGSEGV:
        nst_log_flush();
        nst_log_flush();
        exit(-1);
        break;
    }

    if(action) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO, "%s(%d)", action, signo);
    }
}


static void
nst_sigalrm_handler(int signo)
{
    nst_time_update(0, 0);
}

static void
atexit_func(void)
{
    nst_cpproxy_cycle_delete_pidfile();
}

static void
nst_cpproxy_cycle_set_exit_num(nst_cpproxy_cycle_t *cycle, int exit_num)
{
    if(!cycle->exit_num && exit_num)
        cycle->exit_num = exit_num;
}

nst_status_e
nst_cpproxy_cycle_cold_start(nst_cpproxy_cycle_t *cycle)
{
    nst_status_e ret = NST_OK;

    NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                "cold starting config");

    if(nst_cpproxy_cfg_cold_start_part1() != NST_OK) {
        nst_cpproxy_cycle_set_exit_num(cycle, NST_EXIT_CONFIG_FAILED);
        ret = NST_ERROR;
        goto DONE;
    }

    if(setup_myproc(cycle, &cpproxy_cfg, TRUE) != NST_OK) {
        ret = NST_ERROR;
        goto DONE;
    }

    if(!cycle->parsed_cmd_argv.test_only_mode)  {
        /* init event library */
        if(nst_event_init(&cpproxy_cfg.my_proc->event,
                          &master_cycle.timer_ctx) != NST_OK) {
            ret = NST_ERROR;
            goto DONE;
        }
        
        /* init TP */
        nst_tp_init(nst_http_transaction_init_connection, 
                    nst_cpproxy_cfg_tp_conn_acl);
    }

    /* init the cpt layer */
    nst_cpt_init();

    /* init the http layer */
    if(nst_http_init()) {
        ret = NST_ERROR;
        goto DONE;
    }

    ret = nst_cpproxy_cfg_cold_start_part2();
    if(ret != NST_OK) {
        nst_cpproxy_cycle_set_exit_num(cycle, NST_EXIT_CONFIG_FAILED);
    }

 DONE:
    nst_cpproxy_cfg_reload_reset();
    if(ret != NST_OK) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "cold start config result: ERROR");
        nst_cpproxy_cycle_set_exit_num(cycle, -1);
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "cold start config result: OK");
    }

    return ret;
}

void
nst_cpproxy_cycle_reload(nst_cpproxy_cycle_t *cycle)
{
    nst_cfg_reload_status_e reload_status = NST_CFG_RELOAD_STATUS_NO_CHANGE;

    if(!cycle->reload && !cycle->parsed_cmd_argv.test_reload)
        return;


        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reloading confg");
    reload_status |= nst_cpproxy_cfg_reload_part1();
                
    if(reload_status & 
       (NST_CFG_RELOAD_STATUS_ERROR_BIT | NST_CFG_RELOAD_STATUS_RESTART_NEEDED))
        goto DONE;

    if(reload_status & NST_CFG_RELOAD_STATUS_CHANGED) {
        if(setup_myproc(cycle, &cpproxy_cfg, cpproxy_cfg.reload.reset_log_cfg)) {
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            goto DONE;
        }
        if(!cycle->parsed_cmd_argv.test_only_mode
           && nst_event_reinit(&cpproxy_cfg.my_proc->event)) {
            reload_status |= NST_CFG_RELOAD_STATUS_HARD_ERROR;
            goto DONE;
        }
    }

    reload_status |= nst_cpproxy_cfg_reload_part2();

 DONE:
    if((reload_status & NST_CFG_RELOAD_STATUS_ERROR_BIT)
       &&
       (reload_status & NST_CFG_RELOAD_STATUS_CHANGED)) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR, 
                    "reload result: error encountered "
                    "after something has changed. restarting peacefully");
        cycle->terminating = TRUE;
        nst_cpproxy_cycle_set_exit_num(cycle, NST_EXIT_RELOAD_FAILED);
    } else if(reload_status & NST_CFG_RELOAD_STATUS_ERROR_BIT) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "reload result: error but nothing has been changed. "
                    "keep running with the old version");
        nst_cpproxy_cycle_set_exit_num(cycle, NST_EXIT_RELOAD_FAILED);
    } else if(reload_status & NST_CFG_RELOAD_STATUS_RESTART_NEEDED) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reload result: restart needed. restarting peacefully");
        cycle->terminating = TRUE;
        nst_cpproxy_cycle_set_exit_num(cycle, NST_EXIT_RELOAD_RESTART_NEEDED);
    } else if(reload_status & NST_CFG_RELOAD_STATUS_CHANGED) {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reload result: OK. something has been changed. "
                    "re-scan-listen:%d",
                    cpproxy_cfg.reload.relisten);
    } else {
        NST_NOC_LOG(NST_LOG_LEVEL_INFO,
                    "reload result: OK. nothing has been changed");
    }

    cycle->reload = FALSE;
    nst_cpproxy_cfg_reload_reset();
}

static void
log_flush_timer_handler(nst_timer_t *timer)
{
    nst_tp_log_stats();
    nst_log_flush();
    nst_timer_add(&master_cycle.timer_ctx,
                  timer,
                  cpproxy_cfg.my_proc->log_flush_interval_ms);
}

static nst_status_e
set_timer_resolution(const nst_cpproxy_cfg_local_proc_t *my_proc)
{
    struct itimerval  itv;
    
    itv.it_value.tv_sec
        = itv.it_interval.tv_sec
        = my_proc->timer_resolution_ms / 1000;
    itv.it_value.tv_usec
        = itv.it_interval.tv_usec
        = (my_proc->timer_resolution_ms % 1000) * 1000;

    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "setitimer() failed. %s(%d)",
                    nst_strerror(errno), errno);
        return NST_ERROR;
    } else {
        return NST_OK;
    }
}

static nst_status_e set_log_cfg(const nst_cpproxy_cfg_local_proc_t *my_proc)
{
    typedef nst_log_status_t (*nst_log_set_conf_f) (nst_log_conf_t *);

    size_t i;
    const nst_cfg_log_t *log = &my_proc->log;

    nst_log_facility_t *log_fac[] = {
        &nst_noc_logfac,
        &nst_debug_logfac,
        &nst_access_logfac,
    };

    nst_log_set_conf_f set_log_cfg_func[] = {
        nst_log_noc_set_conf,
        nst_log_debug_set_conf,
        nst_log_access_set_conf,
    };

    for(i = 0;
        i < (sizeof(set_log_cfg_func) / sizeof(set_log_cfg_func[0]));
        i++) {
        nst_log_conf_t log_cfg;
        nst_log_status_t log_ret;

        if(log_fac[i]->conf.flags.config_done != 0) {
            nst_log_fac_close(log_fac[i]);
        }

        nst_memzero(&log_cfg, sizeof(log_cfg));

        if(!log->target[0]) {
            if(nst_cpproxy_cfg_am_i_private_spc()) {
                log_cfg.flags.destfile = 1;
            } else {
                log_cfg.flags.destnet = 1;
            }
        } else {
            if(!strcmp(log->target, "local")) {
                log_cfg.flags.destfile = 1;
                log_cfg.dirname = (char *)log->dirname;
            } else {
                NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                              "logging to remote %s",
                              log->srv_ip);
                log_cfg.flags.destnet = 1;
                if(log->srv_ip[0])
                    strcpy(log_cfg.logserver, log->srv_ip);
            }
        }
        log_ret = set_log_cfg_func[i](&log_cfg);
        if(log_ret != NST_LOG_OK)
            return NST_ERROR;
    }

    return NST_OK;
}

static nst_status_e set_log_level(const nst_cpproxy_cfg_local_proc_t *my_proc)
{
    nst_log_debug_set_level(my_proc->dbg_log_lvl);
    nst_log_noc_set_level(my_proc->noc_log_lvl);

    return NST_OK;
}


static nst_status_e
setup_myproc(const nst_cpproxy_cycle_t *cycle,
             const nst_cpproxy_cfg_t *cpproxy_cfg,
             bool reset_log_cfg)
{
    if(cycle->parsed_cmd_argv.test_only_mode)
        return NST_OK;

    if(reset_log_cfg && set_log_cfg(cpproxy_cfg->my_proc) == NST_ERROR)
        return NST_ERROR;

    set_log_level(cpproxy_cfg->my_proc);

    if(set_timer_resolution(cpproxy_cfg->my_proc) == NST_ERROR)
        return NST_ERROR;

    master_cycle.log_flush_timer.handler = log_flush_timer_handler;

    nst_timer_add(&master_cycle.timer_ctx,
                  &master_cycle.log_flush_timer,
                  cpproxy_cfg->my_proc->log_flush_interval_ms);
                  
    return NST_OK;
}

