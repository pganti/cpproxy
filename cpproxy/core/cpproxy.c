#include "nst_cpproxy_config.h"
#include "nst_cpproxy_cycle.h"

/* cpproxy/http/ includes */
#include <nst_http.h>

/* cpproxy/cfg/ includes */
#include <nst_cpproxy_cfg.h>

/* libevent includes */
#include <nst_tp_connection.h>
#include <nst_event.h>

/* libnstcfg includes */
#include <nst_cfg.h>

/* libcore includes */
#include <nst_timer.h>
#include <nst_crc32.h>
#include <nst_types.h>
#include <nst_log.h>
#include <nst_types.h>
#include <nst_corelib.h>

/* std and sys includes */
#include <sysexits.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define NST_CPPROXY_AGENT_NAME "cpproxy"

static nst_status_e nst_save_argv(nst_cpproxy_cycle_t *cycle,
                                  int argc, char *const *argv);
static nst_status_e nst_getopt(nst_cpproxy_cycle_t *cycle);

int nst_cpproxy_hc_init (void);

int
main(int argc, char *const *argv)
{
    int sys_exit_num = 0;

    nst_cpproxy_cycle_init_b4_cmd_argv(&master_cycle);

    if (nst_save_argv(&master_cycle, argc, argv) != NST_OK) {
        nst_cpproxy_cycle_reset(&master_cycle);
        return -1;
    }

    if (nst_getopt(&master_cycle) != NST_OK) {
        nst_cpproxy_cycle_reset(&master_cycle);
        return EX_USAGE;
    }

    if (master_cycle.parsed_cmd_argv.show_version) {
        fprintf(stdout, "cpproxy version: %s r%u\n\n",
                NST_CPPROXY_VERSION, NST_CPPROXY_BUILD);

        nst_cpproxy_cycle_reset(&master_cycle);
        return 0;
    }

    nst_cpproxy_cycle_init_after_cmd_argv(&master_cycle);
    
#if (NST_PCRE)
    nst_regex_init();
#endif

#if (NST_OPENSSL)
    nst_ssl_init(log);
#endif

    if(nst_cpproxy_cycle_cold_start(&master_cycle) != NST_OK) {
        goto DONE;
    }

    if(master_cycle.parsed_cmd_argv.test_only_mode) {
        if(master_cycle.parsed_cmd_argv.test_reload) {
            master_cycle.reload = TRUE;
            nst_cpproxy_cycle_reload(&master_cycle);
        }
        goto DONE;
    }

    /* test_only_mode should not reach here */

    nst_assert(master_cycle.parsed_cmd_argv.test_only_mode == FALSE);

    while(!master_cycle.terminate) {
        nst_process_events_and_timers();
        nst_cpproxy_cycle_reload(&master_cycle);
    }

 DONE:
    sys_exit_num = master_cycle.exit_num;
    nst_cpproxy_cfg_reset();
    nst_http_reset();
    nst_tp_reset();
    nst_event_cleanup();
    nst_cpproxy_cycle_reset(&master_cycle);
    nst_corelib_reset();
    return sys_exit_num;

#if 0
    if (ngx_init_signals(cycle->log) != NGX_OK) {
        return 1;
    }

    if (!ngx_inherited && ccf->daemon) {
        if (ngx_daemon(cycle->log) != NGX_OK) {
            return 1;
        }

        ngx_daemonized = 1;
    }

    if (ngx_create_pidfile(&ccf->pid, cycle->log) != NGX_OK) {
        return 1;
    }

    if (ngx_process == NGX_PROCESS_MASTER) {
        ngx_master_process_cycle(cycle);

    } else {
        ngx_single_process_cycle(cycle);
    }

    return 0;
#endif
}

static nst_status_e
nst_save_argv(nst_cpproxy_cycle_t *cycle, int argc, char *const *argv)
{
#if (NST_FREEBSD)

    cycle.os_argv = (char **) argv;
    cycle.argc = argc;
    cycle.argv = (char **) argv;

#else
    size_t     len;
    nst_int_t  i;

    cycle->os_argv = (char **) argv;
    cycle->argc = argc;

    cycle->argv = calloc((argc + 1), sizeof(char *));
    if (cycle->argv == NULL) {
        return NST_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = strlen(argv[i]) + 1;

        cycle->argv[i] = calloc(len, sizeof(char));
        if (cycle->argv[i] == NULL) {
            return NST_ERROR;
        }

        memcpy(cycle->argv[i], argv[i], len);
    }

    cycle->argv[i] = NULL;

#endif

    return NST_OK;
}

static void nst_cpproxy_print_usage(void)
{
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr,
            "cpproxy [-vetV] -d <config-directory> -s <sys-id> -p <pid-file-in-full-path>\n");
    fprintf(stderr,
            "    -v: show verbose message (effective before reading config file)\n");
    fprintf(stderr,
            "    -V: show version\n");
    fprintf(stderr,
            "    -t: test the config file only (NOT implemented)\n");
    fprintf(stderr,
            "    -d <config-directory>: the directory that has  config files\n");
    fprintf(stderr,
            "    -s <sys-id>: the sysid to idenitfy the cpproxy from the config file\n");
    fprintf(stderr,
            "    -p <pid-file-in-full-path>: the PID file in full path name\n");
    fprintf(stderr,
            "    -e: ALSO log to stderr (mostly for dev debugging)\n");

    return;
}
                
static nst_status_e
nst_getopt(nst_cpproxy_cycle_t *cycle)
{
    nst_int_t  i;
    nst_int_t argc = cycle->argc;
    char *const *argv = cycle->argv;
    bool got_cfg_dir = FALSE;
    bool got_pid_file = FALSE;
    bool got_sysid = FALSE;
    nst_status_e ret = NST_OK;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "Invalid option: \"%s\"", argv[i]);
            return NST_ERROR;
        }

        switch (argv[i][1]) {

        case 'v':
            cycle->parsed_cmd_argv.verbose = TRUE;
            break;

        case 'V':
            cycle->parsed_cmd_argv.show_version = TRUE;
            break;

        case 't':
            cycle->parsed_cmd_argv.test_only_mode = TRUE;
            break;

        case 'd':
            if (argv[i + 1] == NULL) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                              "the option \"-d\" requires a config directory");
                return NST_ERROR;
            }

            got_cfg_dir = TRUE;
            cycle->parsed_cmd_argv.cfg_dir_name = argv[++i];
            break;

        case 's':
            if (argv[i + 1] == NULL) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                              "the option \"-s\" requires a system id");
                return NST_ERROR;
            }

            got_sysid = TRUE;
            cycle->parsed_cmd_argv.sys_id = argv[++i];
            break;

        case 'p':
            if (argv[i + 1] == NULL) {
                NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                            "the option \"-p\" requires a full pathname to pid file\n");
                return NST_ERROR;
            }

            got_pid_file = TRUE;
            cycle->parsed_cmd_argv.pid_filename = argv[++i];
            break;

        case 'e':
            cycle->parsed_cmd_argv.stderr = TRUE;
            break;
        case 'r':
            cycle->parsed_cmd_argv.test_reload = TRUE;
            break;
        case 'l':
            cycle->parsed_cmd_argv.latest_cfg = TRUE;
            break;
        default:
            NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                        "Invalid option: \"%s\"", argv[i]);
            return NST_ERROR;
        }
    }

    if(cycle->parsed_cmd_argv.show_version)
        return NST_OK;

    if(cycle->parsed_cmd_argv.test_reload) {
        if(!cycle->parsed_cmd_argv.test_only_mode) {
            fprintf(stderr,
                    "Invalid command args: -r must be used with -t\n");
            ret = NST_ERROR;
        }

        if(cycle->parsed_cmd_argv.latest_cfg) {
            fprintf(stderr,
                    "Invalid command args: -r cannot be used with -l\n");
            ret = NST_ERROR;
        }
    }

    if(!got_cfg_dir) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "Invalid command args: -d option is missing");
        ret = NST_ERROR;
    }

    if(!got_sysid) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "Invalid command args: -s option is missing");
        ret = NST_ERROR;
    }    
        
    if(!got_pid_file && !cycle->parsed_cmd_argv.test_only_mode) {
        NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                    "Invalid command args: -p option is missing");
        ret = NST_ERROR;
    }

    if(ret == NST_ERROR)
        nst_cpproxy_print_usage();

    return ret;
}
