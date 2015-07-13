#ifndef _NST_CPPROXY_CYCLE_H_
#define _NST_CPPROXY_CYCLE_H_

#include <nst_config.h>
#include <nst_timer.h>
#include <nst_limits.h>

typedef struct nst_cpproxy_cycle_s nst_cpproxy_cycle_t;

struct nst_cpproxy_cfg_s;

extern nst_cpproxy_cycle_t master_cycle;

struct nst_cpproxy_cycle_s
{
    nst_timer_context_t timer_ctx;

    nst_timer_t log_flush_timer;

    pid_t pid;
    bool  reload;
    bool  terminate;
    bool  terminating;

    int    argc;
    char **os_argv;
    char **argv;

    int exit_num;

    struct {
        bool verbose;
        bool test_only_mode;
        bool test_reload;
        bool show_version;
        bool stderr;
        bool latest_cfg;
        const char *cfg_dir_name;
        const char *sys_id;
        const char *pid_filename;
    } parsed_cmd_argv;
};

extern nst_cpproxy_cycle_t master_cycle;

void nst_cpproxy_cycle_init_b4_cmd_argv(nst_cpproxy_cycle_t *cycle);
void nst_cpproxy_cycle_init_after_cmd_argv(nst_cpproxy_cycle_t *cycle);

void nst_cpproxy_cycle_reset(nst_cpproxy_cycle_t *cycle);


nst_status_e nst_cpproxy_cycle_cold_start(nst_cpproxy_cycle_t *cycle);
void nst_cpproxy_cycle_reload(nst_cpproxy_cycle_t *cycle);

#endif
