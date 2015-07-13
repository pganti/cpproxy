
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_PROCESS_CYCLE_H_INCLUDED_
#define _NST_PROCESS_CYCLE_H_INCLUDED_


#include <nst_config.h>
#include <nst_core.h>


#if 0
#define NST_CMD_OPEN_CHANNEL   1
#define NST_CMD_CLOSE_CHANNEL  2
#define NST_CMD_QUIT           3
#define NST_CMD_TERMINATE      4
#define NST_CMD_REOPEN         5


#define NST_PROCESS_SINGLE   0
#define NST_PROCESS_MASTER   1
#define NST_PROCESS_WORKER   2


void nst_master_process_cycle(nst_cycle_t *cycle);
void nst_single_process_cycle(nst_cycle_t *cycle);
#endif

extern nst_uint_t      nst_process;
extern nst_pid_t       nst_pid;
extern nst_pid_t       nst_new_binary;
extern nst_uint_t      nst_inherited;
extern nst_uint_t      nst_daemonized;
extern nst_uint_t      nst_threaded;
extern nst_uint_t      nst_exiting;

extern sig_atomic_t    nst_reap;
extern sig_atomic_t    nst_sigio;
extern sig_atomic_t    nst_quit;
extern sig_atomic_t    nst_debug_quit;
extern sig_atomic_t    nst_terminate;
extern sig_atomic_t    nst_noaccept;
extern sig_atomic_t    nst_reconfigure;
extern sig_atomic_t    nst_reopen;
extern sig_atomic_t    nst_change_binary;


#endif /* _NST_PROCESS_CYCLE_H_INCLUDED_ */
