nst_uint_t    nst_process;
nst_pid_t     nst_pid;
nst_uint_t    nst_threaded;

sig_atomic_t  nst_reap;
sig_atomic_t  nst_sigio;
sig_atomic_t  nst_terminate;
sig_atomic_t  nst_quit;
sig_atomic_t  nst_debug_quit;
nst_uint_t    nst_exiting;
sig_atomic_t  nst_reconfigure;
sig_atomic_t  nst_reopen;

sig_atomic_t  nst_change_binary;
nst_pid_t     nst_new_binary;
nst_uint_t    nst_inherited;
nst_uint_t    nst_daemonized;

sig_atomic_t  nst_noaccept;
nst_uint_t    nst_noaccepting;
nst_uint_t    nst_restart;

