
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>

#if 0
	if (background) { /* ok, we need to detach this process */
		int i, fd;
		if (quietmode < 0)
			printf("Detatching to start %s...", startas);
		i = fork();
		if (i<0) {
			fatal("Unable to fork.\n");
		}
		if (i) { /* parent */
			if (quietmode < 0)
				printf("done.\n");
			exit(0);
		}
		/* child continues here */
		/* now close all extra fds */
		for (i=getdtablesize()-1; i>=0; --i) close(i);
		/* change tty */
        if ((fd = open(_PATH_CONSOLE, O_RDWR)) == -1)
		fd = open("/dev/tty", O_RDWR);
		ioctl(fd, TIOCNOTTY, 0);
		close(fd);
		chdir("/");
		umask(0); /* set a default for dumb programs */
		setpgid(0,0);  /* set the process group */
		fd=open("/dev/null", O_RDWR); /* stdin */
		dup(fd); /* stdout */
		dup(fd); /* stderr */
	}

#endif

nst_int_t
nst_daemon(nst_log_t *log, const char * changeroot)
{
    int              fd;
    nst_pid_t        nst_pid;
    int              status;

    switch (fork()) {
    case -1:
        nst_log_error(NST_LOG_EMERG, log, nst_errno, "fork() failed");
        return NST_ERROR;

    case 0:
        nst_log_debug(NST_LOG_EMERG, log, nst_errno, "In child");
        sleep (1);
        break;

    default:
        nst_log_debug(NST_LOG_EMERG, log, nst_errno, "In Parent");
        exit(0);
    }

    nst_pid = getpid();

    if (setsid() == -1) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno, "setsid() failed");
        return NST_ERROR;
    }

    umask(0);

    if (changeroot) {
        status = chroot ((const char *)changeroot);
        if (status != 0) {
            char             errstr [1024];
            nst_strerror_r (errno, errstr, sizeof(errstr));
            nst_log_error(NST_LOG_EMERG, log, nst_errno,
                          "Failed to do chroot");
            return NST_ERROR;
        }
    }

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno,
                      "open(\"/dev/null\") failed");
        return NST_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno, "dup2(STDIN) failed");
        return NST_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        nst_log_error(NST_LOG_EMERG, log, nst_errno, "dup2(STDOUT) failed");
        return NST_ERROR;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            nst_log_error(NST_LOG_EMERG, log, nst_errno, "close() failed");
            return NST_ERROR;
        }
    }

    nst_log_error(NST_LOG_EMERG, log, nst_errno,
                  "Set stdout and stdin stdout=%d, stdin=%d\n",
                  STDIN_FILENO, STDOUT_FILENO);

    return NST_OK;
}
