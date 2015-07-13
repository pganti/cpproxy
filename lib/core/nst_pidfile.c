#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "nst_types.h"

int
nst_pidfile_write (char * name)
{
    int                 fd;
    char                buf[32];
    char                fname [1024];
    pid_t               pid;

    pid = getpid ();
    snprintf (fname, sizeof(fname), "/var/run/%s.pid", name);

    fd = open (fname, O_WRONLY | O_CREAT | O_TRUNC); // | O_TEXT);
    if (fd < 0) {
        return NST_ERROR;
    }

    snprintf(buf, sizeof(buf), "%d\n", (int) getpid());
    write (fd, buf, strlen (buf));

    close (fd);

    return NST_OK;
}


pid_t
nst_pidfile_read (char * name)
{
    FILE              * fp;
    char                fname [1024];
    pid_t               pid = -1;
    int                 i;

    snprintf (fname, sizeof(fname), "/var/run/%s.pid", name);

    fp = fopen(fname, "r");
    if (fp != NULL) {
        i = -1;
        if (fscanf (fp, "%d", &i) == 1) {
            pid = (pid_t) i;
        }
        fclose (fp);
        return pid;
    }

    return -1;
}

void
nst_pidfile_remove (char * name)
{
    char                fname [1024];

    snprintf (fname, sizeof(fname), "/var/run/%s.pid", name);

	unlink (fname);
}
