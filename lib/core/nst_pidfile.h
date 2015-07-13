#ifndef __NST_PIDFILE_H__
#define __NST_PIDFILE_H__
int nst_pidfile_write (char * name);
pid_t nst_pidfile_read (char * name);
void nst_pidfile_remove (char * name);
#endif /*__NST_PIDFILE_H__*/
