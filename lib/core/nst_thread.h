
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_THREAD_H_INCLUDED_
#define _NST_THREAD_H_INCLUDED_

#include "nst_config.h"
#include "nst_types.h"

#if (NST_THREADS)

#define NST_MAX_THREADS      128

#include <pthread.h>
typedef pthread_t                    nst_tid_t;


#define nst_thread_self()            pthread_self()
#define nst_log_tid                  (int) nst_thread_self()

#if (NST_FREEBSD) && !(NST_LINUXTHREADS)
#define NST_TID_T_FMT                "%p"
#else
#define NST_TID_T_FMT                "%d"
#endif


typedef pthread_key_t                nst_tls_key_t;

#define nst_thread_key_create(key)   pthread_key_create(key, NULL)
#define nst_thread_key_create_n      "pthread_key_create()"
#define nst_thread_set_tls           pthread_setspecific
#define nst_thread_set_tls_n         "pthread_setspecific()"
#define nst_thread_get_tls           pthread_getspecific


#define NST_MUTEX_LIGHT     0

struct nst_log_s;
typedef struct nst_mutex_s {
    pthread_mutex_t   mutex;
    struct nst_log_s *log;
} nst_mutex_t;

typedef struct {
    pthread_cond_t    cond;
    struct nst_log_s *log;
} nst_cond_t;

#define nst_thread_sigmask     pthread_sigmask
#define nst_thread_sigmask_n  "pthread_sigmask()"

#define nst_thread_join(t, p)  pthread_join(t, p)

#define nst_setthrtitle(n)



nst_int_t nst_mutex_trylock(nst_mutex_t *m);
void nst_mutex_lock(nst_mutex_t *m);
void nst_mutex_unlock(nst_mutex_t *m);


#define nst_thread_volatile   volatile


typedef struct {
    nst_tid_t    tid;
    nst_cond_t  *cv;
    nst_uint_t   state;
} nst_thread_t;

#define NST_THREAD_FREE   1
#define NST_THREAD_BUSY   2
#define NST_THREAD_EXIT   3
#define NST_THREAD_DONE   4

extern nst_int_t              nst_threads_n;
extern volatile nst_thread_t  nst_threads[NST_MAX_THREADS];


typedef void *  nst_thread_value_t;

nst_int_t nst_init_threads(int n, size_t size, nst_cycle_t *cycle);
nst_err_t nst_create_thread(nst_tid_t *tid,
    nst_thread_value_t (*func)(void *arg), void *arg, nst_log_t *log);

nst_mutex_t *nst_mutex_init(nst_log_t *log, nst_uint_t flags);
void nst_mutex_destroy(nst_mutex_t *m);


nst_cond_t *nst_cond_init(nst_log_t *log);
void nst_cond_destroy(nst_cond_t *cv);
nst_int_t nst_cond_wait(nst_cond_t *cv, nst_mutex_t *m);
nst_int_t nst_cond_signal(nst_cond_t *cv);


#else /* !NST_THREADS */

#define nst_thread_volatile

#define nst_log_tid           0
#define NST_TID_T_FMT         "%d"

#define nst_mutex_trylock(m)  NST_OK
#define nst_mutex_lock(m)
#define nst_mutex_unlock(m)

#define nst_cond_signal(cv)

#define nst_thread_main()     1

#endif

#endif /* _NST_THREAD_H_INCLUDED_ */
