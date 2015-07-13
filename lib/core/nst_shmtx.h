
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_SHMTX_H_INCLUDED_
#define _NST_SHMTX_H_INCLUDED_


#include <nst_core.h>


typedef struct {
#if (NST_HAVE_ATOMIC_OPS)
    nst_atomic_t  *lock;
#else
    nst_fd_t       fd;
    u_char        *name;
#endif
} nst_shmtx_t;


nst_int_t nst_shmtx_create(nst_shmtx_t *mtx, void *addr, u_char *name);


#if (NST_HAVE_ATOMIC_OPS)

static nst_inline nst_uint_t
nst_shmtx_trylock(nst_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && nst_atomic_cmp_set(mtx->lock, 0, nst_getpid()));
}

#define nst_shmtx_lock(mtx)   nst_spinlock((mtx)->lock, nst_getpid(), 1024)

#define nst_shmtx_unlock(mtx) (void) nst_atomic_cmp_set((mtx)->lock, nst_getpid(), 0)

#define nst_shmtx_destory(mtx)


#else

static nst_inline nst_uint_t
nst_shmtx_trylock(nst_shmtx_t *mtx)
{
    nst_err_t  err;

    err = nst_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NST_EAGAIN) {
        return 0;
    }

    nst_log_abort(err, nst_trylock_fd_n " failed");

    return 0;
}


static nst_inline void
nst_shmtx_lock(nst_shmtx_t *mtx)
{
    nst_err_t  err;

    err = nst_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    nst_log_abort(err, nst_lock_fd_n " failed");
}


static nst_inline void
nst_shmtx_unlock(nst_shmtx_t *mtx)
{
    nst_err_t  err;

    err = nst_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    nst_log_abort(err, nst_unlock_fd_n " failed");
}


void nst_shmtx_destory(nst_shmtx_t *mtx);

#endif


#endif /* _NST_SHMTX_H_INCLUDED_ */
