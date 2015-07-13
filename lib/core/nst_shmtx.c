
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


#if (NST_HAVE_ATOMIC_OPS)


nst_int_t
nst_shmtx_create(nst_shmtx_t *mtx, void *addr, u_char *name)
{
    mtx->lock = addr;

    return NST_OK;
}

#else


nst_int_t
nst_shmtx_create(nst_shmtx_t *mtx, void *addr, u_char *name)
{
    if (mtx->name) {

        if (nst_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NST_OK;
        }

        nst_shmtx_destory(mtx);
    }

    mtx->fd = nst_open_file(name, NST_FILE_RDWR, NST_FILE_CREATE_OR_OPEN,
                            NST_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NST_INVALID_FILE) {
        nst_log_error(NST_LOG_EMERG, nst_cycle->log, nst_errno,
                      nst_open_file_n " \"%s\" failed", name);
        return NST_ERROR;
    }

    if (nst_delete_file(name) == NST_FILE_ERROR) {
        nst_log_error(NST_LOG_ALERT, nst_cycle->log, nst_errno,
                      nst_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NST_OK;
}


void
nst_shmtx_destory(nst_shmtx_t *mtx)
{
    if (nst_close_file(mtx->fd) == NST_FILE_ERROR) {
        nst_log_error(NST_LOG_ALERT, nst_cycle->log, nst_errno,
                      nst_close_file_n " \"%s\" failed", mtx->name);
    }
}


#endif
