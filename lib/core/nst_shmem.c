
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


#if (NST_HAVE_MAP_ANON)
nst_int_t
nst_shm_alloc(nst_shm_t *shm)
{
    shm->addr = (u_char *) mmap(NULL, shm->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);

    if (shm->addr == MAP_FAILED) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return NST_ERROR;
    }

    return NST_OK;
}


void
nst_shm_free(nst_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (NST_HAVE_MAP_DEVZERO)

nst_int_t
nst_shm_alloc(nst_shm_t *shm)
{
    nst_fd_t  fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "open(\"/dev/zero\") failed");
        return NST_ERROR;
    }

    shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
                                MAP_SHARED, fd, 0);

    if (shm->addr == MAP_FAILED) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "close(\"/dev/zero\") failed");
    }

    return (shm->addr == MAP_FAILED) ? NST_ERROR : NST_OK;
}


void
nst_shm_free(nst_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}
#elif (NST_HAVE_SYSVSHM)
#include <sys/ipc.h>
#include <sys/shm.h>


nst_int_t
nst_shm_alloc(nst_shm_t *shm)
{
    int  id;

    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "shmget(%uz) failed", shm->size);
        return NST_ERROR;
    }

    nst_log_debug1(NST_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    shm->addr = shmat(id, NULL, 0);

    if (shm->addr == (void *) -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno, "shmat() failed");
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? NST_ERROR : NST_OK;
}


void
nst_shm_free(nst_shm_t *shm)
{
    if (shmdt(shm->addr) == -1) {
        nst_log_error(NST_LOG_ALERT, shm->log, nst_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
