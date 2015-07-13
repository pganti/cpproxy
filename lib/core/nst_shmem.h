
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_SHMEM_H_INCLUDED_
#define _NST_SHMEM_H_INCLUDED_


#include <nst_core.h>


typedef struct {
    u_char      *addr;
    size_t       size;
    nst_log_t   *log;
} nst_shm_t;


nst_int_t nst_shm_alloc(nst_shm_t *shm);
void nst_shm_free(nst_shm_t *shm);


#endif /* _NST_SHMEM_H_INCLUDED_ */
