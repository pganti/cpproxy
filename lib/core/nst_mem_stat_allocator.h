#ifndef _NST_MEM_STAT_ALLOCATOR_H
#define _NST_MEM_STAT_ALLOCATOR_H

#include "nst_allocator.h"

nst_allocator_t nst_mem_stat_register(const char *name);

size_t
nst_mem_stat_get_allocated_nbytes(void *data);

size_t
nst_mem_stat_get_allocated_nobjs(void *data);

#endif
