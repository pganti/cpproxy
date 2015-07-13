
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_ALLOC_H_INCLUDED_
#define _NST_ALLOC_H_INCLUDED_

#include "nst_types.h"

struct nst_log_s;

void *nst_alloc(size_t size, struct nst_log_s *log);
void *nst_calloc(size_t size, struct nst_log_s *log);

void * nst_xmalloc(size_t size);
void * nst_xcalloc(size_t size);
void nst_xfree (void * p);

#define nst_free  nst_xfree


/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD has not memalign() or posix_memalign() but its malloc() alignes
 * allocations bigger than page size at the page boundary.
 */

#if (NST_HAVE_POSIX_MEMALIGN || NST_HAVE_MEMALIGN)

void *nst_memalign(size_t alignment, size_t size, struct nst_log_s *log);

#else

#define nst_memalign(alignment, size, log)  nst_alloc(size, log)

#endif


extern nst_uint_t  nst_pagesize;
extern nst_uint_t  nst_pagesize_shift;
extern nst_uint_t  nst_cacheline_size;


#endif /* _NST_ALLOC_H_INCLUDED_ */
