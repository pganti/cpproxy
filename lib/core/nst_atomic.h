
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_ATOMIC_H_INCLUDED_
#define _NST_ATOMIC_H_INCLUDED_


#include <nst_types.h>

#if ( __i386__ || __i386 )

typedef int32_t                     nst_atomic_int_t;
typedef uint32_t                    nst_atomic_uint_t;
typedef volatile nst_atomic_uint_t  nst_atomic_t;

#define NST_ATOMIC_T_LEN            sizeof("-2147483648") - 1

#define NST_HAVE_ATOMIC_OPS  1

#include "nst_gcc_atomic_x86.h"

#elif ( __amd64__ || __amd64 )

typedef int64_t                     nst_atomic_int_t;
typedef uint64_t                    nst_atomic_uint_t;
typedef volatile nst_atomic_uint_t  nst_atomic_t;

#define NST_ATOMIC_T_LEN            sizeof("-9223372036854775808") - 1

#define NST_HAVE_ATOMIC_OPS  1

#include "nst_gcc_atomic_amd64.h"

#endif /*i386 or amd */

#if !(NST_HAVE_ATOMIC_OPS)

#define NST_HAVE_ATOMIC_OPS  0

typedef int32_t                     nst_atomic_int_t;
typedef uint32_t                    nst_atomic_uint_t;
typedef volatile nst_atomic_uint_t  nst_atomic_t;
#define NST_ATOMIC_T_LEN            sizeof("-2147483648") - 1


static nst_inline nst_atomic_uint_t
nst_atomic_cmp_set(nst_atomic_t *lock, nst_atomic_uint_t old,
     nst_atomic_uint_t set)
{
     if (*lock == old) {
         *lock = set;
         return 1;
     }

     return 0;
}


static nst_inline nst_atomic_int_t
nst_atomic_fetch_add(nst_atomic_t *value, nst_atomic_int_t add)
{
     nst_atomic_int_t  old;

     old = *value;
     *value += add;

     return old;
}

#define nst_memory_barrier()
#define nst_cpu_pause()

#endif


void nst_spinlock(nst_atomic_t *lock, nst_atomic_int_t value, nst_uint_t spin);

#define nst_trylock(lock)  (*(lock) == 0 && nst_atomic_cmp_set(lock, 0, 1))
#define nst_unlock(lock)    *(lock) = 0


#endif /* _NST_ATOMIC_H_INCLUDED_ */
