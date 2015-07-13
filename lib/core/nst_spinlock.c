
/*
 * Copyright (C) Igor Sysoev
 */


#include <nst_core.h>


extern nst_int_t nst_ncpu;

void
nst_spinlock(nst_atomic_t *lock, nst_atomic_int_t value, nst_uint_t spin)
{

#if (NST_HAVE_ATOMIC_OPS)

    nst_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && nst_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        if (nst_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    nst_cpu_pause();
                }

                if (*lock == 0 && nst_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }
    }

#else

#if (NST_THREADS)

#error nst_spinlock() or nst_atomic_cmp_set() are not defined !

#endif

#endif

}
