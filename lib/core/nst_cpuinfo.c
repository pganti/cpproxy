#include "nst_cpuinfo.h"
#include "nst_alloc.h"

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#if (( __i386__ || __amd64__ ) && ( __GNUC__ || __INTEL_COTPILER ))


static inline void nst_cpuid(uint32_t i, uint32_t *buf);


#if ( __i386__ )
static inline void
nst_cpuid(uint32_t i, uint32_t *buf)
{

    /*
     * we could not use %ebx as output parameter if gcc builds PIC,
     * and we could not save %ebx on stack, because %esp is used,
     * when the -fomit-frame-pointer optimization is specified.
     */

    __asm__ (

    "    mov    %%ebx, %%esi;  "

    "    cpuid;                "
    "    mov    %%eax, (%1);   "
    "    mov    %%ebx, 4(%1);  "
    "    mov    %%edx, 8(%1);  "
    "    mov    %%ecx, 12(%1); "

    "    mov    %%esi, %%ebx;  "

    : : "a" (i), "D" (buf) : "ecx", "edx", "esi", "memory" );
}


#else /* __amd64__ */

static inline void
nst_cpuid(uint32_t i, uint32_t *buf)
{
    uint32_t  eax, ebx, ecx, edx;

    __asm__ (

        "cpuid"

    : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (i) );

    buf[0] = eax;
    buf[1] = ebx;
    buf[2] = edx;
    buf[3] = ecx;
}


#endif


/* auto detect the L2 cache line size of modern and widespread CPUs */

void
nst_cpuinfo(void)
{
    u_char    *vendor;
    uint32_t   vbuf[5], cpu[4];

    vbuf[0] = 0;
    vbuf[1] = 0;
    vbuf[2] = 0;
    vbuf[3] = 0;
    vbuf[4] = 0;

    nst_cpuid(0, vbuf);

    vendor = (u_char *) &vbuf[1];

    if (vbuf[0] == 0) {
        return;
    }

    nst_cpuid(1, cpu);

    if (strcmp((const char *)vendor, "GenuineIntel") == 0) {

        switch ((cpu[0] & 0xf00) >> 8) {

        /* Pentium */
        case 5:
            nst_cacheline_size = 32;
            break;

        /* Pentium Pro, II, III */
        case 6:
            nst_cacheline_size = 32;

            if ((cpu[0] & 0xf0) >= 0xd0) {
                /* Intel Core */
                nst_cacheline_size = 64;
            }

            break;

        /*
         * Pentium 4, although its cache line size is 64 bytes,
         * it prefetches up to two cache lines during memory read
         */
        case 15:
            nst_cacheline_size = 128;
            break;
        }

    } else if (strcmp((const char *)vendor, "AuthenticAMD") == 0) {
        nst_cacheline_size = 64;
    }
}

#else


void
nst_cpuinfo(void)
{
}


#endif