#ifndef _NST_CRC32_H_INCLUDED_
#define _NST_CRC32_H_INCLUDED_


#include "nst_config.h"
#include "nst_types.h"

#include <stdint.h>
#include <sys/types.h>

extern uint32_t  *nst_crc32_table_short;
extern uint32_t   nst_crc32_table256[];


static nst_inline uint32_t
nst_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = nst_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = nst_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static nst_inline uint32_t
nst_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = nst_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#define nst_crc32_init(crc)                                                   \
    crc = 0xffffffff


static nst_inline void
nst_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = nst_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define nst_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


nst_int_t nst_crc32_table_init(void);
void nst_crc32_table_reset(void);


#endif /* _NST_CRC32_H_INCLUDED_ */
