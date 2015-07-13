#ifndef _NST_BJHASH_H_
#define _NST_BJHASH_H_

#include <nst_config.h>

#include <stdint.h>

#ifdef NST_HAVE_LITTLE_ENDIAN
#define nst_bjhash_bytes  nst_bjhash_little
#else
#define nst_bjhash_bytes  nst_bjhash_big
#endif

uint32_t nst_bjhash_little(const void *key, size_t length, uint32_t initval);
uint32_t nst_bjhash_big(const void *key, size_t length, uint32_t initval);
uint32_t nst_bjhash_uint32s(const uint32_t *k, size_t length, uint32_t initval);

#endif
