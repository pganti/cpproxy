#ifndef _NST_ALLOCATOR_H
#define _NST_ALLOCATOR_H

#include <unistd.h>

typedef struct nst_allocator_s nst_allocator_t;

typedef void* (*malloc_f)(void *, size_t);
typedef void* (*calloc_f)(void *, size_t, size_t);
typedef void* (*realloc_f)(void *, void *, size_t);
typedef void (*free_f)(void *, void *);

extern nst_allocator_t nst_allocator_sys;

struct nst_allocator_s
{
    void *data;
    malloc_f malloc;
    calloc_f calloc;
    realloc_f realloc;
    free_f free;
};

#define nst_allocator_malloc(allocator, size) \
    ((allocator)->malloc((allocator)->data, (size)))

#define nst_allocator_calloc(allocator, nmemb, size)         \
    ((allocator)->calloc((allocator)->data, (nmemb), (size)))

#define nst_allocator_realloc(allocator, ptr, size)  \
    ((allocator)->realloc((allocator)->data, (ptr), (size)))

#define nst_allocator_free(allocator, ptr)  \
    ((allocator)->free((allocator)->data, (ptr)));

#endif
