#include "nst_mem_stat_allocator.h"

#include <nst_types.h>

#include <malloc.h>
#include <assert.h>
#include <string.h>

#define MAX_MEM_STAT_COUNTER 1024
#define MAX_MEM_STAT_NAME_BUF_SIZE 32

typedef nst_uint_t nst_mem_stat_index_t;
typedef struct nst_mem_stat_s nst_mem_stat_t;
typedef struct nst_mem_stat_info_s nst_mem_stat_info_t;

static void *nst_mem_stat_malloc(void *data, size_t size);
static void *nst_mem_stat_calloc(void *data, size_t nmemb, size_t size);
static void *nst_mem_stat_realloc(void *data, void *ptr, size_t size);
static void nst_mem_stat_free(void *data, void *ptr);

struct nst_mem_stat_s
{
    char name[MAX_MEM_STAT_NAME_BUF_SIZE];
    size_t nobjs;
    size_t nbytes;
};

struct nst_mem_stat_info_s
{
    nst_mem_stat_index_t index; /* 64 bits */
    nst_uint_t size;            /* 64 bits */
    /* It should align automatically */
};

static nst_mem_stat_t stats[MAX_MEM_STAT_COUNTER];
static nst_mem_stat_index_t next_counter = 0;

nst_allocator_t
nst_mem_stat_register(const char *name)
{
    nst_mem_stat_t *stat;
    nst_allocator_t new_nst_mem_stat_allocator;

    assert(next_counter < MAX_MEM_STAT_COUNTER);

    new_nst_mem_stat_allocator.data = (void *)next_counter;
    new_nst_mem_stat_allocator.malloc = nst_mem_stat_malloc;
    new_nst_mem_stat_allocator.calloc = nst_mem_stat_calloc;
    new_nst_mem_stat_allocator.realloc = nst_mem_stat_realloc;
    new_nst_mem_stat_allocator.free = nst_mem_stat_free;

    stat = &stats[next_counter];
    memset(stat, 0, sizeof(nst_mem_stat_t));
    strncpy(stat->name,
            name,
            MAX_MEM_STAT_NAME_BUF_SIZE);
    /* just in case */
    stat->name[MAX_MEM_STAT_NAME_BUF_SIZE - 1] = '\0';

    next_counter++;

    return new_nst_mem_stat_allocator;
}

static inline void free_book_keeping(nst_mem_stat_info_t *stat_info,
                                     nst_mem_stat_index_t index)
{
    assert(stat_info->index == index);
    assert(stats[index].nbytes >= stat_info->size);
    assert(stats[index].nobjs > 0);

    stats[index].nbytes -= stat_info->size;
    (stats[index].nobjs)--;

    return;
}

static inline void malloc_book_keeping(nst_mem_stat_info_t *stat_info,
                                       nst_mem_stat_index_t index,
                                       size_t size)
{
    stat_info->index = index;
    stat_info->size = size;

    stats[index].nbytes += stat_info->size;
    (stats[index].nobjs)++;
}

void *nst_mem_stat_realloc(void *data, void *ptr, size_t size)
{
    void *new_ptr;
    nst_mem_stat_info_t *stat_info;
    nst_mem_stat_index_t index = (nst_mem_stat_index_t)data;

    if(size == 0) {
        nst_mem_stat_free(data, ptr);
        return NULL;
    }

    if(ptr) {
        stat_info = (nst_mem_stat_info_t*)((char*)ptr - sizeof(nst_mem_stat_info_t));
        free_book_keeping(stat_info, index);
        new_ptr = realloc(stat_info, size + sizeof(nst_mem_stat_info_t));
    } else {
        new_ptr = malloc(size + sizeof(nst_mem_stat_info_t));
    }

    /* TODO: change to CRITICAL log instead of assert */
    assert(new_ptr);

    malloc_book_keeping((nst_mem_stat_info_t*)new_ptr, index, size);

    return (char*)new_ptr + sizeof(nst_mem_stat_info_t);
}

void *nst_mem_stat_malloc(void *data, size_t size)
{
    nst_mem_stat_index_t index = (nst_mem_stat_index_t)data;
    assert(index < next_counter);

    if(size)
        return nst_mem_stat_realloc(data, NULL, size);
    else
        return NULL;
}

void *nst_mem_stat_calloc(void *data, size_t nmemb, size_t size)
{
    void *new_ptr;

    new_ptr = nst_mem_stat_malloc(data, nmemb * size);
    if(new_ptr)
        memset(new_ptr, 0, nmemb * size);

    return new_ptr;
}

void nst_mem_stat_free(void *data, void *ptr)
{
    nst_mem_stat_index_t index;
    nst_mem_stat_info_t *stat_info;

    if(!ptr)
        /* free(NULL) is allowed */
        return;

    index = (nst_mem_stat_index_t)data;
    stat_info = (nst_mem_stat_info_t*)((char*)ptr - sizeof(nst_mem_stat_info_t));

    free_book_keeping(stat_info, index);
    free(stat_info);
}

size_t
nst_mem_stat_get_allocated_nbytes(void *data)
{
    nst_mem_stat_index_t index;

    index = (nst_mem_stat_index_t)data;
    assert(index < next_counter);

    return stats[index].nbytes;
}

size_t
nst_mem_stat_get_allocated_nobjs(void *data)
{
    nst_mem_stat_index_t index;

    index = (nst_mem_stat_index_t)data;
    assert(index < next_counter);

    return stats[index].nobjs;
}
