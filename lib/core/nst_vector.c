#include "nst_vector.h"

#include "nst_allocator.h"
#include "nst_assert.h"
#include "nst_types.h"

#include <string.h>

nst_vector_t *
nst_vector_new(nst_allocator_t *allocator,
               nst_gen_destructor_f elt_free,
               size_t n,
               size_t size)
{
    nst_vector_t *vec;

    vec = (nst_vector_t*)nst_allocator_malloc(allocator,sizeof(nst_vector_t));
    if (vec == NULL) {
        return NULL;
    }

    vec->elts = nst_allocator_malloc(allocator, n * size);
    if(vec->elts == NULL) {
        nst_allocator_free(allocator, vec);
        return NULL;
    }

    vec->nelts = 0;
    vec->size = size;
    vec->nalloc = n;
    vec->allocator = allocator;
    vec->elt_free = elt_free;

    return vec;
}

void
nst_vector_free(nst_vector_t *vec)
{
    if(!vec)
        return;

    if(vec->elt_free) {
        size_t i;
        void *elts = vec->elts;
        for(i = 0; i < vec->nelts; i++)
            vec->elt_free( (void *)((unsigned char *)elts + (i * (vec->size)) ) );
    }

    nst_allocator_free(vec->allocator, vec->elts);
    nst_allocator_free(vec->allocator, vec);
}

static inline int
nst_vector_expand_if_needed(nst_vector_t *vec, size_t n)
{
    if((vec->nelts + n) >= vec->nalloc) {
        /* we expand by 1.5x */
        size_t new_nalloc = (vec->nalloc * 3) / 2;
        void *new_elts;

        new_nalloc = max(new_nalloc, (vec->nalloc + n));

        new_elts = nst_allocator_realloc(vec->allocator,
                                         vec->elts,
                                         new_nalloc* (vec->size));
        if(new_elts) {
            vec->elts = new_elts;
            vec->nalloc = new_nalloc;
            return 0;
        } else {
            return -1;
        }
    } else {
        return 0;
    }
}

void *
nst_vector_push(nst_vector_t *vec)
{
    void        *elt;

    if(nst_vector_expand_if_needed(vec, 1))
        return NULL;

    nst_assert(vec->nelts < vec->nalloc);

    elt = (unsigned char *)vec->elts + (vec->nelts * vec->size);
    vec->nelts++;

    return elt;
}

void
nst_vector_pop(nst_vector_t *vec)
{
    nst_assert(vec->nelts > 0);

    vec->nelts--;
}

int
nst_vector_append(struct nst_vector_s *vec, void *data, size_t n)
{
    void *elt;

    if(nst_vector_expand_if_needed(vec, n))
        return -1;

    nst_assert(vec->nelts < vec->nalloc);

    elt = (unsigned char *)vec->elts + (vec->nelts * vec->size);
    memcpy(elt, data, n * vec->size);
    vec->nelts++;

    return 0;
}

void
nst_vector_set_elt_at(struct nst_vector_s *vec, void *data, size_t index)
{
    void *elt;

    nst_assert(index < vec->nelts);

    elt = (unsigned char *)vec->elts + (index * vec->size);
    memcpy(elt, data, vec->size);
}


void *
nst_vector_get_elt_at(const nst_vector_t *vec, size_t index)
{
    nst_assert(index < vec->nelts);

    return (unsigned char *)vec->elts + (index * vec->size);
}

size_t
nst_vector_get_nelts(const nst_vector_t *vec)
{
    return vec->nelts;
}

int
nst_vector_for_each_till(nst_vector_t *vec,
                         nst_vector_for_each_till_f actor,
                         void *actor_data)
{
    size_t i;
    void *elts = vec->elts;
    for(i = 0; i < vec->nelts; i++) {
        if(actor(elts, actor_data))
            return 1;

        elts = (unsigned char *)elts + vec->size;
    }

    return 0;
}
