#include "nst_config.h"

#include "nst_gen_func.h"

#ifndef _NST_VECTOR_H_
#define _NST_VECTOR_H_

#include <unistd.h>

struct nst_allocator_s;

typedef struct nst_vector_s nst_vector_t;
typedef int (*nst_vector_for_each_till_f)(void *elt, void *data);
typedef void *(*nst_vector_elt_copy_f)(void *);

struct nst_vector_s
{
    void *elts;
    size_t nelts;
    size_t size;
    size_t nalloc;
    struct nst_allocator_s *allocator;
    nst_gen_destructor_f elt_free;
};

struct nst_vector_s *nst_vector_new(struct nst_allocator_s *nst_allocator,
                                    nst_gen_destructor_f elt_free,
                                    size_t n,
                                    size_t size);
void nst_vector_free(struct nst_vector_s *vec);
void *nst_vector_push(struct nst_vector_s *vec);
void nst_vector_pop(struct nst_vector_s *vec);
int nst_vector_append(struct nst_vector_s *vec, void *data, size_t n);
void nst_vector_set_elt_at(struct nst_vector_s *vec, void *data, size_t index);
void *nst_vector_get_elt_at(const struct nst_vector_s *vec, size_t index);
size_t nst_vector_get_nelts(const struct nst_vector_s *vec);
size_t nst_vector_get_size(const struct nst_vector_s *vec);
int nst_vector_for_each_till(nst_vector_t *vec,
                             nst_vector_for_each_till_f actor,
                             void *actor_data);

#endif
