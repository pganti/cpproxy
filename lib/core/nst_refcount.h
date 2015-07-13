#ifndef __NST_REFCOUNT_H__
#define __NST_REFCOUNT_H__
#include <nst_atomic.h>
#include <nst_types.h>
#include <nst_assert.h>

/* -start- non-atomic refcount. for single process architect */
typedef struct nst_refc_ctx_s refc_ctx_t;
struct nst_refc_ctx_s
{
    nst_uint_t counter;
    void (*destructor)(void *refc_obj);
};

#define NST_REFC_CTX_DEF refc_ctx_t _refc_ctx;

#define NST_REFC_INIT(obj, dstr)                                \
    do {                                                        \
        (obj)->_refc_ctx.counter = 1;                           \
        (obj)->_refc_ctx.destructor = dstr;                     \
    } while(0)

#define NST_REFC_VALUE(obj) ((obj)->_refc_ctx.counter)

#define NST_REFC_GET(obj)                                       \
    do {                                                        \
        nst_assert((obj)->_refc_ctx.counter > 0);               \
        (obj)->_refc_ctx.counter++;                             \
    } while(0)

#define NST_REFC_PUT(obj)                                       \
    do {                                                        \
        if(!obj)                                                \
            break;                                              \
        nst_assert((obj)->_refc_ctx.counter > 0);               \
        if(--((obj)->_refc_ctx.counter) == 0)                   \
            if ((obj)->_refc_ctx.destructor)                    \
                (obj)->_refc_ctx.destructor(obj);               \
    } while(0)

#define NST_REFC_GENHASH_COPY_FUNC_NAME(struct_name)             \
    _nst_refc_genhash_copy_##struct_name

#define NST_REFC_GENHASH_COPY_FUNC_DCL(struct_name)              \
void *_nst_refc_genhash_copy_##struct_name(void *obj);

#define NST_REFC_GENHASH_COPY_FUNC_DEF(struct_name)                 \
void *_nst_refc_genhash_copy_##struct_name(void *obj)               \
{                                                                   \
    struct struct_name *casted_obj = (struct struct_name *)(obj);   \
    NST_REFC_GET(casted_obj);                                       \
    return obj;                                                     \
}

void *refc_genhash_copy(void *obj);
/* -end- non-atomic refcount. for single process architect */


/* -start- atomic refcount. for multi process/threads architect */
static inline void
nst_refcount_init(volatile nst_atomic_t * count, u_int value)
{
    *count = value;
}

static inline void
nst_refcount_acquire(volatile nst_atomic_t * count)
{
    nst_atomic_fetch_add (count, 1);
}

static __inline int
nst_refcount_release(volatile nst_atomic_t * count)
{
    /* XXX: Should this have a rel membar? */
    return (nst_atomic_fetch_add (count, -1) == 1);
}
/* -end- atomic refcount. for multi process/threads architect */

#endif /*__NST_REFCOUNT_H__*/
