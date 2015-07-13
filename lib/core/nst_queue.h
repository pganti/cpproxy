#ifndef _NST_QUEUE_H_INCLUDED_
#define _NST_QUEUE_H_INCLUDED_

#include <nst_config.h>

typedef struct nst_queue_s  nst_queue_t;

struct nst_queue_s {
    nst_queue_t  *prev;
    nst_queue_t  *next;
};


#define nst_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define nst_queue_empty(h)                                                    \
    (h == (h)->prev)


#define nst_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define nst_queue_head(h)                                                     \
    (h)->next


#define nst_queue_last(h)                                                     \
    (h)->prev


#if (NST_DEBUG)

#define nst_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define nst_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define nst_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


#endif /* _NST_QUEUE_H_INCLUDED_ */
