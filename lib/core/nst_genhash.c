#include "nst_genhash.h"

#include <nst_bjhash.h>

#include <nst_allocator.h>
#include <nst_errno.h>
#include <nst_assert.h>
#include <nst_string.h>

#include <string.h>

#define NST_GENHASH_MIN_SIZE (64)
#define NST_GENHASH_MAX_SIZE (2048 * 1024) /* 2048 K maximum */

#define NST_GENHASH_DF_MIN_FILL_FACTOR   5
#define NST_GENHASH_DF_MAX_FILL_FACTOR  70

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

typedef struct nst_genhash_entry_s nst_genhash_entry_t;

struct nst_genhash_entry_s
{
    nst_genhash_key_t    cached_key_hash;
    void *key;                           /**< key of stored element */
    void *value;                         /**< stored element (content) */
    nst_genhash_entry_t *next;           /**< next entry in link-list*/
    nst_genhash_entry_t *prev;           /**< previous entry in link-list*/
    nst_genhash_entry_t *prev_bucket;    /**< previous record in bucket */
    nst_genhash_entry_t *next_bucket;    /**< next record in bucket */
};

struct nst_genhash_s
{
    nst_genhash_entry_t **table;    /**< table of entries in the hash-table */
    nst_genhash_entry_t *head;      /**< first item in the link-list */
    nst_genhash_entry_t *tail;      /**< last item in the link-list */
    uint32_t nbits;                 /**< size of the hash-table */
    uint32_t items;                 /**< number of items in the collection */

    nst_genhash_f  hash_fn;         /**< pointer to hash function */
    nst_compare_f  compare_fn;      /**< pointer to compare function */
	nst_destructor_f free_key;
	nst_destructor_f free_value;
    nst_genhash_kv_copy_f key_copy_fn;
    nst_genhash_kv_copy_f value_copy_fn;

    uint32_t mode;                  /**< operation mode */

	uint32_t min_size;
	int fill_factor_min;		  /**< minimal fill factor in percent */
	int fill_factor_max;		  /**< maximal fill factor in percent */

    struct nst_allocator_s *allocator;
};

static inline nst_genhash_entry_t *
nst_genhash_entry_new(nst_genhash_t *ghash, void *key, void *value)
{
    nst_genhash_entry_t *entry =
		(nst_genhash_entry_t *) nst_allocator_calloc(ghash->allocator,
                                                     1,
                                                     sizeof(nst_genhash_entry_t));

	if (entry == NULL) {
		return NULL;
	}

    entry->key = key;
    entry->value = value;

    return entry;
}

static inline void
nst_genhash_entry_free(nst_genhash_t *ghash, nst_genhash_entry_t *entry)
{
    nst_allocator_free(ghash->allocator, entry);
}

static inline uint32_t
round_size_to_power_two(uint32_t size_hint)
{
    uint32_t nbits = 32;
    uint32_t highest_bit = 0x80000000;

    if(size_hint > 1)
        size_hint--;

    while(nbits) {
        if(size_hint & highest_bit) {
            break;
        } else {
            highest_bit >>= 1;
            nbits--;
        }
    }

    nst_assert(nbits);

    return nbits;
}

static void *
nst_genhash_resize(nst_genhash_t *ghash, bool shrink)
{
    nst_genhash_entry_t **old_table, **new_table;
    nst_genhash_entry_t *entry, **bucket;

    old_table = ghash->table;

    if(shrink) {
        if(ghash->nbits == 1
           || hashsize(ghash->nbits-1) < ghash->min_size) {
            return ghash;
        } else {
            ghash->nbits--;
        }
    } else {
        if(ghash->nbits == 32
           || hashsize(ghash->nbits+1) > NST_GENHASH_MAX_SIZE) {
            return ghash;
        } else {
            ghash->nbits++;
        }
    }

    new_table = ghash->table = (nst_genhash_entry_t **)
        nst_allocator_calloc(ghash->allocator,
                             hashsize(ghash->nbits),
                             sizeof(nst_genhash_entry_t *));

    if(!new_table) {
		errno = ENOMEM;
        return NULL;
    }

    /* We do not have LRU now...so every resize will screw up the
     * nst_genhash_promote_to_top() effort.
     */
    for(entry = ghash->tail; entry; entry = entry->prev) {
        uint32_t index;

        index = entry->cached_key_hash & hashmask(ghash->nbits);
        entry->prev_bucket = NULL;
        bucket = &new_table[index];
        if((entry->next_bucket = *bucket)) {
            (*bucket)->prev_bucket = entry;
        }
        *bucket = entry;
    }

    nst_allocator_free(ghash->allocator, old_table);

    return ghash;
}

static inline void
nst_genhash_promote_to_top(nst_genhash_entry_t **head_bucket,
                           nst_genhash_entry_t *entry)
{
    if(!entry->prev_bucket)
        /* Alrite!!! I am at the top of the mountain. What else can I do? */
        return;

    /* At this point, we know there is a prev_bucket */

    /* Fix the next_bucket pointer of the previous bucket */
    if((entry->prev_bucket->next_bucket = entry->next_bucket)) {
        /* If I have a next bucket, fix up its prev_bucket pointer */
        entry->next_bucket->prev_bucket = entry->prev_bucket;
    }

    /* Now, I am out of the list.  Time to conquer the head_bucket! */
    if((entry->next_bucket = *head_bucket))
        /* Actually, this check is not necessary since I just check
         * that I am not at the head, so someone else must be at the head.
         */
        (*head_bucket)->prev_bucket = entry;
    *head_bucket = entry;
    entry->prev_bucket = NULL;
}

static inline nst_genhash_entry_t *
nst_genhash_add_internal(nst_genhash_t *ghash,
                         nst_genhash_entry_t *entry)
{
    nst_genhash_entry_t **head_bucket;
    uint32_t index;

    if(!(ghash->mode & NST_GENHASH_MODE_NO_EXPAND)
       &&
       (ghash->items * 100) > (hashsize(ghash->nbits) * ghash->fill_factor_max))
        nst_genhash_resize(ghash, FALSE);

    entry->cached_key_hash = (*ghash->hash_fn)(entry->key);
    index = entry->cached_key_hash & hashmask(ghash->nbits);
    head_bucket = &(ghash->table[index]);

    /* put the newly created element to the beginning of the bucket */
    if((entry->next_bucket = *head_bucket))
        (*head_bucket)->prev_bucket = entry;
    *head_bucket = entry;
    entry->prev_bucket = NULL;

    ghash->items++;

    return entry;
}

static inline nst_genhash_entry_t *
nst_genhash_del_internal(nst_genhash_t *ghash, const void *key)
{
    nst_genhash_entry_t *removing;
    uint32_t index;

    if(!(ghash->mode & NST_GENHASH_MODE_NO_SHRINK)
       &&
       (ghash->items * 100) < (hashsize(ghash->nbits) * ghash->fill_factor_min))
        nst_genhash_resize(ghash, TRUE);

    index = ((*ghash->hash_fn)(key)) & hashmask(ghash->nbits);
    for (removing = ghash->table[index];
         removing;
         removing = removing->next_bucket) {
        if ((*ghash->compare_fn)(removing->key, key) == 0)
            break;
    }

    if(!removing)
        return NULL;

	if (removing->prev_bucket) {
        /* fix up the prev_bucket */
		if((removing->prev_bucket->next_bucket = removing->next_bucket)) {
            /* fix up the next_bucket */
			removing->next_bucket->prev_bucket = removing->prev_bucket;
        }
	} else {
        /* put the next_bucket to the head */
		if((ghash->table[index] = removing->next_bucket))
			removing->next_bucket->prev_bucket = NULL;
	}

    ghash->items--;

    return removing;
}

static inline void
nst_genhash_link_internal(nst_genhash_t *ghash,
                          nst_genhash_entry_t *adding)
{
    /* adding->next and adding->prev must be NULL at this point */

    if (ghash->head) {
        adding->next = ghash->head;
        ghash->head->prev = adding;
        ghash->head = adding;
    }
    else {
        ghash->head = ghash->tail = adding;
    }
}

static inline void
nst_genhash_unlink_internal(nst_genhash_t *ghash,
                            nst_genhash_entry_t *removing)
{
    if (removing->next)
        removing->next->prev = removing->prev;
    else
        ghash->tail = removing->prev;

    if (removing->prev)
        removing->prev->next = removing->next;
    else
        ghash->head = removing->next;

	return;
}

nst_genhash_t*
nst_genhash_new(uint32_t mode,
                uint32_t min_size,
                uint32_t fill_factor_min,
                uint32_t fill_factor_max,
                nst_allocator_t *allocator,
                nst_genhash_f hash_fn,
                nst_compare_f compare_fn,
                nst_destructor_f free_key,
                nst_destructor_f free_value,
                nst_genhash_kv_copy_f key_copy_fn,
                nst_genhash_kv_copy_f value_copy_fn)
{
    nst_genhash_t *ghash;

    if(!hash_fn || !compare_fn || !allocator) {
        errno = EINVAL;
        return NULL;
    }

    if(key_copy_fn && !free_key) {
        errno = EINVAL;
        return NULL;
    }

    if(value_copy_fn && !free_value) {
        errno = EINVAL;
        return NULL;
    }

    if((fill_factor_min ? 1 : 0) != (fill_factor_max ? 1 : 0)) {
        /* You can either specify none or specify both but not either one */
        errno = EINVAL;
        return NULL;
    } else if(fill_factor_max) {
        /* both have been specified */
        if(fill_factor_min >= fill_factor_max
           || fill_factor_max > 100) {
            errno = EINVAL;
            return NULL;
        }
    }

    ghash = (nst_genhash_t *) nst_allocator_calloc(allocator,
                                                   1,
                                                   sizeof(nst_genhash_t));
    if(ghash == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    ghash->allocator = allocator;
    if(min_size == 0)
        min_size = NST_GENHASH_MIN_SIZE;
    else if(min_size > NST_GENHASH_MAX_SIZE)
        min_size = NST_GENHASH_MAX_SIZE;

    ghash->nbits = round_size_to_power_two(min_size);
    ghash->items = 0;
    ghash->table = (nst_genhash_entry_t **)
        nst_allocator_calloc(allocator,
                             hashsize(ghash->nbits),
                             sizeof(nst_genhash_entry_t *));
    if (ghash->table == NULL) {
        nst_allocator_free(allocator, ghash);
		errno = ENOMEM;
        return NULL;
    }

    ghash->hash_fn = hash_fn;
    ghash->compare_fn = compare_fn;
	ghash->free_key = free_key;
	ghash->free_value = free_value;
    ghash->key_copy_fn = key_copy_fn;
    ghash->value_copy_fn = value_copy_fn;

    ghash->head = ghash->tail = NULL;

    ghash->mode = mode;

	ghash->min_size = hashsize(ghash->nbits);
    if(fill_factor_min)
        ghash->fill_factor_min = fill_factor_min;
    else
        ghash->fill_factor_min = NST_GENHASH_DF_MIN_FILL_FACTOR;

    if(fill_factor_max)
        ghash->fill_factor_max = fill_factor_max;
    else
        ghash->fill_factor_max = NST_GENHASH_DF_MAX_FILL_FACTOR;

    return ghash;
}

void
nst_genhash_free(nst_genhash_t *ghash)
{
    if(!ghash)
        return;

	while (ghash->head != NULL) {
        nst_genhash_entry_t *entry = ghash->head;
		ghash->head = entry->next;
        if (ghash->free_key)
            (*ghash->free_key)(entry->key);
        if (ghash->free_value)
            (*ghash->free_value)(entry->value);
		nst_genhash_entry_free(ghash, entry);
	}

    nst_allocator_free(ghash->allocator, ghash->table);
    nst_allocator_free(ghash->allocator, ghash);
}

void
nst_genhash_flush(nst_genhash_t *ghash)
{
    if(!ghash)
        return;

	while (ghash->head != NULL) {
        nst_genhash_entry_t *entry = ghash->head;
		ghash->head = entry->next;
        if (ghash->free_key)
            (*ghash->free_key)(entry->key);
        if (ghash->free_value)
            (*ghash->free_value)(entry->value);
		nst_genhash_entry_free(ghash, entry);
	}

    ghash->items = 0;
    ghash->head = ghash->tail = NULL;
    nst_memzero(ghash->table,
                hashsize(ghash->nbits) * sizeof(nst_genhash_entry_t *));

    if(!(ghash->mode & NST_GENHASH_MODE_NO_SHRINK))
        nst_genhash_resize(ghash, TRUE);
}

nst_status_e
nst_genhash_add(nst_genhash_t *ghash, void *key, void *value)
{
    nst_genhash_entry_t *adding;
    void *new_key = NULL;

	if ((ghash->mode & NST_GENHASH_MODE_MULT_VALUES) == 0
		&& nst_genhash_find(ghash, key)) {
		errno = EEXIST;
        return NST_ERROR;
    }

    if(ghash->key_copy_fn)
        if(!(new_key = key = ghash->key_copy_fn(key)))
            return NST_ERROR;

    if(ghash->value_copy_fn) {
        if(!(value = ghash->value_copy_fn(value))) {
            if(new_key && ghash->free_key) {
                /* free the newly created key */
                ghash->free_key(new_key);
            }
            return NST_ERROR;
        }
    }

    if((adding = nst_genhash_entry_new(ghash, key, value)) == NULL) {
        return NST_ERROR;
	}

    nst_genhash_add_internal(ghash, adding);
    nst_genhash_link_internal(ghash, adding);

    return NST_OK;
}

nst_status_e
nst_genhash_del(nst_genhash_t *ghash, const void *key)
{
    nst_genhash_entry_t *removing;

    if((removing = nst_genhash_del_internal(ghash, key))) {
        nst_genhash_unlink_internal(ghash, removing);
        if(ghash->free_key)
            (*ghash->free_key)(removing->key);

        if(ghash->free_value)
            (*ghash->free_value)(removing->value);

        nst_allocator_free(ghash->allocator, removing);
    }

    if(removing)
        return NST_OK;
    else
        return NST_ERROR;
}

void *nst_genhash_find(nst_genhash_t *ghash, const void *key)
{
    uint32_t index;
    nst_genhash_entry_t *entry;

    index = ((*ghash->hash_fn)(key)) & hashmask(ghash->nbits);
    entry = ghash->table[index];
    while (entry && (*ghash->compare_fn)(entry->key, key))
		entry = entry->next_bucket;

    if(entry) {
        if(ghash->mode & NST_GENHASH_MODE_PROMOTE_TO_TOP) {
            nst_genhash_promote_to_top(&ghash->table[index], entry);
        }
        return entry->value;
    } else {
        return NULL;
    }
}

uint32_t
nst_genhash_get_nelts(const nst_genhash_t *ghash)
{
    return ghash->items;
}

void
nst_genhash_iter_init(const nst_genhash_t *ghash,
                      nst_genhash_iter_t *iterator)
{
    iterator->pos = ghash->head;
}

bool
nst_genhash_iter_next(nst_genhash_iter_t *iterator,
                      void **key, void **value)
{
    nst_genhash_entry_t *entry = NULL;

    if (iterator->pos) {
        entry = (nst_genhash_entry_t *)iterator->pos;
        iterator->pos = entry->next;
        if(key) (*key) = entry->key;
        if(value) (*value) = entry->value;
        return TRUE;
    }
    else {
        return FALSE;
    }
}

uint32_t
nst_genhash_uint32(const void *k)
{
    return nst_bjhash_uint32s(k, 1, 0);
}

int
nst_genhash_uint32_cmp(const void *k1, const void *k2)
{
    return (*(const uint32_t *)k1 != *(const uint32_t *)k2);
}

uint32_t
nst_genhash_void(const void *k)
{
    return nst_bjhash_uint32s((const void *)&k, sizeof(void *)/sizeof(uint32_t), 0);
}

int
nst_genhash_void_cmp(const void *k1, const void *k2)
{
    return (k1 != k2);
}

uint32_t
nst_genhash_cstr(const void *key)
{
    const char *cstr = (const char *)key;
    size_t cstrlen = strlen(cstr);

    return nst_bjhash_bytes(key, cstrlen, 0);
}

int
nst_genhash_cstr_cmp(const void *k1, const void *k2)
{
    const char *cstr1 = (const char *)k1;
    const char *cstr2 = (const char *)k2;

    return strcmp(cstr1, cstr2);
}
