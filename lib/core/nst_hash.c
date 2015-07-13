#include <nst_core.h>


void *
nst_hash_find(nst_hash_t *hash, nst_uint_t key,
              const u_char *name, size_t len)
{
    nst_uint_t       i;
    nst_hash_elt_t  *elt;

#if 0
    nst_str_t  line;

    line.len = len;
    line.data = name;
    nst_log_error(NST_LOG_ALERT, nst_cycle->log, 0, "hf:\"%V\"", &line);
#endif

    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
        if (len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < len; i++) {
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }

        return elt->value;

    next:

        elt = (nst_hash_elt_t *) nst_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return NULL;
}


void *
nst_hash_find_wc_head(nst_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    nst_uint_t   i, n, key;

#if 0
    nst_str_t  line;

    line.len = len;
    line.data = name;
    nst_log_error(NST_LOG_ALERT, nst_cycle->log, 0, "wch:\"%V\"", &line);
#endif

    n = len;

    while (n) {
        if (name[n - 1] == '.') {
            break;
        }

        n--;
    }

    key = 0;

    for (i = n; i < len; i++) {
        key = nst_hash(key, name[i]);
    }

#if 0
    nst_log_error(NST_LOG_ALERT, nst_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = nst_hash_find(&hwc->hash, key, &name[n], len - n);

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer,
         *     01 - value is pointer to wildcard hash allowing
         *          "*.example.com" only,
         *     11 - value is pointer to wildcard hash allowing
         *          both "example.com" and "*.example.com".
         */

        if ((uintptr_t) value & 1) {

            hwc = (nst_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            if (n == 0) {
                if ((uintptr_t) value & 2) {
                    return hwc->value;

                } else {
                    return NULL;
                }
            }

            value = nst_hash_find_wc_head(hwc, name, n - 1);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


void *
nst_hash_find_wc_tail(nst_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    nst_uint_t   i, key;

#if 0
    nst_str_t  line;

    line.len = len;
    line.data = name;
    nst_log_error(NST_LOG_ALERT, nst_cycle->log, 0, "wct:\"%V\"", &line);
#endif

    key = 0;

    for (i = 0; i < len; i++) {
        if (name[i] == '.') {
            break;
        }

        key = nst_hash(key, name[i]);
    }

    if (i == len) {
        return NULL;
    }

#if 0
    nst_log_error(NST_LOG_ALERT, nst_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = nst_hash_find(&hwc->hash, key, name, i);

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer,
         *     01 - value is pointer to wildcard hash allowing "example.*".
         */

        if ((uintptr_t) value & 1) {

            i++;

            hwc = (nst_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            value = nst_hash_find_wc_tail(hwc, &name[i], len - i);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


void *
nst_hash_find_combined(nst_hash_combined_t *hash, nst_uint_t key, u_char *name,
    size_t len)
{
    void  *value;

    if (hash->hash.buckets) {
        value = nst_hash_find(&hash->hash, key, name, len);

        if (value) {
            return value;
        }
    }

    if (hash->wc_head && hash->wc_head->hash.buckets) {
        value = nst_hash_find_wc_head(hash->wc_head, name, len);

        if (value) {
            return value;
        }
    }

    if (hash->wc_tail && hash->wc_tail->hash.buckets) {
        value = nst_hash_find_wc_tail(hash->wc_tail, name, len);

        if (value) {
            return value;
        }
    }

    return NULL;
}


#define NST_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + nst_align((name)->key.len + 1, sizeof(void *)))

nst_int_t
nst_hash_init(nst_hash_init_t *hinit, nst_hash_key_t *names, nst_uint_t nelts)
{
    u_char          *elts;
    size_t           len;
    u_short         *test;
    nst_uint_t       i, n, key, size, start, bucket_size;
    nst_hash_elt_t  *elt, **buckets;

    for (n = 0; n < nelts; n++) {
        if (names[n].key.len >= 255) {
            nst_log_error(NST_LOG_EMERG, hinit->pool->log, 0,
                          "the \"%V\" value to hash is to long: %uz bytes, "
                          "the maximum length can be 255 bytes only",
                          &names[n].key, names[n].key.len);
            return NST_ERROR;
        }

        if (hinit->bucket_size < NST_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
        {
            nst_log_error(NST_LOG_EMERG, hinit->pool->log, 0,
                          "could not build the %s, you should "
                          "increase %s_bucket_size: %i",
                          hinit->name, hinit->name, hinit->bucket_size);
            return NST_ERROR;
        }
    }

    test = nst_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);
    if (test == NULL) {
        return NST_ERROR;
    }

    bucket_size = hinit->bucket_size - sizeof(void *);

    start = nelts / (bucket_size / (2 * sizeof(void *)));
    start = start ? start : 1;

    if (hinit->max_size > 10000 && hinit->max_size / nelts < 100) {
        start = hinit->max_size - 1000;
    }

    for (size = start; size < hinit->max_size; size++) {

        nst_memzero(test, size * sizeof(u_short));

        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {
                continue;
            }

            key = names[n].key_hash % size;
            test[key] = (u_short) (test[key] + NST_HASH_ELT_SIZE(&names[n]));

#if 0
            nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %ui %ui \"%V\"",
                          size, key, test[key], &names[n].key);
#endif

            if (test[key] > (u_short) bucket_size) {
                goto next;
            }
        }

        goto found;

    next:

        continue;
    }

    nst_log_error(NST_LOG_EMERG, hinit->pool->log, 0,
                  "could not build the %s, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size);

    nst_free(test);

    return NST_ERROR;

found:

    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        test[key] = (u_short) (test[key] + NST_HASH_ELT_SIZE(&names[n]));
    }

    len = 0;

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        test[i] = (u_short) (nst_align(test[i], nst_cacheline_size));

        len += test[i];
    }

    if (hinit->hash == NULL) {
        hinit->hash = nst_pcalloc(hinit->pool, sizeof(nst_hash_wildcard_t)
                                             + size * sizeof(nst_hash_elt_t *));
        if (hinit->hash == NULL) {
            nst_free(test);
            return NST_ERROR;
        }

        buckets = (nst_hash_elt_t **)
                      ((u_char *) hinit->hash + sizeof(nst_hash_wildcard_t));

    } else {
        buckets = nst_pcalloc(hinit->pool, size * sizeof(nst_hash_elt_t *));
        if (buckets == NULL) {
            nst_free(test);
            return NST_ERROR;
        }
    }

    elts = nst_palloc(hinit->pool, len + nst_cacheline_size);
    if (elts == NULL) {
        nst_free(test);
        return NST_ERROR;
    }

    elts = nst_align_ptr(elts, nst_cacheline_size);

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        buckets[i] = (nst_hash_elt_t *) elts;
        elts += test[i];

    }

    for (i = 0; i < size; i++) {
        test[i] = 0;
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        elt = (nst_hash_elt_t *) ((u_char *) buckets[key] + test[key]);

        elt->value = names[n].value;
        elt->len = (u_char) names[n].key.len;

        for (i = 0; i < names[n].key.len; i++) {
            elt->name[i] = nst_tolower(names[n].key.data[i]);
        }

        test[key] = (u_short) (test[key] + NST_HASH_ELT_SIZE(&names[n]));
    }

    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }

        elt = (nst_hash_elt_t *) ((u_char *) buckets[i] + test[i]);

        elt->value = NULL;
    }

    nst_free(test);

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

#if 0

    for (i = 0; i < size; i++) {
        nst_str_t   val;
        nst_uint_t  key;

        elt = buckets[i];

        if (elt == NULL) {
            nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: NULL", i);
            continue;
        }

        while (elt->value) {
            val.len = elt->len;
            val.data = &elt->name[0];

            key = hinit->key(val.data, val.len);

            nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %p \"%V\" %ui", i, elt, &val, key);

            elt = (nst_hash_elt_t *) nst_align_ptr(&elt->name[0] + elt->len,
                                                   sizeof(void *));
        }
    }

#endif

    return NST_OK;
}


nst_int_t
nst_hash_wildcard_init(nst_hash_init_t *hinit, nst_hash_key_t *names,
    nst_uint_t nelts)
{
    size_t                len, dot_len;
    nst_uint_t            i, n, dot;
    nst_array_t           curr_names, next_names;
    nst_hash_key_t       *name, *next_name;
    nst_hash_init_t       h;
    nst_hash_wildcard_t  *wdc;

    if (nst_array_init(&curr_names, hinit->temp_pool, nelts,
                       sizeof(nst_hash_key_t))
        != NST_OK)
    {
        return NST_ERROR;
    }

    if (nst_array_init(&next_names, hinit->temp_pool, nelts,
                       sizeof(nst_hash_key_t))
        != NST_OK)
    {
        return NST_ERROR;
    }

    for (n = 0; n < nelts; n = i) {

#if 0
        nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                      "wc0: \"%V\"", &names[n].key);
#endif

        dot = 0;

        for (len = 0; len < names[n].key.len; len++) {
            if (names[n].key.data[len] == '.') {
                dot = 1;
                break;
            }
        }

        name = nst_array_push(&curr_names);
        if (name == NULL) {
            return NST_ERROR;
        }

        name->key.len = len;
        name->key.data = names[n].key.data;
        name->key_hash = hinit->key(name->key.data, name->key.len);
        name->value = names[n].value;

#if 0
        nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                      "wc1: \"%V\" %ui", &name->key, dot);
#endif

        dot_len = len + 1;

        if (dot) {
            len++;
        }

        next_names.nelts = 0;

        if (names[n].key.len != len) {
            next_name = nst_array_push(&next_names);
            if (next_name == NULL) {
                return NST_ERROR;
            }

            next_name->key.len = names[n].key.len - len;
            next_name->key.data = names[n].key.data + len;
            next_name->key_hash= 0;
            next_name->value = names[n].value;

#if 0
            nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                          "wc2: \"%V\"", &next_name->key);
#endif
        }

        for (i = n + 1; i < nelts; i++) {
            if (nst_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
                break;
            }

            if (!dot
                && names[i].key.len > len
                && names[i].key.data[len] != '.')
            {
                break;
            }

            next_name = nst_array_push(&next_names);
            if (next_name == NULL) {
                return NST_ERROR;
            }

            next_name->key.len = names[i].key.len - dot_len;
            next_name->key.data = names[i].key.data + dot_len;
            next_name->key_hash= 0;
            next_name->value = names[i].value;

#if 0
            nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                          "wc3: \"%V\"", &next_name->key);
#endif
        }

        if (next_names.nelts) {

            h = *hinit;
            h.hash = NULL;

            if (nst_hash_wildcard_init(&h, (nst_hash_key_t *) next_names.elts,
                                       next_names.nelts)
                != NST_OK)
            {
                return NST_ERROR;
            }

            wdc = (nst_hash_wildcard_t *) h.hash;

            if (names[n].key.len == len) {
                wdc->value = names[n].value;
#if 0
                nst_log_error(NST_LOG_ALERT, hinit->pool->log, 0,
                              "wdc: \"%V\"", wdc->value);
#endif
            }

            name->value = (void *) ((uintptr_t) wdc | (dot ? 1 : 3));
        }
    }

    if (nst_hash_init(hinit, (nst_hash_key_t *) curr_names.elts,
                      curr_names.nelts)
        != NST_OK)
    {
        return NST_ERROR;
    }

    return NST_OK;
}


nst_uint_t
nst_hash_key(const u_char *data, size_t len)
{
    nst_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = nst_hash(key, data[i]);
    }

    return key;
}


nst_uint_t
nst_hash_key_lc(const u_char *data, size_t len)
{
    nst_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = nst_hash(key, nst_tolower(data[i]));
    }

    return key;
}


nst_int_t
nst_hash_keys_array_init(nst_hash_keys_arrays_t *ha, nst_uint_t type)
{
    nst_uint_t  asize;

    if (type == NST_HASH_SMALL) {
        asize = 4;
        ha->hsize = 107;

    } else {
        asize = NST_HASH_LARGE_ASIZE;
        ha->hsize = NST_HASH_LARGE_HSIZE;
    }

    if (nst_array_init(&ha->keys, ha->temp_pool, asize, sizeof(nst_hash_key_t))
        != NST_OK)
    {
        return NST_ERROR;
    }

    if (nst_array_init(&ha->dns_wc_head, ha->temp_pool, asize,
                       sizeof(nst_hash_key_t))
        != NST_OK)
    {
        return NST_ERROR;
    }

    if (nst_array_init(&ha->dns_wc_tail, ha->temp_pool, asize,
                       sizeof(nst_hash_key_t))
        != NST_OK)
    {
        return NST_ERROR;
    }

    ha->keys_hash = nst_pcalloc(ha->temp_pool, sizeof(nst_array_t) * ha->hsize);
    if (ha->keys_hash == NULL) {
        return NST_ERROR;
    }

    ha->dns_wc_head_hash = nst_pcalloc(ha->temp_pool,
                                       sizeof(nst_array_t) * ha->hsize);
    if (ha->dns_wc_head_hash == NULL) {
        return NST_ERROR;
    }

    ha->dns_wc_tail_hash = nst_pcalloc(ha->temp_pool,
                                       sizeof(nst_array_t) * ha->hsize);
    if (ha->dns_wc_tail_hash == NULL) {
        return NST_ERROR;
    }

    return NST_OK;
}


nst_int_t
nst_hash_add_key(nst_hash_keys_arrays_t *ha, nst_str_t *key, void *value,
    nst_uint_t flags)
{
    size_t           len;
    u_char          *p;
    nst_str_t       *name;
    nst_uint_t       i, k, n, skip, last;
    nst_array_t     *keys, *hwc;
    nst_hash_key_t  *hk;

    last = key->len;

    if (flags & NST_HASH_WILDCARD_KEY) {

        /*
         * supported wildcards:
         *     "*.example.com", ".example.com", and "www.example.*"
         */

        n = 0;

        for (i = 0; i < key->len; i++) {

            if (key->data[i] == '*') {
                if (++n > 1) {
                    return NST_DECLINED;
                }
            }

            if (key->data[i] == '.' && key->data[i + 1] == '.') {
                return NST_DECLINED;
            }
        }

        if (key->len > 1 && key->data[0] == '.') {
            skip = 1;
            goto wildcard;
        }

        if (key->len > 2) {

            if (key->data[0] == '*' && key->data[1] == '.') {
                skip = 2;
                goto wildcard;
            }

            if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {
                skip = 0;
                last -= 2;
                goto wildcard;
            }
        }

        if (n) {
            return NST_DECLINED;
        }
    }

    /* exact hash */

    k = 0;

    for (i = 0; i < last; i++) {
        if (!(flags & NST_HASH_READONLY_KEY)) {
            key->data[i] = nst_tolower(key->data[i]);
        }
        k = nst_hash(k, key->data[i]);
    }

    k %= ha->hsize;

    /* check conflicts in exact hash */

    name = ha->keys_hash[k].elts;

    if (name) {
        for (i = 0; i < ha->keys_hash[k].nelts; i++) {
            if (last != name[i].len) {
                continue;
            }

            if (nst_strncmp(key->data, name[i].data, last) == 0) {
                return NST_BUSY;
            }
        }

    } else {
        if (nst_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                           sizeof(nst_str_t))
            != NST_OK)
        {
            return NST_ERROR;
        }
    }

    name = nst_array_push(&ha->keys_hash[k]);
    if (name == NULL) {
        return NST_ERROR;
    }

    *name = *key;

    hk = nst_array_push(&ha->keys);
    if (hk == NULL) {
        return NST_ERROR;
    }

    hk->key = *key;
    hk->key_hash = nst_hash_key(key->data, last);
    hk->value = value;

    return NST_OK;


wildcard:

    /* wildcard hash */

    k = 0;

    for (i = skip; i < last; i++) {
        key->data[i] = nst_tolower(key->data[i]);
        k = nst_hash(k, key->data[i]);
    }

    k %= ha->hsize;

    if (skip == 1) {

        /* check conflicts in exact hash for ".example.com" */

        name = ha->keys_hash[k].elts;

        if (name) {
            len = last - skip;

            for (i = 0; i < ha->keys_hash[k].nelts; i++) {
                if (len != name[i].len) {
                    continue;
                }

                if (nst_strncmp(&key->data[1], name[i].data, len) == 0) {
                    return NST_BUSY;
                }
            }

        } else {
            if (nst_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                               sizeof(nst_str_t))
                != NST_OK)
            {
                return NST_ERROR;
            }
        }

        name = nst_array_push(&ha->keys_hash[k]);
        if (name == NULL) {
            return NST_ERROR;
        }

        name->len = last - 1;
        name->data = nst_palloc(ha->temp_pool, name->len);
        if (name->data == NULL) {
            return NST_ERROR;
        }

        nst_memcpy(name->data, &key->data[1], name->len);
    }


    if (skip) {

        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */

        p = nst_palloc(ha->temp_pool, last);
        if (p == NULL) {
            return NST_ERROR;
        }

        len = 0;
        n = 0;

        for (i = last - 1; i; i--) {
            if (key->data[i] == '.') {
                nst_memcpy(&p[n], &key->data[i + 1], len);
                n += len;
                p[n++] = '.';
                len = 0;
                continue;
            }

            len++;
        }

        if (len) {
            nst_memcpy(&p[n], &key->data[1], len);
            n += len;
        }

        p[n] = '\0';

        hwc = &ha->dns_wc_head;
        keys = &ha->dns_wc_head_hash[k];

    } else {

        /* convert "www.example.*" to "www.example\0" */

        last++;

        p = nst_palloc(ha->temp_pool, last);
        if (p == NULL) {
            return NST_ERROR;
        }

        nst_cpystrn(p, key->data, last);

        hwc = &ha->dns_wc_tail;
        keys = &ha->dns_wc_tail_hash[k];
    }


    hk = nst_array_push(hwc);
    if (hk == NULL) {
        return NST_ERROR;
    }

    hk->key.len = last - 1;
    hk->key.data = p;
    hk->key_hash = 0;
    hk->value = value;


    /* check conflicts in wildcard hash */

    name = keys->elts;

    if (name) {
        len = last - skip;

        for (i = 0; i < keys->nelts; i++) {
            if (len != name[i].len) {
                continue;
            }

            if (nst_strncmp(key->data + skip, name[i].data, len) == 0) {
                return NST_BUSY;
            }
        }

    } else {
        if (nst_array_init(keys, ha->temp_pool, 4, sizeof(nst_str_t)) != NST_OK)
        {
            return NST_ERROR;
        }
    }

    name = nst_array_push(keys);
    if (name == NULL) {
        return NST_ERROR;
    }

    name->len = last - skip;
    name->data = nst_palloc(ha->temp_pool, name->len);
    if (name->data == NULL) {
        return NST_ERROR;
    }

    nst_memcpy(name->data, key->data + skip, name->len);

    return NST_OK;
}
