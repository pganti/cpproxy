
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NST_USER_H_INCLUDED_
#define _NST_USER_H_INCLUDED_

#include "nst_config.h"
#include "nst_types.h"

struct nst_pool_s;

typedef uid_t  nst_uid_t;
typedef gid_t  nst_gid_t;


nst_int_t nst_crypt(struct nst_pool_s *pool, u_char *key, u_char *salt,
    u_char **encrypted);



#endif /* _NST_USER_H_INCLUDED_ */
