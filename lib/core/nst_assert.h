#ifndef _NST_ASSERT_H_
#define _NST_ASSERT_H_

#include <nst_config.h>
#include <nst_log.h>

#include <stdlib.h>

#define NST_ASSERT nst_assert /* mainly for nst_log.h */

#define nst_assert(cond)                                            \
    do {                                                            \
        if(!(cond)) {                                               \
            NST_DEBUG_LOG(NST_LOG_LEVEL_CRITICAL,                   \
                          "assert condition \"" #cond "\" failed"); \
            abort();                                                \
        }                                                           \
    } while(0)


#endif
