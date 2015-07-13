#include "nst_cfg_test_common.h"

#include "nst_cpt.h"

#include "nst_cfg_common.h"
#include "nst_cfg.h"

#include "nst_mem_stat_allocator.h"
#include "nst_assert.h"

#include <stdarg.h>
#include <stdio.h>

static void nst_cfg_test_common_init(void) __attribute__((constructor));

static nst_expat_stack_frame_t test_expat_stack_bottom = {
    .parser = NULL,
    .name = NULL,
    .atts = NULL,
    .start_handler = test_root_start_handler,
    .end_handler = test_root_end_handler,
    .char_handler = test_root_char_handler,
    .parent = NULL,
    .data = NULL,
};

nst_expat_stack_frame_t *test_expat_stack_top = &test_expat_stack_bottom;

void
test_root_start_handler(void *udata, 
                        const XML_Char *name, const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG, "<%s>", name);
    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &test_expat_stack_bottom) {
        nst_assert(current->start_handler);
        nst_assert(current->end_handler);
        current->start_handler(udata, name, attrs);
    } else {
        test_start_elt_dispatcher(udata, name, attrs);
    }
}

void
test_root_end_handler(void *udata, const XML_Char *name)
{

    nst_expat_stack_frame_t *current;

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG, "</%s>", name);

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &test_expat_stack_bottom) {
        nst_assert(current->start_handler);
        nst_assert(current->end_handler);
        current->end_handler(udata, name);
    } else {
        test_end_elt_dispatcher(udata, name);
    }
}

void
test_root_char_handler(void *udata, const XML_Char *s, int len)
{
   nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &test_expat_stack_bottom
       && current->char_handler) {
        current->char_handler(udata, s, len);
    }
}

static void
nst_cfg_test_common_init(void)
{
    nst_cpt_init();
    nst_cfg_init();
}
