#include "nst_cpt.h"

/* NST CPT */
#include "nst_cpt_common.h"
#include "nst_cpt_node.h"

/* NST libs */
#include <nst_mem_stat_allocator.h>
#include <nst_allocator.h>
#include <nst_vector.h>
#include <nst_assert.h>

#include <stdlib.h>

nst_allocator_t nst_cpt_allocator;

void nst_cpt_init(void)
{
    nst_cpt_allocator = nst_mem_stat_register("NST CPT");
    nst_cpt_node_init();
}

#if 0
static void nst_cpt_debug_log_indent(const nst_cpt_request_t *request,
                                     nst_cpt_debug_log_level_e level)
{
    int i;
    if(nst_cpt_log->debug_log_level == NST_CPT_DEBUG_LOG_LEVEL_OFF
       || nst_cpt_log->debug_log_level < level)
        return;

    for(i = 0; i < request->current_depth; i++)
        nst_cpt_log.debug_log("%s", "  ");

    return;
}

static void nst_cpt_regular_log_indent(nst_cpt_regular_log_level_e level)
{
    int i;
    if(nst_cpt_log->regular_log_level < level)
        return;

    for(i = 0; i < request->current_depth; i++)
        nst_cpt_log.regular_log("%s", "  ");

    return;
}

static void nst_cpt_regular_log(nst_cpt_regular_log_level_e level,
                            const char *fmt, ...)
{
    va_list va;
    int saved_errno;

    if(nst_cpt_log.regular_log_level < level)
        return;

    saved_errno = errno;

    va_start(va, fmt);
    nst_cpt_log.regular_log(fmt, ap);
    va_end(ap);

    errno = saved_errno;

    return;
}

static void nst_cpt_debug_log(const char *fmt, ...)
{
    if(nst_cpt_log.debug_log_level == NST_CPT_DEBUG_LOG_LEVEL_OFF
       || nst_cpt_log.debug_log_level < level)
        return;

    saved_errno = errno;

    va_start(va, fmt);
    nst_cpt_log.debug_log(fmt, ap);
    va_end(ap);

    errno = saved_errno;

    return;
}

static const char *nst_cpt_debuge_log_node(const nst_cpt_node_t *node)
{

}
#endif
