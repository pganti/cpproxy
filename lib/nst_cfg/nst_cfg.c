#include "nst_cfg.h"

#include "nst_cfg_common.h"

#include <nst_genhash.h>
#include <nst_mem_stat_allocator.h>
#include <nst_allocator.h>
#include <nst_log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

nst_allocator_t nst_cfg_allocator;
XML_Parser parser = NULL;

void
nst_cfg_init(void)
{
    nst_cfg_allocator = nst_mem_stat_register("NST CONFIG");
}

void
nst_cfg_reset(void)
{
    if(parser)
        XML_ParserFree(parser);
}

void
nst_cfg_log_capture_error(const char *capturing_entity_tag,
                          const char *error_tag, bool is_end_tag,
                          nst_uint_t line_num)
{
    NST_NOC_LOG(NST_LOG_LEVEL_CRITICAL,
                "<%s> parsing error: when capturing <%s%s> "
                "at around %ud",
                capturing_entity_tag,
                is_end_tag ? "/" : "",
                error_tag,
                line_num);
}

void
nst_cfg_log_ignore_tag(const char *capturing_entity_tag,
                       const char *ignore_tag, bool is_end_tag,
                       nst_uint_t line_num, const char *reason)
{
    NST_NOC_LOG(NST_LOG_LEVEL_DEBUG,
                "<%s> parsing verbose: ignored <%s%s> at arround %ud. %s",
                capturing_entity_tag,
                is_end_tag ? "/" : "",
                ignore_tag,
                line_num,
                reason ? reason : "");
}

void nst_cfg_cstr_vec_free(void *elt)
{
    if(!elt)
        return;

    nst_allocator_free(&nst_cfg_allocator, *(char **)elt);
}

void nst_cfg_cstr_free(void *data)
{
    nst_allocator_free(&nst_cfg_allocator, data);
}

void nst_cfg_frame_data_empty_extra_free(void *data)
{
    (void)data;
    return;
}
