
#include "nst_core.h"
#include "nst_posix_init.h"

nst_log_t *
nst_corelib_init (const char *agent)
{
    nst_log_t * log;

    nst_time_init ();

    log = nst_log_init (agent);

    nst_os_init();
    nst_crc32_table_init();

    return log;
}

void
nst_corelib_reset(void)
{
    nst_crc32_table_reset();

    nst_log_reset();
}
