#include "nst_http_helpers.h"

#include <nst_event.h>
#include <nst_connection.h>

#include <nst_log.h>

void
nst_http_empty_event_handler(nst_event_t *ev)
{
    nst_connection_t *c = ev->data;

    NST_DEBUG_LOG_OV(c->dbg_log_lvl,
                     NST_LOG_LEVEL_DEBUG,
                     "c#:%ui got %s event",
                     c->number,
                     ev->write == 1 ? "write" : "read");
}
