/* always include myself first */
#include "nst_http_transaction.h"

/* local includes */
#include "nst_http_helpers.h"
#include "nst_http_request.h"
#include "nst_http_defaults.h"

/* libevent includes */
#include <nst_event.h>
#include <nst_connection.h>
#include <nst_cfg_svc.h>

/* libcore includes */
#include <nst_time.h>
#include <nst_timer.h>
#include <nst_palloc.h>

static void nst_http_transaction_init(nst_event_t *rev);

void
nst_http_transaction_init_connection(nst_connection_t *cli_c)
{
    nst_event_t         *rev;

    rev = cli_c->read;
    rev->handler = nst_http_transaction_init;
    cli_c->write->handler = nst_http_empty_event_handler;

    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        nst_http_transaction_init(rev);
    } else {
        nst_event_add_timer(rev, cli_c->svc->post_accept_timeout_ms);

        if (nst_handle_read_event(rev, 0) == NST_ERROR) {
            nst_http_downstream_close(cli_c, NST_IO_CLOSE_REASON_ERROR);
        }
    }

    return;
}

void
nst_http_transaction_min_mem_usage(nst_http_transaction_t *htran)
{
    nst_iobuf_free(htran->small_req_hdr_iobuf);

    nst_iochain_free(&htran->recycle_req_hdr_iochain_in);
}

static void
nst_http_transaction_init(nst_event_t *rev)
{
    nst_connection_t           *cli_c;
    nst_http_transaction_t     *htran;

    cli_c = rev->data;

    if (nst_event_is_timedout(rev)) {
        NST_NOC_LOG(NST_LOG_INFO, "c#:%ui client timed out", cli_c->number);

        nst_http_downstream_close(cli_c, NST_IO_CLOSE_REASON_TIMEDOUT);
        return;
    }


    htran = nst_pcalloc(cli_c->pool, sizeof(nst_http_transaction_t));
    if (htran == NULL) {
        nst_http_downstream_close(cli_c, NST_IO_CLOSE_REASON_ERROR);
        return;
    }
    htran->cli_connection = cli_c;

    /* cli_c->tid = 0; */ /* it should be done when a connection is accepted */
    cli_c->data = htran;

    nst_iochain_init(&htran->recycle_req_hdr_iochain_in);

    nst_http_request_init(rev);
}
