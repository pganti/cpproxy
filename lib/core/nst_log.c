#include "nst_log.h"

#include <nst_mempool.h>
#include <nst_types.h>
#include <nst_time.h>
#include <nst_errno.h>
#include <nst_string.h>
#include <nst_assert.h>
#include <nst_alloc.h>
#include <nst_defaults.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <nst_times.h>

#if 0
#define	dprintf		printf
#else
#define	dprintf(args...)
#endif

nst_log_facility_t      nst_access_logfac;
nst_log_facility_t      nst_debug_logfac;
nst_log_facility_t      nst_noc_logfac;
nst_log_facility_t      nst_audit_logfac;
static int              nst_log_inited = 0;

static nst_log_status_t nst_log_open_file (nst_log_facility_t * fac);
static nst_log_status_t nst_log_close_file (nst_log_facility_t * fac);

static int nst_log_check_and_add_newline (int len, nst_log_message_t * m);

static nst_log_status_t nst_logit (nst_log_facility_t * fac, nst_log_conf_t * conf, nst_log_level_t clevel, const char * function, int line, nst_log_level_t level, const char * fmt, va_list args);
static void nst_log_write_net (nst_log_facility_t * fac, nst_log_message_t * m);
static int nst_log_ratelimit_prune_entries (nst_log_facility_t * fac);
static void nst_log_ratelimit_free_entries (nst_log_facility_t * fac);
static nst_log_status_t nst_log_ratelimit (nst_log_facility_t * fac, nst_log_conf_t * conf, nst_log_message_t * m);
static nst_log_status_t nst_log_ratelimit_simple_duplicate_check (nst_log_facility_t * fac, nst_log_conf_t  * conf, nst_log_message_t * m);

nst_log_status_t nst_log_open_socket (nst_log_facility_t * fac, nst_log_conf_t * conf);

static int nst_log_time_year_base = 1900;


/*! nst_log_ratelimit_message_limits_check - Checks the message limits */
/*
 * This functions checks to see if the message exeeded the its limits.
 * This functions checks for:
 *        - Number of duplicate hits on this message.
 *        - Last hit time of the message.
 * If the message is hit more than given number of times or
 * if the message is created before certain time will disqualify this
 * message to be used to supress the duplicates.
 *
 * @returns 0 if the message can be used for duplicate supression.
 * @returns 1 if the message can't be used for duplicate supression.
 */
static inline int
nst_log_ratelimit_message_limits_check (nst_log_facility_t * fac,
                                        nst_log_conf_t     * conf,
                                        nst_log_message_t * m
                                        )
{
    struct timeval        vp, tv;

    if (m->hits >= conf->ratelimit.hits_ceiling)
        return 1;

    nst_getcached_tv (&tv);

    timersub(&tv, &(m->createdtv), &vp);

    if ((u32)vp.tv_sec >= conf->ratelimit.time_ceiling)
        return 1;

    return 0;
}

static nst_log_status_t
nst_log_ratelimit_simple_duplicate_check (nst_log_facility_t * fac,
                                          nst_log_conf_t     * conf,
                                          nst_log_message_t * m)
{
    nst_log_ratelimit_table_t    * rt;
    nst_log_message_t            * rm;
    nst_log_level_t                l = m->h.level;
    nst_log_status_t               status = NST_LOG_STATUS_RL_LOG;

    rt = &fac->rattab;
    rm = rt->duplicates [l];

    if (rm) {
        int    sl = m->h.len - m->skip_len;
        int    dl = rm->h.len - rm->skip_len;

        if (sl == dl) {
            char * s = m->logmsg + m->skip_len;
            char * d = rm->logmsg + rm->skip_len;
            int len = strncmp (s, d, sl);
            int rc = nst_log_ratelimit_message_limits_check (fac, conf, rm);

            if (len == 0) {
                if (rc == 0) {
                    rt->stats.duplicates++;
                    rm->hits++;
                    status = NST_LOG_STATUS_RL_DUPLICATE;
                }
                else {
                    /*
                     * Message exceeded either time or count.
                     * Reset the rate limit count for this message.
                     */
                    nst_log_message_free (fac, rm);
                    rm = rt->duplicates [l] = NULL;
                }
            }
        }
    }

    if (status != NST_LOG_STATUS_RL_DUPLICATE) {
        NST_ASSERT(rt->duplicates [l] == rm);
        if (rm) {
            nst_log_message_free (fac, rm);
        }
        rt->duplicates [l] = m;
        nst_log_message_takeref (m);
        m->hits = 0;
        nst_getcached_tv (&(m->createdtv));
    }

    return status;
}

static void
nst_log_simple_duplicate_entries_free (nst_log_facility_t * fac)
{
    nst_log_message_t            * rm;
    nst_log_level_t                l;

    for (l = NST_LOG_LEVEL_START; l < NST_LOG_LEVEL_END; l++) {
        rm = fac->rattab.duplicates[l];
        if (rm) {
            nst_log_message_free (fac, rm);
        }
    }
}
static inline void
nst_log_ratelimit_tryfreeing_last (nst_log_facility_t * fac,
                                   nst_log_ratelimit_queue_t * q)
{
    nst_log_message_t           * lm = NULL, * fm = NULL;

    fm = TAILQ_FIRST(&(q->msgq));
    lm = TAILQ_LAST(&(q->msgq), mq);

    if (fm != lm && lm && lm->hits == 0 && q->len > NST_LOG_PRUNE_QLEN_LEN) {
        TAILQ_REMOVE(&q->msgq, lm, next);
        nst_log_message_free (fac, lm);
    }
}

static nst_log_status_t
nst_log_ratelimit (nst_log_facility_t * fac, nst_log_conf_t * conf,
                   nst_log_message_t * m)
{
    nst_log_ratelimit_queue_t   * q;
    int                       sl, k, found = 0;
    nst_log_level_t               l;
    nst_log_message_t           * rm = NULL;
    nst_log_status_t              status;
    char                    * s;
    struct timeval            tv, vp;

    sl = m->h.len - m->skip_len;
    s  = m->logmsg + m->skip_len;
    l  = m->h.level;
    k = s[m->h.len + m->skip_len - 1];
    q = &fac->rattab.level_queues [l][k];

    nst_getcached_tv (&tv);
    timersub(&tv, &(fac->rattab.time_interval_lasttv), &vp);

    if ((u32)vp.tv_sec >= conf->ratelimit.rollover_time_interval) {
        fac->rattab.logged                 = 0;
        fac->rattab.time_interval_lasttv   = tv;
    }

    if (fac->rattab.logged >= conf->ratelimit.messages_per_sec) {
        /*
         * All this sucker does is a tail drop.
         * I really don't like it. How about RED. May be later. Let's
         * not make a carrer out of logging.
         */
        fac->rattab.stats.ratelimited++;
        dprintf ("nst_log_ratelimit: Rate limited=%ld, "
                 "logged(curr=%d, total=%ld), qlen=%d\n",
                 fac->rattab.stats.ratelimited, fac->rattab.logged,
                 fac->rattab.stats.total_logged, q->len);

        return NST_LOG_STATUS_RL_RATELIMITED;
    }


    rm = TAILQ_FIRST(&q->msgq);
    while (rm != NULL) {
        int    dl = rm->h.len - rm->skip_len;
        char * d = rm->logmsg + rm->skip_len;

        if (dl == sl) {
            int len = strncmp (s, d, sl);
            if (len == 0) {
                if (nst_log_ratelimit_message_limits_check (fac, conf, rm)==0) {
                    found = 1;
                }
                else {
                    /* Message exceeded time or count, free this message.*/
                    m->ohits = rm->hits + rm->ohits;
                    TAILQ_REMOVE(&q->msgq, rm, next);
                    q->len--;
                    nst_log_message_free (fac, rm);
                    rm = NULL;

                }
                break;
            }
        }
        rm = TAILQ_NEXT(rm, next);
    }

    if (found == 0) {
        m->hits = 0;
        nst_getcached_tv (&(m->createdtv));
        TAILQ_INSERT_HEAD(&q->msgq, m, next);
        q->len++;
        nst_log_message_takeref(m);
        fac->rattab.logged++;
        fac->rattab.stats.total_logged++;
        status = NST_LOG_STATUS_RL_LOG;
    }
    else { /* Found */
        NST_ASSERT(rm != NULL);
        status = NST_LOG_STATUS_RL_DUPLICATE;
        rm->hits++;
        fac->rattab.stats.duplicates++;

        TAILQ_REMOVE(&q->msgq, rm, next);
        TAILQ_INSERT_HEAD(&q->msgq, rm, next);
    }

    nst_log_ratelimit_tryfreeing_last (fac, q);

    return  status;
}

static void
nst_log_ratelimit_table_init (nst_log_ratelimit_table_t * tab)
{
    int                              i;
    nst_log_level_t                      l;

    bzero ((void *)tab, sizeof(nst_log_ratelimit_table_t));

    for (l = NST_LOG_LEVEL_START; l < NST_LOG_LEVEL_END; l++) {

        for (i = 0; i < NST_LOG_RATELIMIT_ALPHA_QUEUE_LEN; i++) {
            nst_log_ratelimit_queue_t  * q = &(tab->level_queues [l][i]);
            TAILQ_INIT(&(q->msgq));
            q->len = 0;
        }
    }
    nst_getcached_tv (&tab->time_interval_lasttv);
    tab->logged = 0;
}


static void
nst_log_ratelimit_free_entries (nst_log_facility_t * fac)
{
    nst_log_ratelimit_queue_t   * q;
    nst_log_message_t           * rm;
    nst_log_level_t               l;
    int                           i;


    for (l = NST_LOG_LEVEL_VERBOSE; l >= NST_LOG_LEVEL_CRITICAL; l--) {
        for (i = 0; i < NST_LOG_RATELIMIT_ALPHA_QUEUE_LEN; i++) {
            q = &fac->rattab.level_queues [l][i];

            while (1) {
                rm = TAILQ_FIRST(&q->msgq);
                if (rm == NULL)
                    break;

                TAILQ_REMOVE(&q->msgq, rm, next);
                nst_log_message_free (fac, rm);
            }
        }
    }
}

static int
nst_log_ratelimit_prune_entries (nst_log_facility_t * fac)
{
    nst_log_ratelimit_queue_t   * q;
    int                       i, pruned = 0;
    nst_log_message_t           * rm;
    struct timeval            tv;
    nst_log_level_t               l;

    nst_getcached_tv (&tv);

    for (l = NST_LOG_LEVEL_VERBOSE; l >= NST_LOG_LEVEL_CRITICAL; l--) {
        int   p = 0;
        for (i = 0; i < NST_LOG_RATELIMIT_ALPHA_QUEUE_LEN; i++) {
            q = &fac->rattab.level_queues [l][i];

            while (1) {
                rm = TAILQ_LAST(&q->msgq, mq);
                if (rm == NULL)
                    break;

                TAILQ_REMOVE(&q->msgq, rm, next);
                nst_log_message_free (fac, rm);
                q->len--;
                pruned++;
                p++;
                dprintf ("nst_log_ratelimit_prune_entries: Pruned "
                        "level=%d, bucket=%d, len=%d\n",
                        l, i, q->len);
                if (p > 5)
                    break;
            }
        }
    }

    return pruned;
}

nst_log_message_t *
nst_log_message_alloc (nst_log_facility_t * fac)
{
    nst_log_message_t * m = NULL;
    int             i, p;

    for (i = 0; i < 2; i++) {
        m = (nst_log_message_t *)nst_mempool_alloc (fac->pool);
        //m = (nst_log_message_t *)nst_xmalloc (NST_LOG_MSG_SIZE);
        if (m) {
            bzero (&m->h, sizeof(nst_log_hdr_t));
            m->logmsg = m->buf + sizeof(nst_log_hdr_t) + NST_LOG_INFO_LEN;
            //m->bsize = NST_LOG_MSG_SIZE - sizeof(nst_log_message_t);
            m->bsize = NST_LOG_MSG_SIZE - (sizeof(nst_log_message_t) + sizeof(nst_log_hdr_t) + NST_LOG_INFO_LEN);
            m->skip_len = 0;
            m->refcount = 1;
            m->hits = 0;
            m->ohits = 0;
            fac->stats.messages_inuse++;
            break;
        }

        /* Prune the entries */
        p = nst_log_ratelimit_prune_entries (fac);
        dprintf ("nst_log_message_alloc: Pruned entries: %d\n", p);
    }

    return m;
}

void
nst_log_message_free (nst_log_facility_t * fac, nst_log_message_t * m)
{
    m->refcount--;
    NST_ASSERT(m->refcount >= 0);

    if (m->refcount == 0) {
        fac->stats.messages_inuse--;
        //nst_xfree (m);
        nst_mempool_free (fac->pool, m);
    }
}

void
nst_log_message_takeref (nst_log_message_t * m)
{
    m->refcount++;
}

nst_log_facility_t *
nst_log_get_facility (nst_log_facility_type_t f)
{
    nst_log_facility_t  * fac = NULL;

    switch (f) {
        case NST_LOG_TYPE_DEBUG:
            fac = &nst_debug_logfac;
            break;
        case NST_LOG_TYPE_NOC:
            fac = &nst_noc_logfac;
            break;
        case NST_LOG_TYPE_ACCESS:
            fac = &nst_access_logfac;
            break;
        case NST_LOG_TYPE_AUDIT:
            fac = &nst_audit_logfac;
            break;
        default:
            break;
    }

    return fac;
}

static inline int
nst_log_check_and_add_newline (int len, nst_log_message_t * m)
{
    char     * str = m->logmsg;

    if (len && str[len-1] != '\n') {
        if (len == m->bsize) {
            str[len-2] = '\n';
            str[len-1] = '\0';
        }
        else {
            str[len] = '\n';
            len++;
            str[len] = '\0';
        }
    }
    return len;
}

const char *
nst_log_facility_name (nst_log_facility_type_t t)
{
    switch (t) {
        case NST_LOG_TYPE_NOC:
            return "noc";

        case NST_LOG_TYPE_ACCESS:
            return "access";

        case NST_LOG_TYPE_DEBUG:
            return "debug";

        case NST_LOG_TYPE_AUDIT:
            return "audit";

        default:
            return "unknown";
    }

    return "unknown";
}

const char *
nst_log_level_name (nst_log_level_t l)
{
    switch (l) {
        case NST_LOG_LEVEL_CRITICAL:
            return "CRITICAL";
        case NST_LOG_LEVEL_ERROR:
            return "ERROR";
        case NST_LOG_LEVEL_NOTICE:
            return "NOTICE";
        case NST_LOG_LEVEL_INFO:
            return "INFO";
        case NST_LOG_LEVEL_DEBUG:
            return "DEBUG";
        case NST_LOG_LEVEL_VERBOSE:
            return "VERBOSE";
        default:
            return "UNKNOWN";
    }
    return "unknown";
}


static void
nst_log_get_filename (nst_log_facility_t * fac, nst_log_conf_t * conf,
                      char * str,
                      int len, int filenumber)
{
    char         dstr[24];
    pid_t        pid;
    struct tm    tm;
    time_t       t;

    pid = getpid ();
    t = time (NULL);
    gmtime_r (&t, &tm);

    snprintf (dstr, sizeof(dstr), "%04d%02d%02d",
              tm.tm_year + nst_log_time_year_base,
              tm.tm_mon + 1,
              tm.tm_mday);


    /*<directory>-<filename>-<facility name>-<pid>-<date>-<file number>.log */
    snprintf (str, len, "%s/%s-%s-%d-%s-%d.log",
            conf->dirname,
            conf->logname,
            fac->name,
            pid,
            dstr,
            filenumber);
}

void
nst_log_write_stderr (nst_log_facility_t * fac,
                      nst_log_conf_t * conf,
                      nst_log_message_t * m)
{
    int              len;
    char             info [NST_LOG_INFO_LEN];
    char           * logstr;

    len         = m->h.len;
    logstr      = m->logmsg;

    if (conf->flags.mid) {
        int l = snprintf (info, NST_LOG_INFO_LEN,
                         "!%08u!%04d!: ", m->id, m->ohits);
        logstr = m->logmsg - l;
        strncpy (logstr, info, l);
        len += l;
    }

    len = fwrite (logstr, 1, len, stderr);

    fflush(stderr);
}

void
nst_log_write_file (nst_log_facility_t * fac,
                    nst_log_conf_t * conf,
                    nst_log_message_t * m)
{
    int              sz, len;
    nst_log_level_t      level;
    char             info [NST_LOG_INFO_LEN];
    char           * logstr;

    level       = m->h.level;
    len         = m->h.len;
    logstr      = m->logmsg;

    if (conf->flags.mid) {
        int l = snprintf (info, NST_LOG_INFO_LEN,
                         "!%08u!%04d!: ", m->id, m->ohits);
        logstr = m->logmsg - l;
        strncpy (logstr, info, l);
        len += l;
    }

    sz = fwrite (logstr, 1, len, fac->fp);

    if (sz == len) {
        fac->stats.hd_logged++;
        if (level <= NST_LOG_LEVEL_ERROR) {
            fflush (fac->fp);
        }
        if ((fac->stats.hd_logged % conf->flush_count) == 0) {
            struct stat st;

            fflush (fac->fp);
            fstat (fileno(fac->fp), &st);
            if (st.st_size >= conf->filesize) {
                nst_log_close_file (fac);
                nst_log_open_file (fac);
            }
        }
    }
    else {
        /* Some thing wrong */
        nst_log_close_file (fac);
        nst_log_open_file (fac);
    }
}

static void
nst_log_write_net (nst_log_facility_t * fac, nst_log_message_t * m)
{
    nst_log_hdr_t        * h;
    int                slen, len, l;
    char             * str;

    slen   = sizeof(struct sockaddr_in);

    str    = m->logmsg - sizeof(nst_log_hdr_t);
    h      = (nst_log_hdr_t *)str;

    h->type   = m->h.type;
    h->level  = m->h.level;
    h->len    = htons(m->h.len);
    len       = m->h.len + sizeof(nst_log_hdr_t);

#if 0
    snprintf (h->facility, NST_LOG_FAC_NAME_LEN, "%s", fac->conf.logname);
    snprintf (h->agent, NST_LOG_AGENT_NAME_LEN, "%s", fac->conf.agent);
#endif

    l = sendto (fac->fd,
                str,
                len,
                0,
                (struct sockaddr *)&fac->sin,
                (socklen_t)slen);
    if (l != len) {
        dprintf ("nst_log_write_net: Failed to send on fd=%d, err=%s\n",
                 fac->fd, strerror(errno));
    }
}

nst_log_status_t
nst_log_open_socket (nst_log_facility_t * fac, nst_log_conf_t * conf)
{
    int                   s;
    struct hostent      * h;

    s = socket(AF_INET,  SOCK_DGRAM, 0);
    if (s < 0) {
        NST_DEBUG_LOG(NST_LOG_LEVEL_CRITICAL, "Failed to open socket");
        return NST_LOG_ERROR_SOCKET_OPEN;
    }

    h = gethostbyname ((const char *)conf->logserver);
    if (h == NULL || h->h_addr_list[0] == NULL) {
        NST_DEBUG_LOG (NST_LOG_LEVEL_CRITICAL,
                       "Failed to get ip for hostname=%s",
                       conf->logserver);
        return NST_LOG_ERROR_NAME_RESOLUTION;
    }

    bzero (&fac->sin, sizeof(struct sockaddr_in));
    fac->sin.sin_family        = AF_INET;
    fac->sin.sin_addr.s_addr   = *(in_addr_t *)(h->h_addr_list[0]);
    fac->sin.sin_port          = htons (conf->logserver_port);

    fac->fd = s;

    return NST_LOG_OK;
}

static nst_log_status_t
nst_log_open_file (nst_log_facility_t * fac)
{
    char         n [NST_LOG_FILE_FULL_NAME+1];
    int          i;

    for (i = fac->filenumber; i < NST_LOG_MAX_FILE_NUMBER; i++) {
        FILE      * fp;

        nst_log_get_filename (fac, &fac->conf, n, sizeof(n), i);

        fp = fopen (n, "r");
        if (fp == NULL)
            break;

        fclose (fp);
    }

    i = (i == NST_LOG_MAX_FILE_NUMBER) ? 0 : i;
    nst_log_get_filename (fac, &fac->conf, n, sizeof(n), i);
    fac->fp = fopen (n, "w+");

    if (fac->fp == NULL) {
        fprintf (stderr, "Failed to open log file=%s, error=%s(%d)\n",
                 n, strerror(errno), errno);
        return NST_LOG_ERROR_OPEN;
    }

    fac->filenumber = i;

    return NST_LOG_OK;
}

static nst_log_status_t
nst_log_close_file (nst_log_facility_t * fac)
{
    char   n [NST_LOG_FILE_FULL_NAME];

    fclose (fac->fp);
    fac->fp = NULL;

    nst_log_get_filename (fac, &fac->conf,
                          n, sizeof(n), fac->filenumber);

    chmod (n,  S_IROTH | S_IRGRP | S_IRUSR);

    return NST_LOG_OK;
}



static nst_log_status_t
nst_log_set_conf (nst_log_facility_t * fac, nst_log_conf_t * conf)
{
    nst_log_status_t          status;
    char                    * dname;

    if (fac->conf.dirname) {
        nst_xfree (fac->conf.dirname);
    }

    if (fac->fp != NULL) {
        fclose (fac->fp);
    }

    if (fac->fd > 0) {
        close (fac->fd);
    }

    fac->conf.flags.destfile = 1;
    fac->flags.nst_log_enabled = 0;

    dname = NST_DEFAULT_LOG_DIR;
    if (conf->dirname)
        dname = conf->dirname;
    fac->conf.dirname = (char *)nst_xstrdup ((u_char *)dname);
    NST_ASSERT(fac->conf.dirname != NULL);

    if (conf->ratelimit.messages_per_sec > 0) {
        fac->conf.ratelimit.messages_per_sec = conf->ratelimit.messages_per_sec;
    }

    if (conf->flush_count > 0)
        fac->conf.flush_count = conf->flush_count;

    if (conf->ratelimit.hits_ceiling > 0)
        fac->conf.ratelimit.hits_ceiling = conf->ratelimit.hits_ceiling;

    if (conf->ratelimit.time_ceiling > 0)
        fac->conf.ratelimit.time_ceiling = conf->ratelimit.time_ceiling;

    if (conf->ratelimit.rollover_time_interval > 0) {
        fac->conf.ratelimit.rollover_time_interval =
            conf->ratelimit.rollover_time_interval;
    }

        status = nst_log_open_file (fac);
        if (status != OK)
            goto error;
        fac->conf.flags.destfile = 1;
        fac->flags.nst_log_enabled = 1;

    if (conf->filesize > 0)
        fac->conf.filesize = conf->filesize;

    fac->conf.flags.config_done = 1;

    if (conf->level < NST_LOG_LEVEL_CRITICAL
        || conf->level > NST_LOG_LEVEL_VERBOSE) {
        fac->conf.level = NST_LOG_LEVEL_DEFAULT;
    } else {
        fac->conf.level = conf->level;
    }

    return NST_LOG_OK;

error:

    if (fac->fp)  {
        fclose (fac->fp);
        fac->fp = NULL;
    }
    if (fac->fd > 0)
        close (fac->fd);

    return status;
}


nst_log_facility_t *
nst_log_get_debug_facility ()
{
    return &nst_debug_logfac;
}


nst_log_facility_t *
nst_log_get_noc_facility ()
{
    return &nst_noc_logfac;
}

nst_log_facility_t *
nst_log_get_access_facility ()
{
    return &nst_access_logfac;
}

nst_log_facility_t *
nst_log_get_audit_facility ()
{
    return &nst_audit_logfac;
}

nst_log_status_t
nst_log_access_set_conf (nst_log_conf_t * conf)
{
    nst_log_status_t        status;

    status = nst_log_set_conf (&nst_access_logfac, conf);

    if (status != NST_LOG_OK) {
        return status;
    }

    return NST_LOG_OK;
}

nst_log_status_t
nst_log_audit_set_conf (nst_log_conf_t * conf)
{
    nst_log_status_t        status;

    status = nst_log_set_conf (&nst_audit_logfac, conf);
    if (status != OK) {
        return status;
    }
    return NST_LOG_OK;
}

nst_log_status_t
nst_log_noc_set_conf (nst_log_conf_t * conf)
{
    nst_log_status_t        status;

    status = nst_log_set_conf (&nst_noc_logfac, conf);
    if (status != NST_LOG_OK) {
        return status;
    }

    return NST_LOG_OK;
}

nst_log_status_t
nst_log_debug_set_conf (nst_log_conf_t * conf)
{
    nst_log_status_t        status;


    snprintf (nst_debug_logfac.name, NST_LOG_FACILITY_NAME_LEN, "%s",
              nst_log_facility_name (NST_LOG_TYPE_DEBUG));

    status = nst_log_set_conf (&nst_debug_logfac, conf);
    if (status != OK) {
        return status;
    }
    return NST_LOG_OK;
}

void
nst_log_enable_stderr(void)
{
    nst_log_set_stderr (&nst_access_logfac, 1);
    nst_log_set_stderr (&nst_debug_logfac, 1);
    nst_log_set_stderr (&nst_noc_logfac, 1);
    nst_log_set_stderr (&nst_audit_logfac, 1);
}

void
nst_log_disable_stderr(void)
{
    nst_log_set_stderr (&nst_access_logfac, 0);
    nst_log_set_stderr (&nst_debug_logfac, 0);
    nst_log_set_stderr (&nst_noc_logfac, 0);
    nst_log_set_stderr (&nst_audit_logfac, 0);
}

void
nst_log_set_level (nst_log_level_t l)
{
    nst_log_debug_set_level(l);
    nst_log_noc_set_level(l);
}

void
nst_log_debug_set_level (nst_log_level_t l)
{
    if (l >= NST_LOG_LEVEL_CRITICAL && l < NST_LOG_LEVEL_VERBOSE) {
        nst_debug_logfac.conf.level = l;
    }
    else {
        nst_debug_logfac.conf.level = NST_LOG_LEVEL_DEFAULT;
    }
}

void
nst_log_noc_set_level (nst_log_level_t l)
{

    if (l >= NST_LOG_LEVEL_CRITICAL && l < NST_LOG_LEVEL_VERBOSE) {
        nst_noc_logfac.conf.level = l;
    }
    else {
        nst_noc_logfac.conf.level = NST_LOG_LEVEL_DEFAULT;
    }
}

nst_log_status_t
nst_log_ratedup_checks (nst_log_facility_t * fac,
                        nst_log_conf_t * conf, nst_log_message_t * m)
{
    nst_log_status_t status = NST_LOG_STATUS_RL_LOG;

    if (conf->flags.simple_dup_check) {
        if (nst_log_ratelimit_simple_duplicate_check (fac, conf, m) ==
            NST_LOG_STATUS_RL_DUPLICATE) {
            dprintf ("Duplicate\n");
            return NST_LOG_STATUS_RL_DUPLICATE;
        }
    }

    if (conf->flags.ratelimit) {
        status = nst_log_ratelimit (fac, conf, m);
    }

    return status;
}

/*! nst_log_get_skip_len:  Gets the lenght to skip in the message. */
/*
 * This functions returns the timestamp length.
 */

int
nst_log_get_skip_len (nst_log_facility_type_t f, int len, char * str)
{
    int     i, clns = 1;

    switch (f) {
        case NST_LOG_TYPE_DEBUG:
        case NST_LOG_TYPE_NOC:
            if (str[0] == '!') {
                clns++;
            }

            for (i = 0; i < len; i++) {
                if (str[i] == ':') {
                    clns--;
                }
                if (clns == 0)
                    break;
            }

            if (clns != 0)
                i = -1;
            return (i+1);

        case NST_LOG_TYPE_ACCESS:
        case NST_LOG_TYPE_AUDIT:
        default:
            return 0;
    }

    return 0;
}
/*
static void
nst_fac_unix_connect (nst_log_facility_t * fac)
{
	struct sockaddr_un logunixpath;

    strncpy (logunixpath.sun_path, NST_LOG_UNIX_PATH,
             sizeof(logunixpath.sun_path));
    if (connect (fac->fd, (struct sockaddr *)&logunixpath,
                 sizeof(logunixpath)) == 0) {
		fac->flags.unix_connected = 1;
    }
}
*/

static nst_log_status_t
nst_fac_init (nst_log_facility_t * fac,
              nst_log_facility_type_t type,
              nst_log_level_t level,
              const char *agent,
              int stderr)
{

    NST_ASSERT (fac->inited != NST_LOG_INITED_SIGNATURE);

    fac->type = type;

    snprintf (fac->name, NST_LOG_FACILITY_NAME_LEN, "%s",
              nst_log_facility_name (type));

    /* Set the default values for the configuration */
    fac->conf.ratelimit.max_messages = NST_LOG_MAX_RATELIMIT_ENTRIES;

    fac->pool = nst_mempool_create ((char *)nst_log_facility_name (type),
                                    0,
                                    fac->conf.ratelimit.max_messages,
                                    NST_LOG_RATELIMIT_ENTRIES,
                                    NST_LOG_MSG_SIZE,
                                    0);
    if (fac->pool == NULL) {
        return NST_LOG_ERROR_POOL_CREATION;
    }

    NST_ASSERT(fac->conf.agent == NULL);
    fac->conf.agent = (char *) nst_xstrdup ((u_char *)agent);
    if(fac->conf.agent == NULL) {
        nst_mempool_destroy(fac->pool);
        fac->pool = NULL;
        return NST_LOG_ERROR_MALLOC;
    }
    fac->conf.logname = (char *)nst_xstrdup ((u_char *)agent);
    NST_ASSERT(fac->conf.logname != NULL);

    fac->conf.filesize = NST_LOG_DEFAULT_FILE_SIZE;
    fac->conf.flush_count = NST_LOG_DEFAULT_FLUSH_COUNT;

    fac->conf.ratelimit.messages_per_sec =
            NST_LOG_RATELIMIT_DEFAULT_MESSAGES_PER_SECOND;
    fac->conf.ratelimit.hits_ceiling = NST_LOG_RATELIMIT_DEFAULT_MAX_HITS;
    fac->conf.ratelimit.time_ceiling = NST_LOG_RATELIMIT_DEFAULT_MAX_SECONDS;
    fac->conf.ratelimit.rollover_time_interval =
        NST_LOG_RATELIMIT_DEFAULT_TIME_INTERVAL_SECONDS;


    fac->conf.level =  level;

    if (stderr) {
        fac->conf.flags.stderr = 1;
        fac->flags.nst_log_enabled = 1;
    }

    nst_log_ratelimit_table_init (&fac->rattab);

    fac->conf.flags.simple_dup_check = 1;
    fac->conf.flags.mid              = 1;
    fac->inited                      = NST_LOG_INITED_SIGNATURE;

	fac->fd = socket (AF_UNIX, SOCK_DGRAM, 0);
    NST_ASSERT(fac->fd > 0);
    fac->flags.nst_log_enabled = 1;

#if 0
    nst_fac_unix_connect (fac);
	fac->conf.flags.destunix = 1;
#endif

    return NST_LOG_OK;
}


static nst_log_status_t
nst_logit (nst_log_facility_t  * fac,
           nst_log_conf_t      * conf,
           nst_log_level_t       clevel,
           const char          * function,
           int                   line,
           nst_log_level_t       level,
           const char          * fmt,
           va_list               args)
{
    char                   * logstr, * str;
    int                      len;
    nst_log_message_t      * m;
    nst_log_status_t         status = NST_LOG_STATUS_RL_LOG;
    va_list                  dargs;

    fac->stats.messages_in++;
    m = nst_log_message_alloc (fac);
    if (m == NULL) {
        if (m == NULL) {
            return NST_LOG_ERROR_MALLOC;
        }
    }

    m->h.type = fac->type;
    m->h.level = level;

    logstr = m->logmsg;

    fac->mid++;
    m->id = fac->mid;

    len = 0;
    if (fac->type == NST_LOG_TYPE_DEBUG || fac->type == NST_LOG_TYPE_NOC) {
        nst_str_t cached_log_time;
        nst_uint_t msec;

        cached_log_time.data = nst_cached_log_time.data;
        msec = nst_cached_time->msec;
        cached_log_time.len = nst_cached_log_time.len;

        m->skip_len += cached_log_time.len + 4;

        /* time:agent:level:file.line:message */
        len += snprintf (logstr + len, m->bsize - len, "%s.%03lu: %s: %s: ",
                         cached_log_time.data, msec,
                         conf->agent, nst_log_level_name (level));
    }
    if (fac->type == NST_LOG_TYPE_DEBUG) {
        len += snprintf (logstr + len, m->bsize - len, "%s(%d): ",
                         function, line);
    }

    if ((fac->type == NST_LOG_TYPE_NOC) && (level <= NST_LOG_LEVEL_DEBUG) &&
        (nst_debug_logfac.flags.nst_log_enabled) && (level <= clevel)) {
        va_copy (dargs, args);
    }

    str = (char *)nst_vsnprintf ((u_char *)logstr+len, m->bsize - len,
                                 (const char *)fmt, args);
    len = str - logstr;
    len = nst_log_check_and_add_newline (len, m);

    m->h.len = len;


    if (conf->flags.stderr) {
        /* Special mode for debugging */
        nst_log_write_stderr (fac, conf, m);
    }

    status = nst_log_ratedup_checks (fac, conf, m);
    if (status == NST_LOG_STATUS_RL_LOG) {
        if (conf->flags.destfile && fac->fp) {
            nst_log_write_file (fac, conf, m);
        }

        if (conf->flags.destnet && fac->fd >= 0) {
            nst_log_write_net (fac, m);
        }

#if 0
        if (conf->flags.destunix) {
            if (fac->flags.unix_connected == 0)
                nst_fac_unix_connect (fac);
			if (fac->flags.unix_connected)
                nst_log_write_net (fac, m);
        }
#endif

        fac->stats.messages_logged++;
        status = NST_LOG_OK;
    }

    if ((fac->type == NST_LOG_TYPE_NOC) && (level <= NST_LOG_LEVEL_DEBUG) &&
        (nst_debug_logfac.flags.nst_log_enabled) && (level <= clevel)) {
        nst_logit (&nst_debug_logfac, conf, clevel, function,
                   line, level, fmt, dargs);
    }

    nst_log_message_free (fac, m);

    return status;
}

nst_log_status_t
nst_log_facility (nst_log_facility_t * fac, nst_log_level_t clevel,
                  const char * function, int line, nst_log_level_t level,
                  const char * fmt, ...)
{
    va_list                 args;
    nst_log_status_t        status;
    nst_log_conf_t        * conf;

    conf = &fac->conf;

    va_start(args, fmt);

    status = nst_logit (fac, conf, clevel, function, line, level, fmt, args);

    va_end (args);

    return status;
}

void
nst_log_fac_close (nst_log_facility_t * fac)
{

    fac->flags.nst_log_enabled = 0;

    if (fac->fp)
        fclose (fac->fp);
    if (fac->fd > 0)
        close (fac->fd);

    nst_log_ratelimit_free_entries (fac);
    nst_log_simple_duplicate_entries_free (fac);

    if (fac->pool)
        nst_mempool_destroy (fac->pool);
    fac->pool = NULL;

    nst_xfree (fac->conf.agent);
    nst_xfree (fac->conf.logname);
    nst_xfree (fac->conf.dirname);
    bzero (fac, sizeof(nst_log_facility_t));
}

nst_log_t  *
nst_log_init (const char *agent)
{
    nst_log_status_t        status;

    NST_ASSERT(nst_log_inited == 0);

    bzero (&nst_dl_logger, sizeof(nst_log_t));
    bzero (&nst_debug_logfac, sizeof(nst_log_facility_t));
    bzero (&nst_noc_logfac, sizeof(nst_log_facility_t));
    bzero (&nst_access_logfac, sizeof(nst_log_facility_t));
    bzero (&nst_audit_logfac, sizeof(nst_log_facility_t));

    status = nst_fac_init (&nst_debug_logfac, NST_LOG_TYPE_DEBUG,
                           NST_LOG_DEBUG_DEFAULT_LEVEL, agent, 0);
    if (status != NST_LOG_OK) {
        return NULL;
    }

    status = nst_fac_init (&nst_noc_logfac, NST_LOG_TYPE_NOC,
                           NST_LOG_NOC_DEFAULT_LEVEL, agent, 0);
    if (status != NST_LOG_OK) {
        nst_log_fac_close(&nst_debug_logfac);
        return NULL;
    }

    status = nst_fac_init (&nst_audit_logfac, NST_LOG_TYPE_AUDIT,
                           NST_LOG_AUDIT_DEFAULT_LEVEL, agent, 0);
    if (status != NST_LOG_OK) {
        nst_log_fac_close(&nst_debug_logfac);
        nst_log_fac_close(&nst_noc_logfac);
        return NULL;
    }

    status = nst_fac_init (&nst_access_logfac, NST_LOG_TYPE_ACCESS,
                           NST_LOG_AUDIT_DEFAULT_LEVEL, agent, 0);

    if (status != NST_LOG_OK) {
        nst_log_fac_close(&nst_debug_logfac);
        nst_log_fac_close(&nst_noc_logfac);
        nst_log_fac_close(&nst_audit_logfac);
        return NULL;
    }

    nst_dl_logger.fac = &nst_debug_logfac;
    nst_log_inited  = 1;

    return &nst_dl_logger;
}

void
nst_log_reset (void)
{
    nst_log_fac_close(&nst_debug_logfac);
    nst_log_fac_close(&nst_noc_logfac);
    nst_log_fac_close(&nst_access_logfac);
    nst_log_fac_close(&nst_audit_logfac);

    nst_log_inited  = 0;
}

void
nst_log_flush_fac (nst_log_facility_t  * fac)
{
    if (fac->flags.nst_log_enabled && fac->conf.flags.destfile && fac->fp) {
        fflush(fac->fp);
    }
}

void
nst_log_flush(void)
{
    size_t i;
    nst_log_facility_t *log_fac[] = {
        &nst_access_logfac,
        &nst_debug_logfac,
        &nst_noc_logfac,
        &nst_audit_logfac,
    };

    for(i = 0; i < sizeof(log_fac)/sizeof(log_fac[i]); i++) {
        nst_log_flush_fac (log_fac[i]);
    }
}
