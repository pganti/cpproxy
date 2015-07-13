#ifndef _NST_LOG_H_
#define _NST_LOG_H_

#include <nst_config.h>
#include <queue.h>
#include <nst_types.h>

#include <arpa/inet.h>
#include <stdio.h>

struct mempool; /* pronto caching memory pool */

#define NST_LOG_UNIX_PATH          "/var/log/pronto"
#define NST_LOG_DIRNAME_LEN        (2048)
#define NST_LOG_AGENT_NAME_LEN     (32)
#define NST_LOG_FAC_NAME_LEN       (32)

#define NST_LOG_INITED_SIGNATURE     (('M' << 24) | ('L' << 16) | ('O' << 8) | 'O')

#define NST_LOG_MAX_RATELIMIT_ENTRIES (2000)
#define NST_LOG_MAX_SRC_FILE_NAME     (256)

#define NST_LOG_INFO_LEN              (100)
#define NST_LOG_MSG_SIZE              (1024 * 4)
//#define NST_LOG_MAX_LINE_LEN          (NST_LOG_INFO_LEN - (1024 * 4))

#define NST_LOG_MAX_FILE_NUMBER      (1024 * 10)
#define NST_LOG_FILE_NAME_MAX        (1024)
#define NST_LOG_DIR_NAME_MAX         (1024 * 2)
#define NST_LOG_FILE_FULL_NAME       (NST_LOG_FILE_NAME_MAX + NST_LOG_DIR_NAME_MAX + 1024)
#define NST_LOG_FACILITY_NAME_LEN    (64)
#define NST_LOG_DEFAULT_FLUSH_COUNT  (100)

#define NST_LOG_LEVEL_DEFAULT        (NST_LOG_LEVEL_INFO)
#define NST_LOG_DEBUG_DEFAULT_LEVEL  (NST_LOG_LEVEL_DEBUG)
#define NST_LOG_NOC_DEFAULT_LEVEL    (NST_LOG_LEVEL_INFO)
#define NST_LOG_ACCESS_DEFAULT_LEVEL (NST_LOG_LEVEL_CRITICAL)
#define NST_LOG_AUDIT_DEFAULT_LEVEL (NST_LOG_LEVEL_INFO)

#define NST_LOG_DEFAULT_FILE_SIZE                         (1024 * 1024 * 1024 * 1)
#define NST_LOG_RATELIMIT_DEFAULT_MESSAGES_PER_SECOND     (100)
#define LOGD_RATELIMIT_DEFAULT_MESSAGES_PER_SECOND        (1000)
#define NST_LOG_RATELIMIT_ENTRIES                         (128)

#define NST_LOG_RATELIMIT_DEFAULT_TIME_INTERVAL_SECONDS   (1)
#define NST_LOG_RATELIMIT_DEFAULT_MAX_HITS                (100)
#define NST_LOG_RATELIMIT_DEFAULT_MAX_SECONDS             (5*60)

#define NST_LOG_PRUNE_QLEN_LEN                        (20)

typedef enum {
    NST_LOG_OK,
    NST_LOG_ERROR_FILE_NAME_SIZE            = -1,
    NST_LOG_ERROR_DIR_NAME_SIZE             = -2,
    NST_LOG_ERROR_OPEN                      = -3,
    NST_LOG_ERROR_SOCKET_OPEN               = -4,
    NST_LOG_ERROR_NAME_RESOLUTION           = -5,
    NST_LOG_ERROR_FACILITY                  = -6,
    NST_LOG_ERROR_POOL_CREATION             = -7,
    NST_LOG_ERROR_MALLOC                    = -8,
    NST_LOG_STATUS_RL_LOG                   = -9,
    NST_LOG_STATUS_RL_RATELIMITED           = -10,
    NST_LOG_STATUS_RL_DUPLICATE             = -12,
    NST_LOG_STATUS_INVALID_MESSAGE          = -13,
} nst_log_status_t;

typedef enum nst_log_facility_type {
    NST_LOG_TYPE_NOC = 1,
    NST_LOG_TYPE_ACCESS,
    NST_LOG_TYPE_DEBUG,
    NST_LOG_TYPE_AUDIT,
    NST_LOG_TYPE_MAX = NST_LOG_TYPE_AUDIT,
} nst_log_facility_type_t;

typedef enum nst_log_level {
    NST_LOG_LEVEL_START = 0,
    NST_LOG_LEVEL_STDERR = NST_LOG_LEVEL_START,
    NST_LOG_LEVEL_CRITICAL,
    NST_LOG_LEVEL_ERROR,
    NST_LOG_LEVEL_NOTICE,
    NST_LOG_LEVEL_INFO,
    NST_LOG_LEVEL_DEBUG,
    NST_LOG_LEVEL_VERBOSE,
    NST_LOG_LEVEL_END
} nst_log_level_t;

typedef struct nst_log_hdr {
    u8               type;      /* Type of the  log  - 256 types */
    u8               level;     /* Level of the message - 256 levels */
    u16              len;       /* Length of message excluding this header */
    /*char             facility [NST_LOG_FAC_NAME_LEN];
      char             agent [NST_LOG_AGENT_NAME_LEN];*/
} nst_log_hdr_t;

struct nst_log_message;
typedef struct nst_log_message {
    u16                       skip_len;
    short                     refcount;
    u32                       id;
    short                     hits;
    short                     ohits;
    struct timeval            createdtv;
    nst_log_hdr_t             h;
    u16                       bsize;
    char                    * logmsg;  /* Log message */
    TAILQ_ENTRY(nst_log_message)  next;
    char                      buf [];
} nst_log_message_t;


typedef struct nst_log_conf {
    char             * dirname;
    char             * logname;
    char             * agent;
    int                filesize;
    u32                flush_count;
    char	           logserver[NST_MAXHOSTNAMELEN+1];
    short	           logserver_port;
    nst_log_level_t    level;

    struct {
        short              hits_ceiling;
        u32                time_ceiling;   /* In seconds */
        u32                rollover_time_interval;   /* In seconds */
        u32                messages_per_sec;
        u32                bandwidth_per_sec;
        u32                max_messages;
    } ratelimit;

    struct {
        int            email:1;
        int            ratelimit:1;
        int            destfile:1;
        int            destunix:1;
        int            stderr:1;
        int            destnet:1;
        int            mid:1;
        int            simple_dup_check:1;
        int            config_done:1;
    } flags;

} nst_log_conf_t;

#define NST_LOG_RATELIMIT_ALPHA_QUEUE_LEN (256)

typedef struct nst_log_ratelimit_queue {
    TAILQ_HEAD(mq, nst_log_message)    msgq;
    int                             len;
} nst_log_ratelimit_queue_t;

typedef struct nst_log_ratelimit_table {
    struct {
        u64                 duplicates;
        u64                 ratelimited;
        u64                 total_logged;
    } stats;

    struct timeval          time_interval_lasttv;
    u32                     logged;

    nst_log_message_t          * duplicates [NST_LOG_LEVEL_END];
    nst_log_ratelimit_queue_t    level_queues [NST_LOG_LEVEL_END][NST_LOG_RATELIMIT_ALPHA_QUEUE_LEN];

    struct {
        int                 timelimited:1;
        int                 sizelimited:1;
    } flags;
} nst_log_ratelimit_table_t;



struct nst_log_facility {
    u32                         inited;
    nst_log_facility_type_t     type;
    char                        name [NST_LOG_FACILITY_NAME_LEN];
    int                         filenumber;
    FILE                      * fp;
    int                         fd;
    struct sockaddr_in          sin;

    struct mempool             * pool;
    nst_log_ratelimit_table_t   rattab;

    nst_log_conf_t              conf;

    u32                         mid;

    struct {
        u64                     messages_in;
        u64                     messages_logged;
        u64                     hd_logged;
        int                     net_logged;
        int                     messages_inuse;
    }stats;

    struct {
        int                 nst_log_enabled:1;
        int                 unix_connected:1;
    } flags;

};

typedef struct nst_log_facility nst_log_facility_t;

static inline int nst_log_is_level_valid (nst_log_level_t level)
{
    switch (level) {
        case NST_LOG_LEVEL_CRITICAL:
        case NST_LOG_LEVEL_ERROR:
        case NST_LOG_LEVEL_NOTICE:
        case NST_LOG_LEVEL_INFO:
        case NST_LOG_LEVEL_DEBUG:
        case NST_LOG_LEVEL_VERBOSE:
            return OK;
        default:
            return ERROR;
    }
    return ERROR;
}

static inline int nst_log_is_facility_valid (nst_log_facility_type_t f)
{
    switch (f) {
        case NST_LOG_TYPE_NOC:
        case NST_LOG_TYPE_ACCESS:
        case NST_LOG_TYPE_DEBUG:
            return OK;
        default:
            return ERROR;
    }
    return ERROR;
}

static inline int nst_log_get_max_line_len (void);
static inline int nst_log_get_max_line_len ()
{
    return (NST_LOG_MSG_SIZE -
            (sizeof(nst_log_message_t) + sizeof(nst_log_hdr_t) + NST_LOG_INFO_LEN));
}

static inline char * nst_log_message_getfromhdr (nst_log_message_t * m)
{
    char  *  str;

    str = m->buf + NST_LOG_INFO_LEN;

    return str;
}


static inline u32
nst_log_pack_hdr (nst_log_facility_type_t type, nst_log_level_t level, u16 len)
{
    u32 l, t;

    l = (((type << 24) | (level << 16) | (len)) & 0xffffffff);

    t = htonl(l);

    return t;
}

static inline void
nst_log_unpack_hdr (u32 l, nst_log_hdr_t * hdr)
{
    l = ntohl(l);

    hdr->len = l & 0xffff;
    hdr->level = (l >> 16) & 0xff;
    hdr->type = (l >> 24) & 0xff;
}

static inline void
nst_log_set_stderr (nst_log_facility_t * fac, int on)
{
    if (on) {
        fac->conf.flags.stderr = 1;
        fac->flags.nst_log_enabled = 1;
    }
    else {
        fac->conf.flags.stderr = 0;
        if (fac->conf.flags.destnet == 0 && fac->conf.flags.destfile == 0)
            fac->flags.nst_log_enabled = 0;
    }
}

#define NST_ACCESS_LOG(args...) do {                                    \
    NST_LOG(&nst_access_logfac, NST_LOG_LEVEL_CRITICAL,  \
            __FUNCTION__, __LINE__, nst_access_logfac.conf.level, args); \
 } while (0)

#define NST_AUDIT_LOG(args...) do {                                     \
    NST_LOG(&nst_audit_logfac,  nst_audit_logfac.conf.level,            \
            __FUNCTION__,  __LINE__, NST_LOG_LEVEL_CRITICAL, args);     \
 } while (0)

#define NST_NOC_LOG(lvl, args...) do {                                  \
    NST_LOG(&nst_noc_logfac, nst_noc_logfac.conf.level,                 \
            __FUNCTION__,  __LINE__, lvl, args);                         \
 } while(0)

#define NST_NOC_LOG_OV(clvl, lvl, args...) do {                         \
    NST_LOG(&nst_noc_logfac, clvl, __FUNCTION__, __LINE__, lvl, args);  \
 } while(0)

#define NST_DEBUG_LOG(lvl, args...) do {                                \
    NST_LOG(&nst_debug_logfac, nst_debug_logfac.conf.level,             \
            __FUNCTION__, __LINE__, lvl, args);                         \
 } while (0)

#define NST_DEBUG_LOG_OV(clvl, lvl, args...)  do {                  \
    NST_LOG(&nst_debug_logfac, clvl, __FUNCTION__, __LINE__, lvl, args); \
} while (0)


#define NST_LOG(__logfac, clvl, __func, __line, lvl, args...)  do {     \
    if ((__logfac)->flags.nst_log_enabled) {                            \
        nst_log_level_t elvl;                                           \
        elvl = ((__logfac)->conf.level < (clvl) ? (clvl) : (__logfac)->conf.level); \
        if((lvl) <= (elvl)) {                                           \
            nst_log_facility((__logfac), (elvl), __func, __line, (lvl), args); \
        }                                                               \
    }                                                                   \
 } while (0)


extern nst_log_facility_t      nst_access_logfac;
extern nst_log_facility_t      nst_debug_logfac;
extern nst_log_facility_t      nst_noc_logfac;
extern nst_log_facility_t      nst_audit_logfac;

extern nst_log_status_t nst_log_access_set_conf (nst_log_conf_t * conf);
extern nst_log_status_t nst_log_noc_set_conf (nst_log_conf_t * conf);
extern nst_log_status_t nst_log_debug_set_conf (nst_log_conf_t * conf);
extern nst_log_status_t nst_log_audit_set_conf (nst_log_conf_t * conf);

extern nst_log_status_t nst_log_facility (nst_log_facility_t * fac, nst_log_level_t clevel, const char * function, int line, nst_log_level_t level, const char * fmt, ...);

extern const char * nst_log_facility_name (nst_log_facility_type_t t);
extern const char * nst_log_level_name (nst_log_level_t l);
extern int nst_log_time_str (char * str, int len);

extern void nst_log_enable_stderr (void);
extern void nst_log_disable_stderr (void);

extern void nst_log_set_level (nst_log_level_t l);
extern void nst_log_debug_set_level (nst_log_level_t l);
extern void nst_log_noc_set_level (nst_log_level_t l);
extern nst_log_facility_t * nst_log_get_facility (nst_log_facility_type_t f);
extern nst_log_message_t * nst_log_message_alloc (nst_log_facility_t * fac);
extern void nst_log_message_free (nst_log_facility_t * fac, nst_log_message_t * m);
extern void nst_log_message_takeref (nst_log_message_t * m);
nst_log_status_t nst_log_ratedup_checks (nst_log_facility_t * fac, nst_log_conf_t * conf, nst_log_message_t * m);
extern void nst_log_write_file (nst_log_facility_t * fac, nst_log_conf_t * conf, nst_log_message_t * m);
extern int nst_log_get_skip_len (nst_log_facility_type_t f, int len, char * str);
extern void nst_log_flush(void);
extern void nst_log_flush_fac (nst_log_facility_t  * fac);

nst_log_facility_t * nst_log_get_debug_facility (void);
nst_log_facility_t * nst_log_get_noc_facility (void);
nst_log_facility_t * nst_log_get_audit_facility ();
nst_log_status_t nst_log_access_set_conf (nst_log_conf_t * conf);
void nst_log_fac_close (nst_log_facility_t * fac);

static inline bool
nst_noc_log_level_test_ml(nst_log_level_t ovr_lvl, nst_log_level_t msg_lvl)
{
    return (nst_noc_logfac.conf.level >= msg_lvl || ovr_lvl >= msg_lvl);
}

static inline bool
nst_debug_log_level_test_ml(nst_log_level_t ovr_lvl, nst_log_level_t msg_lvl)
{
    return (nst_debug_logfac.conf.level >= msg_lvl || ovr_lvl >= msg_lvl);
}

#include <nst_log_debug.h>

#endif /*_NST_LOG_H_*/
