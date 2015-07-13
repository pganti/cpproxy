#ifndef _NST_CPT_H
#define _NST_CPT_H

#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

struct nst_allocator_s;
struct nst_array_s;

typedef unsigned short cpt_score_t;

typedef struct cpt_node_s cpt_node_t;
typedef struct cpt_request_s cpt_request_t;
typedef struct cpt_log_s cpt_log_t;

typedef enum cpt_node_type_e cpt_node_type_e;
typedef enum cpt_sel_type_e cpt_sel_type_e;
typedef enum cpt_role_e cpt_role_e;
typedef enum cpt_request_type_e cpt_request_type_e;
typedef enum cpt_regular_log_level_e cpt_regular_log_level_e;
typedef enum cpt_debug_log_level_e cpt_debug_log_level_e;


#define CPT_SCORE_DOWN USHRT_MAX
#define CPT_SCORE_FILTERED USHRT_MAX - 1
#define CPT_SCORE_MAX (CPT_SCORE_FILTERED - 1)
#define CPT_SCORE_UNKNOWN CPT_SCORE_MAX
#define CPT_SCORE_MIN (1)

#define CPT_MAX_NUM_TRIES (3)

enum cpt_module_type_e
{
    CPT_MODULE_TYPE_UNKNOWN = -1,
    CPT_MODULE_TYPE_CORE_CPT = 0,
    CPT_MODULE_TYPE_HTTP = 1,
    CPT_MODULE_TYPE_DNS = 2,
    CPT_MODULE_TYPE_NUM = 3,
};

enum cpt_debug_log_level_e 
{
    CPT_DEBUG_LOG_LEVEL_OFF = -2,
    CPT_DEBUG_LOG_LEVEL_UNKNOWN = -1,
    CPT_DEBUG_LOG_LEVEL_1 = 0,
    CPT_DEBUG_LOG_LEVEL_2 = 1,
    CPT_DEBUG_LOG_LEVEL_3 = 2,
    CPT_DEBUG_LOG_LEVEL_DEFAULT = CPT_DEBUG_LOG_LEVEL_3,
    CPT_DEBUG_LOG_LEVEL_4 = 4,
    CPT_DEBUG_LOG_LEVEL_NUM = 5,
};

enum cpt_regular_log_level_e
{
    CPT_REGULAR_LOG_LEVEL_UNKNOWN = -1,
    CPT_REGULAR_LOG_LEVEL_CRITICAL = 0,
    CPT_REGULAR_LOG_LEVEL_ERROR = 1,
    CPT_REGULAR_LOG_LEVEL_INFO = 2,
    CPT_REGULAR_LOG_LEVEL_DEFAULT = CPT_REGULAR_LOG_LEVEL_INFO,
    CPT_REGULAR_LOG_LEVEL_DETAILS = 3,
    CPT_REGULAR_LOG_LEVEL_NUM = 4,
};

struct cpt_log_s
{
    cpt_regular_log_level_e regular_log_level;
    cpt_debug_log_level_e debug_log_level;
    void (*regular_log)(const char *fmt, va_list va);
    void (*debug_log)(const char *fmt, va_list va);
};

enum cpt_node_type_e
{
    CPT_NODE_TYPE_UNKNOWN = -1,
    CPT_NODE_TYPE_INTERNAL = 0,
    CPT_NODE_TYPE_MAPPED_CPC = 1,
    CPT_NODE_TYPE_FORCE_CPC = 2,
    CPT_NODE_TYPE_CACHE = 3,
    CPT_NODE_TYPE_SPC = 4,
    CPT_NODE_TYPE_INTERMEDIATE_SPC = 5,
    CPT_NODE_TYPE_OS = 6,
    CPT_NODE_TYPE_OS_IP = 7,
    CPT_NODE_TYPE_OS_HOSTNAME = 8,
    CPT_NODE_TYPE_NUM = 7,
};

enum cpt_sel_type_e 
{
    CPT_SEL_TYPE_UNKNOWN = -1,
    CPT_SEL_TYPE_SCORE = 0,
    CPT_SEL_TYPE_FIRST = 1,
    CPT_SEL_TYPE_RANDOM = 2,
    CPT_SEL_TYPE_END_USER_IP_HASH = 3,
    _CPT_SEL_TYPE_NUM = 4,
};


enum cpt_request_type_e
{
    CPT_REQ_TYPE_UNKNOWN = -1,
    CPT_REQ_TYPE_DNS = 0,
    CPT_REQ_TYPE_HTTP = 1,
    _CPT_REQ_TYPE_NUM = 2,
};

struct cpt_node_s
{
    cpt_node_type_e type;
    cpt_sel_type_e sel_type;
    struct nst_array_s *children;
    cpt_score_t score;
    /* Each module can have its own config. */ 
    void *data;
};

#define DECLARE_CPT_REQUEST(type) \
    cpt_request_type_e req_type:CPT_REQ_TYPE_UNKNOWN; \
    unsigned char cur_depth:0;     \
    const cpt_node_t *last_tried_nodes[CPT_MAX_NUM_TRIES];   \
    size_t ntried:0; \
    cpt_regular_log_level_e regular_log_level: CPT_REGULAR_LOG_LEVEL_DEFAULT; \
    cpt_debug_log_level_e debug_log_level: CPT_DEBUG_LOG_LEVEL_DEFAULT; \
    void (*debug_log)(const cpt_request_t *request);

struct cpt_request_s
{
    cpt_request_type_e req_type;
    unsigned char cur_depth;
    const cpt_node_t *last_tried_nodes[CPT_MAX_NUM_TRIES];
    size_t ntried;
    cpt_regular_log_level_e regular_log_level;
    cpt_debug_log_level_e debug_log_level;
    void (*debug_log)(const cpt_request_t *request);
};

void cpt_init(const struct nst_allocator_s *allocator,
              const cpt_log_t *log);

#endif
