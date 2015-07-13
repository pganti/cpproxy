#ifndef _NST_CPT_NODE_H_
#define _NST_CPT_NODE_H_


#include <nst_log.h>
#include <nst_types.h>

#include <limits.h>
#include <unistd.h>

#define CPT_NODE_TAG "node"

#define NST_CPT_NODE_SCORE_DOWN_BY_TRIED      (300 - 1)
#define NST_CPT_NODE_SCORE_DOWN_BY_APP_FILTERED (300-2)
#define NST_CPT_NODE_SCORE_DOWN_BY_FILTERED   (300 - 3)

#define NST_CPT_NODE_SCORE_DOWN_BY_UNKNOWN    (0 + 4096)
#define NST_CPT_NODE_SCORE_DOWN_BY_NO_CHILD   (0 + 4095)
#define NST_CPT_NODE_SCORE_DOWN_BY_CFG_SCORE  (0 + 4094)
#define NST_CPT_NODE_SCORE_DOWN_BY_SVC        (0 + 4)
#define NST_CPT_NODE_SCORE_DOWN_BY_NO_SPC     (0 + 3)
#define NST_CPT_NODE_SCORE_DOWN_BY_RTT        (0 + 2)
#define NST_CPT_NODE_SCORE_DOWN_BY_HC         (0 + 1)
#define NST_CPT_NODE_SCORE_MAX                (1024 - 1)
#define NST_CPT_NODE_SCORE_MIN                (1)

typedef u32 nst_cpt_node_score_t;

typedef enum nst_cpt_node_type_e nst_cpt_node_type_e;
typedef enum nst_cpt_node_sel_type_e nst_cpt_node_sel_type_e;
typedef struct nst_cpt_node_s nst_cpt_node_t;
typedef struct nst_cpt_node_ops_s nst_cpt_node_ops_t;

typedef nst_status_e (*nst_cpt_node_set_data_f)(nst_cpt_node_t *);
typedef void (*nst_cpt_node_free_data_f)(nst_cpt_node_t *node);
typedef void (*nst_cpt_node_reg_log_f)(const nst_cpt_node_t *,
                                       nst_log_level_t ovr_lvl,
                                       nst_log_level_t msg_lvl,
                                       size_t tree_depth);
typedef void (*nst_cpt_node_eval_reg_log_f)(const nst_cpt_node_t *,
                                       const nst_cpt_node_t *,
                                       nst_cpt_node_score_t score,
                                       nst_log_level_t ovr_lvl,
                                       nst_log_level_t msg_lvl,
                                       size_t tree_depth);
typedef nst_cpt_node_score_t (*nst_cpt_node_get_score_f)(const nst_cpt_node_t *node);
typedef bool (*nst_cpt_node_is_valid_f)(const nst_cpt_node_t *node);
typedef nst_status_e (*nst_cpt_node_copy_cstor_f)(nst_cpt_node_t *dst_node,
                                         const nst_cpt_node_t *src_node);

enum nst_cpt_node_type_e
{
    NST_CPT_NODE_TYPE_UNKNOWN = 0,              /* NO ONE      */
    NST_CPT_NODE_TYPE_INTERNAL = 1,             /* dns & proxy */
    NST_CPT_NODE_TYPE_MAPPED_CPC = 2,           /* dns only    */
    NST_CPT_NODE_TYPE_FORCE_CPC = 3,            /* dns only    */
    NST_CPT_NODE_TYPE_CACHE = 4,                /* proxy only  */
    NST_CPT_NODE_TYPE_SPC = 5,                  /* proxy only  */
    NST_CPT_NODE_TYPE_INTERMEDIATE_SPC = 6,     /* proxy only  */
    NST_CPT_NODE_TYPE_OSITE = 7,                /* dns & proxy */
    NST_CPT_NODE_TYPE_OSRV = 8,                 /* dns & proxy */
    _NST_CPT_NODE_TYPE_NUM = 9,                 /* NO ONE      */
};

enum nst_cpt_node_sel_type_e 
{
    NST_CPT_NODE_SEL_TYPE_UNKNOWN = 0,
    NST_CPT_NODE_SEL_TYPE_SCORE = 1,
    NST_CPT_NODE_SEL_TYPE_FIRST = 2,
    NST_CPT_NODE_SEL_TYPE_RANDOM = 3,
    NST_CPT_NODE_SEL_TYPE_END_USER_IP_HASH = 4,
    _NST_CPT_NODE_SEL_TYPE_NUM = 5,
};

struct nst_cpt_node_ops_s
{
    nst_cpt_node_set_data_f set_data;
    nst_cpt_node_free_data_f free_data;
    nst_cpt_node_copy_cstor_f copy_cstor;
    nst_cpt_node_reg_log_f reg_log;
    nst_cpt_node_eval_reg_log_f eval_reg_log;
    nst_cpt_node_get_score_f get_score;
    nst_cpt_node_is_valid_f is_valid;
};

struct nst_cpt_node_s
{
    nst_cpt_node_type_e type;
    char *name;
    nst_cpt_node_sel_type_e sel_type;
    struct nst_vector_s *children;
    nst_cpt_node_score_t score_from_cfg;
    nst_cpt_node_score_t score;
    /* Each module can have its own config. */ 
    nst_cpt_node_t *ref_node;
    void *data;
};

void nst_cpt_node_init(void);

nst_status_e
nst_cpt_node_set_type(nst_cpt_node_t *node,
                      nst_cpt_node_type_e type);

nst_cpt_node_t *
nst_cpt_node_new(void);

void nst_cpt_node_free(nst_cpt_node_t *node);
void nst_cpt_node_vec_free(nst_cpt_node_t **node);
nst_cpt_node_t *nst_cpt_node_copy_cstor(const nst_cpt_node_t *src_node);


const char *nst_cpt_node_get_indent_str(size_t level);
void nst_cpt_node_reg_log(const nst_cpt_node_t *node,
                          nst_log_level_t ovr_lvl,
                          nst_log_level_t msg_lvl,
                          size_t tree_depth);
void nst_cpt_node_eval_reg_log(const nst_cpt_node_t *node,
                               const nst_cpt_node_t *picked_node,
                               nst_cpt_node_score_t score,
                               nst_log_level_t ovr_lvl,
                               nst_log_level_t msg_lvl,
                               size_t tree_depth);


nst_cpt_node_score_t nst_cpt_node_get_score(const nst_cpt_node_t *node);
void nst_cpt_node_set_score_from_cfg(nst_cpt_node_t *node,
                                     nst_cpt_node_score_t score_from_cfg);
void nst_cpt_node_get_score_str(const nst_cpt_node_t *node,
                           char *buf, size_t buf_size);
void nst_cpt_node_score_to_str(const nst_cpt_node_score_t score,
                               char *buf, size_t buf_size);




inline nst_cpt_node_type_e nst_cpt_node_get_type(const nst_cpt_node_t *node);
const char *nst_cpt_node_type_to_str(const nst_cpt_node_type_e type);
nst_cpt_node_type_e nst_cpt_node_type_from_str(const char *type_str);

void nst_cpt_node_set_sel_type(nst_cpt_node_t *node,
                               nst_cpt_node_sel_type_e sel_type);
nst_cpt_node_sel_type_e nst_cpt_node_get_sel_type(const nst_cpt_node_t *node);
const char * nst_cpt_node_sel_type_to_str(nst_cpt_node_sel_type_e sel_type);
nst_cpt_node_sel_type_e nst_cpt_node_sel_type_from_str(const char *sel_type_str);


int nst_cpt_unhandled_node_set_data(nst_cpt_node_t *node);
void nst_cpt_unhandled_node_free_data(nst_cpt_node_t *node);
nst_status_e nst_cpt_unhandled_node_copy_cstor(nst_cpt_node_t *dst_node,
                                               const nst_cpt_node_t *src_node);
void nst_cpt_unhandled_node_reg_log(const nst_cpt_node_t *node,
                                    nst_log_level_t ovr_lvl,
                                    nst_log_level_t msg_lvl,
                                    size_t tree_depth);
void nst_cpt_unhandled_node_eval_reg_log(const nst_cpt_node_t *node,
                                         const nst_cpt_node_t *picked_child,
                                         nst_cpt_node_score_t score,
                                         nst_log_level_t ovr_lvl,
                                         nst_log_level_t msg_lvl,
                                         size_t tree_depth);
nst_cpt_node_score_t
nst_cpt_unhandled_node_get_score(const nst_cpt_node_t *node);
bool nst_cpt_unhandled_node_is_valid(const nst_cpt_node_t *node);


#if 0
void nst_cpt_node_set_ref(nst_cpt_node_t *node, nst_cpt_node_t *ref_node);
const nst_cpt_node_t *nst_cpt_node_get_ref(const nst_cpt_node_t *node);
#endif
const char *nst_cpt_node_get_name(const nst_cpt_node_t *node);

int nst_cpt_node_set_name(nst_cpt_node_t *node, const char *name, int name_len);

bool nst_cpt_node_is_valid(const nst_cpt_node_t *node);

#endif
