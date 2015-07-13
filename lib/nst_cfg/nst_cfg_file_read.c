/* include myself */
#include "nst_cfg_file_read.h"

/* libnst_cfg includes */
#include <nst_cfg_diff_data.h>
#include <nst_cfg_common.h>

/* libnst_log includes */
#include <nst_log.h>

/* libcore includes */
#include <nst_genhash.h>
#include <nst_limits.h>
#include <nst_string.h>
#include <nst_errno.h>
#include <nst_assert.h>

/* std an sys includes */
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>

static void root_start_handler(void *udata, 
                   const XML_Char *name,
                   const XML_Char **attrs);
static void root_end_handler(void *udata, const XML_Char *name);
static void root_char_handler(void *udata, const XML_Char *s, int len);

static nst_expat_stack_frame_t expat_stack_bottom;

static nst_expat_stack_frame_t *expat_stack_top = &expat_stack_bottom;

extern XML_Parser parser;

static void
expat_stack_bottom_init(nst_cfg_file_read_ctx_t *rf_ctx)
{
    nst_memzero(&expat_stack_bottom, sizeof(expat_stack_bottom));
    
    expat_stack_bottom.parser = parser;
    expat_stack_bottom.start_handler = root_start_handler;
    expat_stack_bottom.end_handler = root_end_handler;
    expat_stack_bottom.char_handler = root_char_handler;
    expat_stack_bottom.child_ret = NST_ERROR;
    expat_stack_bottom.skip_on_error = FALSE;
    expat_stack_bottom.data = rf_ctx;
}

static nst_status_e
parser_init(void)
{
    if(!parser) {
        parser = XML_ParserCreate(NULL);
        if(!parser) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot create XML_Parser object");
            return NST_ERROR;
        }
    }

    XML_SetStartElementHandler(parser, root_start_handler);
    XML_SetEndElementHandler(parser, root_end_handler);
    XML_SetCharacterDataHandler(parser, root_char_handler);
    XML_SetUserData(parser, (void*)&expat_stack_top);
    
    return NST_OK;
}

static void
root_start_handler(void *udata, 
                   const XML_Char *name,
                   const XML_Char **attrs)
{
    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &expat_stack_bottom) {
        nst_assert(current->start_handler);
        nst_assert(current->end_handler);
        current->start_handler(udata, name, attrs);
    } else {
        nst_cfg_file_read_ctx_t *rf_ctx = 
            (nst_cfg_file_read_ctx_t *)current->data;
        if(strcmp(rf_ctx->entity_start_tag, name)) {
            /* upexpected start tag */
            XML_StopParser(current->parser, XML_FALSE);
        } else {
            rf_ctx->capture(udata, name, attrs,
                            rf_ctx->capture_data0, rf_ctx->capture_data1,
                            rf_ctx->capture_data2, rf_ctx->capture_data3);
        }
    }
}

static void
root_end_handler(void *udata, const XML_Char *name)
{

    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &expat_stack_bottom) {
        nst_assert(current->start_handler);
        nst_assert(current->end_handler);
        current->end_handler(udata, name);
    } else {
        nst_cfg_file_read_ctx_t *rf_ctx = 
            (nst_cfg_file_read_ctx_t *)current->data;
        if(strcmp(rf_ctx->entity_start_tag, name)) {
            XML_StopParser(current->parser, XML_FALSE);
        } else if(current->child_ret == NST_ERROR) {
            XML_StopParser(current->parser, XML_FALSE);
        } else if(rf_ctx->done_cb
                  && rf_ctx->done_cb(rf_ctx) == NST_ERROR) {
            XML_StopParser(current->parser, XML_FALSE);
        }   
    }
}

static void
root_char_handler(void *udata, const XML_Char *s, int len)
{
   nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &expat_stack_bottom && current->char_handler) {
        current->char_handler(udata, s, len);
    }
}


nst_status_e
nst_cfg_file_read(const char *full_filename,
                  nst_cfg_file_read_ctx_t *rf_ctx)
{
    int fd = -1;
    ssize_t nread;
    char buf[4096];
    nst_status_e ret = NST_OK;

    fd = open(full_filename, O_RDONLY);
    if(fd == -1) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot open config file %s, %s(%d)",
                    full_filename,
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    if(parser_init() == NST_ERROR) {
        ret = NST_ERROR;
        goto DONE;
    }

    expat_stack_bottom_init(rf_ctx);

    NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                  "reading config file \"%s\"",
                  full_filename);

    while(TRUE) {
        enum XML_Status xml_status;
        nread = read(fd, buf, sizeof(buf));

        if(nread == -1) {
            if(errno == EINTR) {
                continue;
            } else {
                NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                            "error reading config file %s. %s(%d)",
                            full_filename,
                            nst_strerror(errno), errno);
                ret = NST_ERROR;
                goto DONE;
            }
        } 

        xml_status = XML_Parse(parser, buf, nread, (size_t)nread < sizeof(buf));

        if(xml_status != XML_STATUS_OK) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "XML parsing file %s failed at line %ud. %s\n",
                        full_filename,
                        XML_GetCurrentLineNumber(parser),
                        XML_ErrorString(XML_GetErrorCode(parser)));
            ret = NST_ERROR;
            goto DONE;
        }
        if((size_t)nread < sizeof(buf))
            break;
    }

 DONE:
    if(parser) {
        if(XML_ParserReset(parser, NULL) != XML_TRUE) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot reset XML_Parser object for reuse. %s",
                        XML_ErrorString(XML_GetErrorCode(parser)));
            XML_ParserFree(parser);
            parser = NULL; /* recreate it next time */
        }
    }

    if(fd != -1) {
        while(close(fd) == -1 && errno == EINTR) {}
    }

    return ret;
}

nst_status_e nst_cfg_dir_read(const char *full_dir_name,
                              nst_genhash_t *fn_ghash)
{
    DIR *dir;
    struct dirent entry;
    struct dirent *result;
    nst_cfg_diff_data_t *diff_data;
    nst_status_e ret = NST_OK;

    dir = opendir(full_dir_name);
    if(!dir) {
        NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                    "cannot open config dir %s. %s(%d)",
                    full_dir_name,
                    nst_strerror(errno), errno);
        return NST_ERROR;
    }

    for(readdir_r(dir, &entry, &result);
        result;
        readdir_r(dir, &entry, &result)) {
        size_t filename_len = strlen(entry.d_name);

        if(filename_len < NST_CFG_FILENAME_EXT_LEN
           || strcmp(entry.d_name + filename_len - NST_CFG_FILENAME_EXT_LEN,
                     NST_CFG_FILENAME_EXT)
           || entry.d_name[0] == '.') {
            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                        "ignore file \"%s\"",
                        entry.d_name);
            continue;
        }

        /* +4 for ".xml" */
        filename_len -= NST_CFG_FILENAME_EXT_LEN;
        if(filename_len  + 1 > sizeof(((nst_cfg_diff_data_t *)0)->name)) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_ERROR,
                        "%s/%s has filename length > %u. ignored",
                        full_dir_name, entry.d_name,
                        NST_MAX_CFG_NAME_ELT_BUF_SIZE + 4 - 1);
            ret = NST_ERROR;
            continue;
        }

        /* +1 for '/'. +1 for '\0' */
        diff_data = nst_allocator_calloc(&nst_cfg_allocator,
                                         1,
                                         sizeof(nst_cfg_diff_data_t));
        if(!diff_data) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot create nst_cfg_diff_data_t object. %s(%d)",
                        nst_strerror(errno), errno);
            ret = NST_ERROR;
            goto DONE;
        }

        memcpy(diff_data->name, entry.d_name, filename_len);
        diff_data->name[filename_len] = '\0';
        if(nst_genhash_add(fn_ghash, diff_data->name, diff_data) == NST_OK) {
            NST_DEBUG_LOG(NST_LOG_LEVEL_DEBUG,
                          "added filename \"%s%s\" to hash",
                          diff_data->name,
                          NST_CFG_FILENAME_EXT);
        } else if(errno == EEXIST) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "duplicate config file \"%s%s\" found",
                        diff_data->name,
                        NST_CFG_FILENAME_EXT);
            nst_assert(0 && "duplicate config file found when reading dir");
            ret = NST_ERROR;
        } else {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR,
                        "cannot add config file \"%s%s\" found. %s(%d)",
                        diff_data->name,
                        NST_CFG_FILENAME_EXT,
                        nst_strerror(errno), errno);
            ret = NST_ERROR;
            goto DONE;
        }
    }

 DONE:
    
    closedir(dir);
    return ret;
}
