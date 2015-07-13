#include "nst_allocator.h"
#include "nst_mem_stat_allocator.h"
#include "nst_limits.h"
#include "nst_cfg_common.h"
#include "nst_cfg_elt_data.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

static void root_start_handler(void *udata, 
                               const XML_Char *name, const XML_Char **atts);
static void root_end_handler(void *udata, const XML_Char *name);
static void root_char_handler(void *udata, const XML_Char *s, int len);

static char hostname_buf[NST_MAX_HOSTNAME_BUF_SIZE];

const char *xml_test_strings[] = {
    "<hostname>Hello World</hostname>",
    "  <hostname-list>\n<hostname>   Hello World</hostname>\n<hostname>Hello World    </hostname>     <hostname>  \t\nHello \t   \nWorld\n\t\n   </hostname>    </hostname-list>",
};

nst_expat_stack_frame_t expat_stack_bottom = {
    .parser = NULL,
    .name = NULL,
    .atts = NULL,
    .start_handler = root_start_handler,
    .end_handler = root_end_handler,
    .char_handler = root_char_handler,
    .parent = NULL,
    .data = NULL,
};

nst_expat_stack_frame_t *expat_stack_top = &expat_stack_bottom;

nst_allocator_t nst_cfg_allocator;

void
root_start_handler(void *udata,
                   const XML_Char *name,
                   const XML_Char **atts)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    if(current != &expat_stack_bottom) {
        assert(current->start_handler);
        assert(current->end_handler);
        current->start_handler(udata, name, atts);
    } else {
        assert(parent == NULL);

        if(!strcmp(name, "hostname")) {
            memset(hostname_buf, 0, sizeof(hostname_buf));
            current->child_ret = -1;
            nst_cfg_elt_data_capture(udata,
                                     name, atts,
                                     hostname_buf, sizeof(hostname_buf),
                                     FALSE);
        } 
    }
}

void
root_end_handler(void *udata,
                 const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    if(current != &expat_stack_bottom) {
        assert(current->start_handler);
        assert(current->end_handler);
        current->end_handler(udata, name);
    } else {
        if(!strcmp(name, "hostname")) {
            assert(current->child_ret == 11);
            assert(!strcmp(hostname_buf, "Hello World"));
        }
    }
}

void
root_char_handler(void *udata, const XML_Char *s, int len)
{
    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT(udata, current);

    if(current != &expat_stack_bottom
       && current->char_handler) {
        assert(current != &expat_stack_bottom);
        current->char_handler(udata, s, len);
    }
}

int
main(int argc, char **argv)
{
    XML_Parser parser;

    size_t i;
    size_t j;

    nst_cfg_allocator = nst_mem_stat_register("NST CFG");

    parser = XML_ParserCreate(NULL);
    expat_stack_top->parser = parser;

    if(!parser) {
        assert(0 && "Cannot allocate memory during XML_ParserCreate\n");
        return -1;
    }
    
    for(i = 0; 
        i < sizeof(xml_test_strings) / sizeof(const char *);
        i++) {
        const char *xml_test_string = xml_test_strings[i];
        enum XML_Status xml_status;

        XML_SetStartElementHandler(parser, root_start_handler);
        XML_SetEndElementHandler(parser, root_end_handler);
        XML_SetCharacterDataHandler(parser, root_char_handler);
        XML_SetUserData(parser, (void*)&expat_stack_top);

        for(j = 0; xml_test_string[j]; j++) {
            xml_status = XML_Parse(parser, xml_test_string+j, 1, 0);
            if(xml_status != XML_STATUS_OK) {
                fprintf(stderr, "Parse error at line %lu: %s\n",
                        XML_GetCurrentLineNumber(parser),
                        XML_ErrorString(XML_GetErrorCode(parser)));
                return -1;
            }
        }
        
        xml_status = XML_Parse(parser, NULL, 0, 1);
        if(xml_status != XML_STATUS_OK) {
            fprintf(stderr, "Parse error at line %lu: %s\n",
                    XML_GetCurrentLineNumber(parser),
                    XML_ErrorString(XML_GetErrorCode(parser)));
            return -1;
        }

        XML_ParserReset(parser, NULL);
    };

    XML_ParserFree(parser);

    assert(nst_mem_stat_get_allocated_nbytes(nst_cfg_allocator.data) == 0);
    return 0;
}
