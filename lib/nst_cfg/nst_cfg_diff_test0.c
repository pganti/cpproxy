#include "nst_cfg_diff.h"
#include "nst_cfg_diff_data.h"

#include "nst_cfg_test_common.h"
#include "nst_cfg_common.h"
#include "nst_cfg.h"

#include <nst_assert.h>
#include <nst_genhash.h>
#include <nst_mem_stat_allocator.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

const char *xml_test_strings[] = {
    "<diff-root>\n"
    "    <old-version>123</old-version>\n"
    "    <modified>\n"
    "        <services>\n"
    "            <name>m-svc1</name>\n"
    "            <name>m-svc2</name>\n"
    "            <name>m-svc3</name>\n"
    "        </services>\n"
    "        <clusters>\n"
    "            <name>m-remote-dc1</name>\n"
    "        </clusters>\n"
    "        <applications>\n"
    "        </applications>\n"
    "    </modified>\n"
    ""
    "    <removed>\n"
    "        <services>\n"
    "            <name>d-svc1</name>\n"
    "        </services>\n"
    "        <clusters>\n"
    "        </clusters>\n"
    "        <applications>\n"
    "            <name>d-application1</name>\n"
    "        </applications>\n"
    "    </removed>\n"
    ""
    "    <added>\n"
    "        <services>\n"
    "        </services>\n"
    "        <clusters>\n"
    "        </clusters>\n"
    "        <applications>\n"
    "            <name>a-application1</name>\n"
    "            <name>a-application2</name>\n"
    "        </applications>\n"
    "    </added>\n"
    "</diff-root>"
};

nst_cfg_diff_t diff;

void
test_start_elt_dispatcher(void *udata,
                          const XML_Char *name,
                          const XML_Char **atts)
{
    nst_expat_stack_frame_t *current;
    nst_expat_stack_frame_t *parent;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(parent == NULL);

    nst_assert(!strcmp(name, NST_CFG_DIFF_ROOT_TAG));
    nst_cfg_diff_init(&diff);
    nst_cfg_diff_capture(udata,
                         name, atts,
                         (void **)&diff, NULL, NULL, NULL);
}

void
test_end_elt_dispatcher(void *udata,
                        const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;
    nst_cfg_diff_block_t *diff_blocks[] = {
        &diff.modified,
        &diff.removed,
        &diff.added,
    };
    const char *diff_block_str[] = {
        "modified",
        "removed",
        "added",
    };

    const char *ghash_str[] = {
        "services",
        "clusters",
        "applications",
    };

    size_t i;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(!strcmp(name, NST_CFG_DIFF_ROOT_TAG));
    nst_assert(current->child_ret == 0);
 
    printf("old-version: %lu\n\n", diff.old_version);

    for(i = 0; i < sizeof(diff_blocks)/sizeof(diff_blocks[0]); i++) {
        size_t j;
        nst_genhash_t *ghashs[] = {
            diff_blocks[i]->services,
            diff_blocks[i]->dcs,
            diff_blocks[i]->applications,
        };
        
        printf("%s:\n", diff_block_str[i]);

        for(j = 0; j < sizeof(ghashs)/sizeof(ghashs[i]); j++) {
            nst_genhash_iter_t iter;
            nst_cfg_diff_data_t *diff_data;
            
            printf("\t%s:\n", ghash_str[j]);
            nst_genhash_iter_init(ghashs[j], &iter);
            while(nst_genhash_iter_next(&iter, (void **)&diff_data, NULL)) {
                printf("\t\t%s\n", diff_data->name);
            }
        }

        printf("\n");

    }

    nst_cfg_diff_reset(&diff);
}

int
main(int argc, char **argv)
{
    XML_Parser parser;

    size_t i;
    size_t j;

    parser = XML_ParserCreate(NULL);
    test_expat_stack_top->parser = parser;

    if(!parser) {
        nst_assert(0 && "Cannot allocate memory during XML_ParserCreate\n");
        return -1;
    }
    
    for(i = 0; 
        i < sizeof(xml_test_strings) / sizeof(const char *);
        i++) {
        const char *xml_test_string = xml_test_strings[i];
        enum XML_Status xml_status;

        XML_SetStartElementHandler(parser, test_root_start_handler);
        XML_SetEndElementHandler(parser, test_root_end_handler);
        XML_SetCharacterDataHandler(parser, test_root_char_handler);
        XML_SetUserData(parser, (void*)&test_expat_stack_top);

        for(j = 0; xml_test_string[j]; j++) {
            xml_status = XML_Parse(parser, xml_test_string+j, 1, 0);
            if(xml_status != XML_STATUS_OK) {
                fprintf(stderr, "*Parse error at line %lu: %s\n",
                        XML_GetCurrentLineNumber(parser),
                        XML_ErrorString(XML_GetErrorCode(parser)));
                return -1;
            }
        }
        
        xml_status = XML_Parse(parser, NULL, 0, 1);
        if(xml_status != XML_STATUS_OK) {
            fprintf(stderr, "**Parse error at line %lu: %s\n",
                    XML_GetCurrentLineNumber(parser),
                    XML_ErrorString(XML_GetErrorCode(parser)));
            return -1;
        }

        XML_ParserReset(parser, NULL);
    };

    XML_ParserFree(parser);

    nst_assert(nst_mem_stat_get_allocated_nbytes(nst_cfg_allocator.data) == 0);

    return 0;
}
