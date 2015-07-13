#include "nst_cfg_origin_site.h"

#include "nst_cfg_application.h"
#include "nst_cfg_common.h"
#include "nst_cfg.h"

#include <nst_cpt_osite_node.h>
#include <nst_cpt_common.h>
#include <nst_cpt.h>
#include <nst_cpt_node.h>

#include <nst_gen_func.h>
#include <nst_vector.h>
#include <nst_assert.h>
#include <nst_mem_stat_allocator.h>
#include <nst_corelib.h>

#include <nst_cfg_test_common.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

const char *xml_test_strings[] = {
    "<origin-site>\n"
    "    <name>osite@pek</name>\n"
    "    <ref-cluster>pek-alpha</ref-cluster>\n"
    "    <ref-cluster>pek-ctel</ref-cluster>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv1</name>\n"
    "        <ip type=\"ipv4\">192.168.1.16</ip>  \n"
    "        <score>5</score>\n"
    "    </origin-server>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv2</name>\n"
    "        <hostname>osrv2.alpah.test.pronto.com</hostname>\n"
    "        <score>10</score>\n"
    "    </origin-server>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv3</name>\n"
    "        <hostname>osrv3.alpah.test.pronto.com</hostname>\n"
    "        <score>7</score>\n"
    "    </origin-server>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv4</name>\n"
    "        <ip type=\"ipv4\">192.168.1.17</ip>  \n"
    "        <score>8</score>\n"
    "    </origin-server>\n"
    "\n"
    "</origin-site>\n",

    "<origin-site>\n"
    "    <name>osite@hkg</name>\n"
    "    <ref-cluster>pek-alpha</ref-cluster>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv1</name>\n"
    "        <ip type=\"ipv4\">192.168.1.16</ip>  \n"
    "        <score>40</score>\n"
    "    </origin-server>\n"
    "\n"
    "    <origin-server>\n"
    "        <name>osrv2</name>\n"
    "        <hostname>osrv2.alpah.test.pronto.com</hostname>\n"
    "        <score>30</score>\n"
    "    </origin-server>\n"
    "\n"
    "</origin-site>\n",
};

nst_cfg_application_t application;

void
test_start_elt_dispatcher(void *udata,
                          const XML_Char *name,
                          const XML_Char **atts)
{
    nst_expat_stack_frame_t *current;
    nst_expat_stack_frame_t *parent;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(parent == NULL);

    nst_assert(!strcmp(name, "origin-site"));
    current->child_ret = -1;
    strcpy(application.name, "test-application");
    nst_cfg_origin_site_capture(udata,
                                name, atts,
                                (void **)&application, (void **)"pek-ctel",
                                NULL, NULL);
}

void
test_end_elt_dispatcher(void *udata,
                        const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(parent == NULL);
    nst_assert(!strcmp(name, "origin-site"));
    nst_assert(current->child_ret == 0);
}

int
main(int argc, char **argv)
{
    XML_Parser parser;
    size_t nosites;
    size_t i;
    size_t j;

    nst_corelib_init (argv[0]);
    nst_log_enable_stderr();
    nst_log_set_level(NST_LOG_LEVEL_DEBUG);

    application.origin_sites
        = nst_vector_new(&nst_cfg_allocator,
                         (nst_gen_destructor_f)nst_cpt_node_vec_free,
                         1,
                         sizeof(nst_cpt_node_t *));

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

    nosites = nst_vector_get_nelts(application.origin_sites);
    nst_assert(nosites == 2);
    for(i = 0; i < nosites; i++) {
        nst_cpt_node_t *node;
        node =
            *(nst_cpt_node_t **)nst_vector_get_elt_at(application.origin_sites,
                                                      i);
        nst_assert(node);
        nst_assert(node->type == NST_CPT_NODE_TYPE_OSITE);
        nst_cpt_node_reg_log(node,
                             NST_LOG_LEVEL_DEBUG,
                             NST_LOG_LEVEL_DEBUG,
                             0);
    }
    nst_vector_free(application.origin_sites);

    nst_assert(nst_mem_stat_get_allocated_nbytes(nst_cfg_allocator.data) == 0);
    nst_assert(nst_mem_stat_get_allocated_nbytes(nst_cpt_allocator.data) == 0);

    nst_corelib_reset();

    return 0;
}
