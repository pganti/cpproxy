
#include "nst_cfg_application.h"
#include "nst_cfg_domain.h"

#include "nst_cfg.h"
#include "nst_cfg_test_common.h"
#include "nst_cfg_common.h"

#include "nst_cpt_eval.h"
#include "nst_cpt_request.h"
#include "nst_cpt.h"
#include "nst_cpt_node.h"

#include <nst_genhash.h>
#include <nst_string.h>
#include <nst_vector.h>
#include <nst_mem_stat_allocator.h>
#include <nst_allocator.h>
#include <nst_assert.h>
#include <nst_corelib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

nst_cfg_application_t *application = NULL;
const char *my_dc_name = "sjc-eqx";

static int
print_origin_sites(void *elt, void *actor_data)
{
    nst_cpt_node_t *os_node = *(nst_cpt_node_t **)elt;

    nst_cpt_node_reg_log(os_node,
                         NST_LOG_LEVEL_DEBUG,
                         NST_LOG_LEVEL_DEBUG,
                         0);
    return 0;
}

static int
print_domain(void *elt, void *actor_data)
{
    nst_cpt_request_t request;
    nst_cfg_domain_t *domain;
    const nst_str_t *str;
    size_t naliases;
    size_t i;

    domain = *(nst_cfg_domain_t **)elt;

    str = nst_cfg_domain_get_name(domain);
    fprintf(stdout, "domain name: %s len: %lu\n", str->data,
            (long unsigned int)str->len);
    
    naliases = nst_vector_get_nelts(domain->aliases);
    for(i = 1; i < naliases; i++) {
        str = nst_vector_get_elt_at(domain->aliases, i);
        fprintf(stdout, "domain alias: %s len: %lu\n", str->data, 
            (long unsigned int)str->len);
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "next-hop-tree:\n");
    nst_assert(domain->cpt);
    nst_cpt_node_reg_log(domain->cpt,
                         NST_LOG_LEVEL_DEBUG,
                         NST_LOG_LEVEL_DEBUG,
                         0);
    fprintf(stdout, "\n");

    fprintf(stdout, "tree evaluation\n");
    memset(&request, 0, sizeof(request));
    request.noc_log_lvl = NST_LOG_LEVEL_DEBUG;
    nst_cpt_find_nh(domain->cpt, &request);

    return 0;
}

void
test_start_elt_dispatcher(void *udata,
                          const XML_Char *name,
                          const XML_Char **atts)
{
    nst_expat_stack_frame_t *current;
    nst_expat_stack_frame_t *parent;

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(parent == NULL);

    nst_assert(!strcmp(name, "application"));
    current->child_ret = -1;
    nst_cfg_application_free(application);
    application = NULL;
    nst_cfg_application_capture(udata,
                             name, atts,
                             (void **)&application, (void **)my_dc_name,
                             NULL, NULL);
}

void
test_end_elt_dispatcher(void *udata,
                        const XML_Char *name)
{
    nst_expat_stack_frame_t *parent; 
    nst_expat_stack_frame_t *current;
    nst_cfg_domain_t *domain;
    size_t i;
    size_t j;
    size_t naliases;
    const char *domain_names[] = {
        "alpha.test.pronto.com",
        "myalpha.test.pronto.com",
        ".alpha.test.pronto.com",
    };

    NST_EXPAT_STACK_FRAME_GET_CURRENT_AND_PARENT(udata, current, parent);

    nst_assert(parent == NULL);
    nst_assert(!strcmp(name, "application"));
    nst_assert(current->child_ret == 0);
    nst_assert(application);
    nst_assert(application->origin_sites);
    
    fprintf(stdout, "application name: %s\n\n", application->name);
    fprintf(stdout, "origin sites:\n");
    nst_vector_for_each_till(application->origin_sites,
                             print_origin_sites, NULL);
    fprintf(stdout, "\n");

    nst_vector_for_each_till(application->domains,
                             print_domain, NULL);

    domain = *(nst_cfg_domain_t **)nst_vector_get_elt_at(application->domains, 0);
    naliases = nst_vector_get_nelts(domain->aliases);
    for(i = 0; i < sizeof(domain_names)/sizeof(domain_names[0]); i++) {
        for(j = 0; j < naliases; j ++) {
            nst_str_t *alias;
            alias = nst_vector_get_elt_at(domain->aliases, j);
            if(nst_strcmp(alias->data, domain_names[i]) == 0)
                break;
        }

        nst_assert(j < naliases);
    }

    nst_cfg_application_free(application);
    application = NULL;
}

int
main(int argc, char **argv)
{
    XML_Parser parser;
    int fd;
    ssize_t nread;
    char buf[1];
    char      file [1024];

    nst_corelib_init (argv[0]);
    nst_log_enable_stderr();
    nst_log_set_level(NST_LOG_LEVEL_DEBUG);

    if (argv[1] == NULL) {
        argv[1] = "application_test0.xml";
    }
    snprintf (file, sizeof(file), "%s", argv[1]);
            
    fd = open(file, O_RDONLY);
    nst_assert(fd != -1);

    parser = XML_ParserCreate(NULL);
    test_expat_stack_top->parser = parser;
    nst_assert(parser);

    XML_SetStartElementHandler(parser, test_root_start_handler);
    XML_SetEndElementHandler(parser, test_root_end_handler);
    XML_SetCharacterDataHandler(parser, test_root_char_handler);
    XML_SetUserData(parser, (void*)&test_expat_stack_top);

    while(1) {
        enum XML_Status xml_status;
        nread = read(fd, buf, sizeof(buf));

        if(nread == -1) {
            if(errno == EINTR) {
                continue;
            } else {
                fprintf(stderr, "Errror reading XML file\n");
                abort();
            }
        } /*else if(nread > 0) {
            fprintf(stdout, "%c", buf[0]);
            }*/

        xml_status = XML_Parse(parser, buf, nread, (size_t)nread < sizeof(buf));

        if(xml_status != XML_STATUS_OK) {
            fprintf(stderr, "Parse error at line %lu: %s\n",
                    XML_GetCurrentLineNumber(parser),
                    XML_ErrorString(XML_GetErrorCode(parser)));
            abort();
        }
        if((size_t)nread < sizeof(buf))
            break;
    }

    nst_assert((size_t)nread < sizeof(buf));
    XML_ParserFree(parser);

#if 0
    nst_assert(nst_mem_stat_get_allocated_nbytes(nst_cfg_allocator.data) == 0);
    nst_assert(nst_mem_stat_get_allocated_nbytes(nst_cpt_allocator.data) == 0);
#endif

    nst_cfg_reset();
    nst_corelib_reset();

    return 0;
}
