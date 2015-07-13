#ifndef _NST_CFG_TEST_COMMON_H
#define _NST_CFG_TEST_COMMON_H

#include <nst_allocator.h>

#include <expat.h>

struct nst_expat_stack_frame_s;

extern struct nst_expat_stack_frame_s *test_expat_stack_top;

void test_root_start_handler(void *udata, 
                             const XML_Char *name,
                             const XML_Char **attrs);
void test_root_end_handler(void *udata, const XML_Char *name);
void test_root_char_handler(void *udata, const XML_Char *s, int len);


void test_start_elt_dispatcher(void *udata,
                               const XML_Char *name,
                               const XML_Char **attrs);

void test_end_elt_dispatcher(void *udata,
                             const XML_Char *name);

#endif
