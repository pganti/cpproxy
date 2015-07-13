#ifndef _NST_ENUM_TYPE_HELPERS_H_
#define _NST_ENUM_TYPE_HELPERS_H_

int nst_enum_type_from_str(const char **table,
                           int start, int end, int unknown,
                           const char *type_str);

const char *nst_enum_type_to_str(const char **table,
                                 int start, int end, int unknown,
                                 int type);

#endif
