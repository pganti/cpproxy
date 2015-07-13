#include "nst_enum_type_helpers.h"

#include <string.h>

int
nst_enum_type_from_str(const char **table,
                       int start, int end, int unknown,
                       const char *type_str)
{
    int i;

    for(i = start; i < end; i++) {
        if(!strcmp(type_str, table[i]))
            return i;
    }

    return unknown;
}

const char *
nst_enum_type_to_str(const char **table,
                     int start, int end, int unknown,
                     int type)
{
    if(type >= start && type < end) {
        return table[type];
    } else {
        return table[unknown];
    }
}
