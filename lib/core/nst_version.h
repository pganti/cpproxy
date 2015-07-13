#ifndef __NST_VERSION_H__
#define __NST_VERSION_H__

#define NST_VERSION_STRING_LEN (1024)

#define NST_BUILD_DATE __TIME__ " " __DATE__
#define NST_VERSION_NUMBER "0.0.1"

static char    version_string [NST_VERSION_STRING_LEN];
static inline const char *
nst_version_string()
{
    snprintf (version_string, NST_VERSION_STRING_LEN, "%s, %s",
              NST_VERSION_NUMBER, NST_BUILD_DATE);

    return version_string;
}

#endif /*__NST_VERSION_H__*/
