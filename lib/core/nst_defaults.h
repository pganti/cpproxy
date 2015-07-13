#ifndef __MCPD_DEFAULTS_H__
#define __MCPD_DEFAULTS_H__

#define NST_DEFAULT_LOG_DIR         "/var/log"
#define NST_LOG_DEFAULT_UDP_PORT    (5514)
#define NST_MCPD_DEFAULT_PORT       (5515)

#define NST_DEFAULT_CONF_LATEST_DIR_NAME      "latest"
#define NST_DEFAULT_CONF_WORKING_DIR_NAME      "working"

#define NST_DEFAULT_CONF_DIR         "/etc/pronto/config"
#define NST_DEFAULT_CONF_CURRENT_DIR     "/etc/pronto/config/"
#define NST_DEFAULT_CONF_DIFF_FILENAME "diff.xml"
#define NST_DEFAULT_CONF_VERSION_FILENAME "version.xml"

#define NST_DEFAULT_CONF_DATA_CENTER_DIR "data-centers"
#define NST_DEFAULT_CONF_CUSTOMER_DIR "customers"
#define NST_DEFAULT_CONF_GLOBAL_DIR "globals"
#define NST_DEFAULT_CONF_SERVICES_DIR "services"

#define NST_DEFAULT_DOWS_FILE_NAME "domain-owners.xml"

#define NST_DEFAULT_CHROOT_DIR       "/opt/pronto"
#define NST_DEFAULT_HOSTNAME_FILE    "/etc/sysconfig/network"

#define NST_PROXY_NAME           "cpproxy"
#endif /*__MCPD_DEFAULTS_H__*/
