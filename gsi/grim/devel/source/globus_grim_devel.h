#if !defined(GLOBUS_GRIM_DEVEL_H)
#define GLOBUS_GRIM_DEVEL_H 1

#include "globus_gss_assist.h"
#include "globus_common.h"
#include "globus_error.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"

#define GLOBUS_GRIM_DEFAULT_GRIDMAP       "/etc/grid-security/grid-mapfile"
#define GLOBUS_GRIM_DEFAULT_CA_CERT_DIR   "/etc/grid-security/certificates/"
#define GLOBUS_GRIM_DEFAULT_KEY_FILENAME  "/etc/grid-security/hostkey.pem"
#define GLOBUS_GRIM_DEFAULT_CERT_FILENAME "/etc/grid-security/hostcert.pem"
#define GLOBUS_GRIM_DEFAULT_PORT_TYPE_FILENAME  \
                                          "/etc/grid-security/port_type.xml"
#define GLOBUS_GRIM_DEFAULT_CONF_FILENAME "/etc/grid-security/grim-conf.xml"
#define GLOBUS_GRIM_DEFAULT_MAX_TIME      24*60
#define GLOBUS_GRIM_DEFAULT_TIME          12*60
#define GLOBUS_GRIM_DEFAULT_KEY_BITS      512

#define GlobusGrimFreeNullArray(a)                          \
{                                                           \
    int __ctr = 0;                                          \
    while(a[__ctr] != NULL)                                 \
    {                                                       \
        free(a[__ctr]);                                     \
        __ctr++;                                            \
    }                                                       \
    free(a);                                                \
}

typedef globus_grim_config_t void *;

/*************************************************************************
 *              external api functions
 ************************************************************************/
/**
 *
 */
globus_result_t
globus_grim_config_init(
    globus_grim_config_t *                  config);

/**
 *
 */
globus_result_t
globus_grim_config_init_from_file(
    globus_grim_config_t *                  config,
    FILE *                                  fptr);

/**
 *
 */
globus_result_t
globus_grim_config_get_max_time(
    globus_grim_config_t                    config,
    int *                                   max_time);

/**
 *
 */
globus_result_t
globus_grim_config_set_max_time(
    globus_grim_config_t                    config,
    int                                     max_time);

/**
 *
 */
globus_result_t
globus_grim_config_get_default_time(
    globus_grim_config_t                    config,
    int *                                   default_time);

/**
 *
 */
globus_result_t
globus_grim_config_set_default_time(
    globus_grim_config_t                    config,
    int                                     default_time);

/**
 *
 */
globus_result_t
globus_grim_config_get_key_bits(
    globus_grim_config_t                    config,
    int *                                   key_bits);

/**
 *
 */
globus_result_t
globus_grim_config_set_key_bits(
    globus_grim_config_t                    config,
    int                                     key_bits);

/**
 *
 */
globus_result_t
globus_grim_config_get_ca_cert_dir(
    globus_grim_config_t                    config,
    char **                                 ca_cert_dir);

/**
 *
 */
globus_result_t
globus_grim_config_set_ca_cert_dir(
    globus_grim_config_t                    config,
    char *                                  ca_cert_dir);

/**
 *
 */
globus_result_t
globus_grim_config_get_cert_filename(
    globus_grim_config_t                    config,
    char **                                 cert_filename);

/**
 *
 */
globus_result_t
globus_grim_config_set_cert_filename(
    globus_grim_config_t                    config,
    char *                                  cert_filename);

/**
 *
 */
globus_result_t
globus_grim_config_get_key_filename(
    globus_grim_config_t                    config,
    char **                                 key_filename);

/**
 *
 */
globus_result_t
globus_grim_config_set_key_filename(
    globus_grim_config_t                    config,
    char *                                  key_filename);

/**
 *
 */
globus_result_t
globus_grim_config_get_gridmap_filename(
    globus_grim_config_t                    config,
    char **                                 gridmap_filename);

/**
 *
 */
globus_result_t
globus_grim_config_set_gridmap_filename(
    globus_grim_config_t                    config,
    char *                                  gridmap_filename);

/**
 *
 */
globus_result_t
globus_grim_config_get_port_type_filename(
    globus_grim_config_t                    config,
    char **                                 port_type_filename);

/**
 *
 */
globus_result_t
globus_grim_config_set_port_type_filename(
    globus_grim_config_t                    config,
    char *                                  port_type_filename);

/**
 *  
 */
globus_result_t
globus_grim_devel_get_NID(
    int *                                   nid);

/**
 *  
 */
globus_result_t
globus_grim_devel_port_type_file_parse(
    FILE *                                  fptr,
    char *                                  username,
    char **                                 groups;
    char ***                                port_types);

/**
 *  
 */
globus_result_t
globus_grim_devel_get_all_port_types(
    FILE *                                  fptr,
    char ***                                port_types);

/**
 *  
 */
globus_result_t
globus_grim_devel_port_type_file_parse_uid(
    FILE *                                  fptr,
    char ***                                port_types);


#endif /* GLOBUS_GRIM_DEVEL_H */
