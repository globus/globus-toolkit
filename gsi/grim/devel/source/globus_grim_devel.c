#include "globus_gss_assist.h"
#include "globus_common.h"
#include "globus_error_string.h"
#include "globus_error.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"
#include "globus_grim_devel.h"
#include "globus_error.h"
#include <expat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "version.h"

#define GRIM_ASSERTION_FORMAT_VERSION "1"
#define GRIM_OID                      "1.3.6.1.4.1.3536.1.1.1.7"
#define GRIM_SN                       "GRIMPOLICY"
#define GRIM_LN                       "GRIM Policy Language"

/*************************************************************************
 *              internal data types
 ************************************************************************/
struct globus_l_grim_conf_info_s
{
    int                                     max_time;
    int                                     default_time;
    int                                     key_bits;
    char *                                  ca_cert_dir;
    char *                                  cert_filename;
    char *                                  key_filename;
    char *                                  gridmap_filename;
    char *                                  port_type_filename;
}; 

struct globus_l_grim_assertion_s
{
    char *                                  subject;
    char *                                  username;
    char **                                 dna;
    char **                                 port_types;
};

/*************************************************************************
 *              internal function signatures
 ************************************************************************/
globus_result_t
globus_l_grim_parse_conf_file(
    struct globus_l_grim_conf_info_s *      info,
    FILE *                                  fptr);
 
globus_result_t
globus_l_grim_build_assertion(
    struct globus_l_grim_assertion_s *      info,
    char **                                 out_string);

globus_result_t
globus_l_grim_devel_parse_port_type_file(
    FILE *                                  fptr,
    char *                                  username,
    char **                                 groups,
    char ***                                port_types);

static int globus_l_grim_devel_activate(void);
static int globus_l_grim_devel_deactivate(void);

/*************************************************************************
 *              global variables
 ************************************************************************/
static globus_bool_t                            globus_l_grim_activated 
                                                            = GLOBUS_FALSE;
static int                                      globus_l_grim_NID;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_grim_devel_module =
{
    "globus_grim_devel",
    globus_l_grim_devel_activate,
    globus_l_grim_devel_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*************************************************************************
 *              external api functions
 ************************************************************************/

#define GlobusLGrimSetGetAssertionEnter(assertion, info)                    \
{                                                                           \
    if(assertion == NULL)                                                   \
    {                                                                       \
        return globus_error_put(                                            \
                   globus_error_construct_string(                           \
                       GLOBUS_GRIM_DEVEL_MODULE,                            \
                       GLOBUS_NULL,                                         \
                       "[globus_grim_devel]::assertion handle is null."));  \
    }                                                                       \
    info = (struct globus_l_grim_assertion_s *) assertion;                  \
}

/*
 *  Assertion parsing
 */

/**
 *
 */
globus_result_t
globus_grim_assertion_init(
    globus_grim_assertion_t *               assertion,
    char *                                  subject,
    char *                                  username)
{
    struct globus_l_grim_assertion_s *      ass;

    ass = (struct globus_l_grim_assertion_s *)
                globus_malloc(sizeof(struct globus_l_grim_assertion_s *));
    if(ass == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: malloc failed."));
    }
    ass->subject = strdup(subject);
    ass->username = strdup(username);
    ass->dna = NULL;
    ass->port_types = NULL;
    *assertion = ass;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_init_from_buffer(
    globus_grim_assertion_t *               assertion,
    char *                                  buffer,
    int                                     buffer_length)
{
    return GLOBUS_SUCCESS;
}
    
/**
 *
 */
globus_result_t
globus_grim_assertion_serialize(
    globus_grim_assertion_t                 assertion,
    char **                                 out_assertion_string)
{
    globus_result_t                         res;
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    if(out_assertion_string == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: out_assertion_string is null."));
    }

    res = globus_l_grim_build_assertion(info, out_assertion_string);

    return res;
}
 
/**
 *
 */
globus_result_t
globus_grim_assertion_destroy(
    globus_grim_assertion_t                 assertion)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    free(info->subject);
    free(info->username);
    if(info->dna != NULL)
    {
        GlobusGrimFreeNullArray(info->dna);
    }
    if(info->port_types)
    {
        GlobusGrimFreeNullArray(info->port_types);
    }
    globus_free(info);

    return GLOBUS_SUCCESS;
}
    
/**
 *
 */
globus_result_t
globus_grim_assertion_get_subject(
    globus_grim_assertion_t                 assertion,
    char **                                 subject)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);
    if(subject == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: subject is null."));
    }

    *subject = info->subject;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_get_username(
    globus_grim_assertion_t                 assertion,
    char **                                 username)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);
    if(username == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: username is null."));
    }

    *username = info->username;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_get_dn_array(
    globus_grim_assertion_t                 assertion,
    char ***                                dn_array)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    if(dn_array == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: dn_array is null."));
    }

    *dn_array = info->dna;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_set_dn_array(
    globus_grim_assertion_t                 assertion,
    char **                                 dn_array)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    info->dna = dn_array;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_get_port_types_array(
    globus_grim_assertion_t                 assertion,
    char ***                                port_types_array)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    if(port_types_array == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: port_types_array is null."));
    }

    *port_types_array = info->port_types;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_assertion_set_port_types_array(
    globus_grim_assertion_t                 assertion,
    char **                                 port_types_array)
{
    struct globus_l_grim_assertion_s *      info;

    GlobusLGrimSetGetAssertionEnter(assertion, info);

    info->port_types = port_types_array;

    return GLOBUS_SUCCESS;
}


/*
 *  Config file parsing functions
 */

#define GlobusLGrimConfInfoInit(info)                                       \
{                                                                           \
    info->max_time = GLOBUS_GRIM_DEFAULT_MAX_TIME;                          \
    info->default_time = GLOBUS_GRIM_DEFAULT_TIME;                          \
    info->key_bits = GLOBUS_GRIM_DEFAULT_KEY_BITS;                          \
    info->ca_cert_dir = strdup(GLOBUS_GRIM_DEFAULT_CA_CERT_DIR);            \
    info->cert_filename = strdup(GLOBUS_GRIM_DEFAULT_CERT_FILENAME);        \
    info->key_filename = strdup(GLOBUS_GRIM_DEFAULT_KEY_FILENAME);          \
    info->gridmap_filename = strdup(GLOBUS_GRIM_DEFAULT_GRIDMAP);           \
    info->port_type_filename = strdup(GLOBUS_GRIM_DEFAULT_PORT_TYPE_FILENAME);\
}

#define GlobusLGrimSetGetConfigEnter(config, _info)                         \
{                                                                           \
    if(config == NULL)                                                      \
    {                                                                       \
        return globus_error_put(                                            \
                   globus_error_construct_string(                           \
                       GLOBUS_GRIM_DEVEL_MODULE,                            \
                       GLOBUS_NULL,                                         \
                       "[globus_grim_devel]::config handle is null."));     \
    }                                                                       \
    _info = (struct globus_l_grim_conf_info_s *) config;                    \
}

/**
 *
 */
globus_result_t
globus_grim_config_init(
    globus_grim_config_t *                  config)
{
    struct globus_l_grim_conf_info_s *      info;

    info = (struct globus_l_grim_conf_info_s *)
                globus_malloc(sizeof(struct globus_l_grim_conf_info_s));
    if(info == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: malloc failed."));
    }

    GlobusLGrimConfInfoInit(info);

    *config = info;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_load_from_file(
    globus_grim_config_t                    config,
    FILE *                                  fptr)
{
    globus_result_t                         res;
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);

    if(fptr == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: file pointer is NULL."));
    }

    res = globus_l_grim_parse_conf_file(info, fptr);

    return res;
}

/**
 *
 */
globus_result_t
globus_grim_config_destroy(
    globus_grim_config_t                    config)
{
    struct globus_l_grim_conf_info_s *      info;

    info = (struct globus_l_grim_conf_info_s *) config;
    free(info->ca_cert_dir);
    free(info->cert_filename);
    free(info->key_filename);
    free(info->gridmap_filename);
    free(info->port_type_filename);
    free(info);

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_max_time(
    globus_grim_config_t                    config,
    int *                                   max_time)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(max_time == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: max_time is NULL."));
    }

    *max_time = info->max_time;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_max_time(
    globus_grim_config_t                    config,
    int                                     max_time)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    info->max_time = max_time;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_default_time(
    globus_grim_config_t                    config,
    int *                                   default_time)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(default_time == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: default_time is NULL."));
    }

    *default_time = info->default_time;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_default_time(
    globus_grim_config_t                    config,
    int                                     default_time)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    info->default_time = default_time;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_key_bits(
    globus_grim_config_t                    config,
    int *                                   key_bits)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(key_bits == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: key_bits is NULL."));
    }

    *key_bits = info->key_bits;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_key_bits(
    globus_grim_config_t                    config,
    int                                     key_bits)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    info->key_bits = key_bits;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_ca_cert_dir(
    globus_grim_config_t                    config,
    char **                                 ca_cert_dir)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(ca_cert_dir == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: ca_cert_dir is NULL."));
    }

    *ca_cert_dir = info->ca_cert_dir;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_ca_cert_dir(
    globus_grim_config_t                    config,
    char *                                  ca_cert_dir)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    free(info->ca_cert_dir);
    info->ca_cert_dir = strdup(ca_cert_dir);

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_cert_filename(
    globus_grim_config_t                    config,
    char **                                 cert_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(cert_filename == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: cert_filename is NULL."));
    }

    *cert_filename = info->cert_filename;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_cert_filename(
    globus_grim_config_t                    config,
    char *                                  cert_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    free(info->cert_filename);
    info->cert_filename = strdup(cert_filename);

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_key_filename(
    globus_grim_config_t                    config,
    char **                                 key_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    if(key_filename == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: key_filename is NULL."));
    }

    *key_filename = info->key_filename;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_key_filename(
    globus_grim_config_t                    config,
    char *                                  key_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    free(info->key_filename);
    info->key_filename = strdup(key_filename);

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_gridmap_filename(
    globus_grim_config_t                    config,
    char **                                 gridmap_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    *gridmap_filename = info->gridmap_filename;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_gridmap_filename(
    globus_grim_config_t                    config,
    char *                                  gridmap_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    free(info->gridmap_filename);
    info->gridmap_filename = strdup(gridmap_filename);

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_get_port_type_filename(
    globus_grim_config_t                    config,
    char **                                 port_type_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    *port_type_filename = info->port_type_filename;

    return GLOBUS_SUCCESS;
}

/**
 *
 */
globus_result_t
globus_grim_config_set_port_type_filename(
    globus_grim_config_t                    config,
    char *                                  port_type_filename)
{
    struct globus_l_grim_conf_info_s *      info;
    
    GlobusLGrimSetGetConfigEnter(config, info);
    free(info->port_type_filename);
    info->port_type_filename = strdup(port_type_filename);

    return GLOBUS_SUCCESS;
}


/**
 *  
 */
globus_result_t
globus_grim_devel_get_NID(
    int *                                   nid)
{
    if(!globus_l_grim_activated)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: Module not activated."));
    }

    *nid = globus_l_grim_NID;
    
    return GLOBUS_SUCCESS;
}

/**
 *  
 */
globus_result_t
globus_grim_devel_port_type_file_parse(
    FILE *                                  fptr,
    char *                                  username,
    char **                                 groups,
    char ***                                port_types)
{
    globus_result_t                         res;

    if(fptr == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: File pointer is NULL."));
    }
    if(port_types == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: port_types parameter is NULL."));
    }

    res = globus_l_grim_devel_parse_port_type_file(
              fptr, 
              username,
              groups,
              port_types);

    return res;
}

/**
 *  
 */
globus_result_t
globus_grim_devel_get_all_port_types(
    FILE *                                  fptr,
    char ***                                port_types)
{
    globus_result_t                         res;

    if(fptr == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: File pointer is NULL."));
    }
    if(port_types == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: port_types parameter is NULL."));
    }

    res = globus_l_grim_devel_parse_port_type_file(
              fptr, 
              NULL, 
              NULL,
              port_types);

    return res;
}

/**
 *  
 */
globus_result_t
globus_grim_devel_port_type_file_parse_uid(
    FILE *                                  fptr,
    char ***                                port_types)
{
    char *                                  username;
    char **                                 groups;
    int                                     groups_max = 16;
    int                                     groups_ndx;
    struct group *                          grp_ent;
    int                                     ctr;
    globus_result_t                         res;

    if(fptr == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: File pointer is NULL."));
    }
    if(port_types == NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: port_types parameter is NULL."));
    }

    /*
     *  get group list
     */
    groups_ndx = 0;
    groups = (char **) globus_malloc(sizeof(char *) * groups_max);
    while((grp_ent = getgrent()) != NULL)
    {
        for(ctr = 0; grp_ent->gr_mem[ctr] != NULL; ctr++)
        {
            if(strcmp(username, grp_ent->gr_mem[ctr]) == 0)
            {
                groups[groups_ndx] = strdup(grp_ent->gr_name);
                groups_ndx++;
                if(groups_ndx >= groups_max)
                {
                    groups_max *= 2;
                    groups = (char **)
                        globus_malloc(sizeof(char *) * groups_max);
                }
            }
        }
    }
    groups[groups_ndx] = NULL;

    res = globus_l_grim_devel_parse_port_type_file(
             fptr,
             username,
             groups,
             port_types);
 
    /*
     *  clean up
     */
    free(username);
    GlobusGrimFreeNullArray(groups);

    return res;
}

/*************************************************************************
 *              internal functions
 ************************************************************************/

static int 
globus_l_grim_devel_activate()
{
    int                                     rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_GSI_PROXY_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_GSI_CALLBACK_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    globus_l_grim_activated = GLOBUS_TRUE;
    globus_l_grim_NID = OBJ_create(GRIM_OID, GRIM_SN, GRIM_LN);

    return GLOBUS_SUCCESS;
}

static int 
globus_l_grim_devel_deactivate()
{
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);

    globus_l_grim_activated = GLOBUS_FALSE;

    return GLOBUS_SUCCESS;
}


/************************************************************************
 *                 xml parsing code for port file
 ***********************************************************************/
struct globus_l_grim_port_type_info_s
{
    int                                     found;
    char *                                  username;
    char **                                 groups;
    globus_list_t *                         list;
};  

static void
globus_l_grim_port_type_start(
    void *                                  data,
    const char *                            el, 
    const char **                           attr)
{   
    struct globus_l_grim_port_type_info_s * info;
    int                                     ctr;

    info = (struct globus_l_grim_port_type_info_s *) data;

    info->found = 0;
    if(strcmp(el, "port_type") == 0)
    {
        /* 
         *  if username is NULL it means that we want ever user qualified
         *  port type
         */
        if(info->username == NULL || 
            (strcmp(attr[0], "username") == 0 &&
             strcmp(info->username, attr[1]) == 0))
            
        {
            info->found = 1;
        }
        else if(strcmp(attr[0], "group") == 0)
        {
            for(ctr = 0;
                info->groups != NULL && info->groups[ctr] != NULL;
                ctr++)
            {
                if(strcmp(info->groups[ctr], attr[1]) == 0)
                {
                    info->found = 1;
                }
            }
            /*
             *  if groups are NULL then we want ever group qualified port
             *  type.
             */
            if(info->groups == NULL)
            {
                info->found = 1;
            }
        }
        else
        {
            info->found = 0;
        }
    }


}

static void
globus_l_grim_port_type_end(
    void *                                  data,
    const char *                            el)
{
}

static void
globus_l_grim_port_type_cdata(
    void *                                  data,
    const XML_Char *                        s,
    int                                     len)
{   
    struct globus_l_grim_port_type_info_s * info;
    char *                                  tmp_s;
    
    info = (struct globus_l_grim_port_type_info_s *) data;

    if(info->found)
    {
        tmp_s = malloc(sizeof(char) * (len + 1));
        strncpy(tmp_s, s, len);
        globus_list_insert(&info->list, tmp_s);
        info->found = 0;
    }
}   


globus_result_t
globus_l_grim_devel_parse_port_type_file(
    FILE *                                  fptr,
    char *                                  username,
    char **                                 groups,
    char ***                                port_types)
{
    char                                    buffer[512];
    size_t                                  len;
    XML_Parser                              p;
    int                                     done;
    globus_result_t                         res = GLOBUS_SUCCESS;
    char *                                  port_type;
    char **                                 pt_rc;
    int                                     ctr;
    struct globus_l_grim_port_type_info_s   info;

    p = XML_ParserCreate(NULL);
    if(p == NULL)
    {
        fclose(fptr);

        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_GRIM_DEVEL_MODULE,
                       GLOBUS_NULL,
                       "[globus_grim_devel]:: parser didn't open."));
    }

    XML_SetElementHandler(p, globus_l_grim_port_type_start, 
        globus_l_grim_port_type_end);
    info.list = NULL;
    info.found = 0;
    info.username = username;
    info.groups = groups;
    XML_SetUserData(p, &info);
    XML_SetCharacterDataHandler(p, globus_l_grim_port_type_cdata);

    done = 0;
    while(!done)
    {
        len = fread(buffer, 1, sizeof(buffer), fptr);
        done = len < sizeof(buffer);
        if(XML_Parse(p, buffer, len, len < done) == XML_STATUS_ERROR)
        {
            res = globus_error_put(
                     globus_error_construct_string(
                         GLOBUS_GRIM_DEVEL_MODULE,
                         GLOBUS_NULL,
                         "[globus_grim_devel]:: xml parser failure."));
            goto exit;
        }
    }

    pt_rc = (char **)
              globus_malloc((globus_list_size(info.list) + 1) * sizeof(char *));
    ctr = 0;
    while(!globus_list_empty(info.list))
    {
        port_type = (char *) globus_list_remove(&info.list, info.list);
        pt_rc[ctr] = port_type;
        printf("%s.\n", pt_rc[ctr]);
        ctr++;
    }
    pt_rc[ctr] = NULL;

    if(port_types != NULL)
    {
        *port_types = pt_rc;
    }

  exit:
    fclose(fptr);
    XML_ParserFree(p);

    return res;
}

/************************************************************************
 *                 xml parsing code for conf file
 ***********************************************************************/
static void
grim_conf_end(
    void *                                  data,
    const char *                            el)
{   
}   

static void
grim_conf_start(
    void *                                  data,
    const char *                            el,
    const char **                           attr)
{   
    struct globus_l_grim_conf_info_s *      info;

    info = (struct globus_l_grim_conf_info_s *) data;

    if(strcmp(el, "conf") == 0)
    {
        if(strcmp(attr[0], "max_time") == 0)
        {
            info->max_time = atoi(attr[1]);
        } 
        else if(strcmp(attr[0], "default_time") == 0)
        {
            info->default_time = atoi(attr[1]);
        }
        else if(strcmp(attr[0], "key_bits") == 0)
        {
            info->key_bits = atoi(attr[1]);
        }
        else if(strcmp(attr[0], "cert_filename") == 0)
        {
            free(info->cert_filename);
            info->cert_filename = strdup(attr[1]);
        }
        else if(strcmp(attr[0], "key_filename") == 0)
        {
            free(info->key_filename);
            info->key_filename = strdup(attr[1]);
        }
        else if(strcmp(attr[0], "gridmap_filename") == 0)
        {
            free(info->gridmap_filename);
            info->gridmap_filename = strdup(attr[1]);
        }
        else if(strcmp(attr[0], "port_type_filename") == 0)
        {
            free(info->port_type_filename);
            info->port_type_filename = strdup(attr[1]);
        }
    }
}

globus_result_t
globus_l_grim_parse_conf_file(
    struct globus_l_grim_conf_info_s *      info,
    FILE *                                  fptr)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    int                                     done;
    char                                    buffer[512];
    size_t                                  len;
    XML_Parser                              p = NULL;

    p = XML_ParserCreate(NULL);
    if(p == NULL)
    {
        res = globus_error_put(
                  globus_error_construct_string(
                      GLOBUS_GRIM_DEVEL_MODULE,
                      GLOBUS_NULL,
                      "[globus_grim_devel]:: could not create parser."));
        goto exit;
    }

    XML_SetElementHandler(p, grim_conf_start, grim_conf_end);
    XML_SetUserData(p, info);

    done = 0;
    while(!done)
    {
        len = fread(buffer, 1, sizeof(buffer), fptr);
        done = len < sizeof(buffer); 
        if(XML_Parse(p, buffer, len, len < done) == XML_STATUS_ERROR)
        {
            res = globus_error_put(
                      globus_error_construct_string(
                        GLOBUS_GRIM_DEVEL_MODULE,
                        GLOBUS_NULL,
                        "[globus_grim_devel]:: xml parse failed."));
            goto exit;
        }
    }

  exit:
    
    if(p != NULL)
    {
        XML_ParserFree(p);
    }

    return res;
}


/************************************************************************
 *              code for dealing with assertions
 ***********************************************************************/
#define GrowString(b, len, new, offset)                 \
{                                                       \
    if(len <= strlen(new) + offset)                     \
    {                                                   \
        len *= 2;                                       \
        b = globus_realloc(b, len);                     \
    }                                                   \
    strcpy(&b[offset], new);                            \
    offset += strlen(new);                              \
}

globus_result_t
globus_l_grim_build_assertion(
    struct globus_l_grim_assertion_s *      info,
    char **                                 out_string)
{
    char *                                  buffer;
    int                                     ctr;
    int                                     buffer_size = 1024;
    int                                     buffer_ndx = 0;
    char                                    hostname[MAXHOSTNAMELEN];
    char *                                  subject;
    char *                                  username;
    char **                                 dna;
    char **                                 port_types;

    subject = info->subject;
    username = info->username;
    dna = info->dna;
    port_types = info->port_types;

    globus_libc_gethostname(hostname, MAXHOSTNAMELEN);
    buffer = globus_malloc(sizeof(char) * buffer_size);

    GrowString(buffer, buffer_size, "<GrimAssertion>\n", buffer_ndx);
    GrowString(buffer, buffer_size, "    <Version>", buffer_ndx);
    GrowString(buffer, buffer_size, GRIM_ASSERTION_FORMAT_VERSION, buffer_ndx);
    GrowString(buffer, buffer_size, "    </Version>\n", buffer_ndx);
    GrowString(buffer, buffer_size,
        "    <ServiceGridId Format=\"#X509SubjectName\">",
        buffer_ndx);
    GrowString(buffer, buffer_size, subject, buffer_ndx);
    GrowString(buffer, buffer_size, "</ServerGridId>\n", buffer_ndx);
    GrowString(buffer, buffer_size,
        "    <ServiceLocalId Format=\"#UnixAccountName\" \n",
        buffer_ndx);
    GrowString(buffer, buffer_size, "        NameQualifier=\"", buffer_ndx);
    GrowString(buffer, buffer_size, hostname, buffer_ndx);
    GrowString(buffer, buffer_size, "\">", buffer_ndx);
    GrowString(buffer, buffer_size, username, buffer_ndx);
    GrowString(buffer, buffer_size, "</ServiceLocalId>\n", buffer_ndx);

    /* add all mapped dns */
    for(ctr = 0; dna[ctr] != NULL; ctr++)
    {
        GrowString(buffer, buffer_size,
            "<authorizedClientId Format=\"#X509SubjectName\">",
            buffer_ndx);
        GrowString(buffer, buffer_size, dna[ctr], buffer_ndx);
        GrowString(buffer, buffer_size, "</AuthorizedClientId>\n", buffer_ndx);
    }

    /* add in port_types */
    for(ctr = 0; port_types[ctr] != NULL; ctr++)
    {
        GrowString(buffer, buffer_size, "<authorizedPortType>", buffer_ndx);
        GrowString(buffer, buffer_size, port_types[ctr], buffer_ndx);
        GrowString(buffer, buffer_size, "</authorizedPortType>\n", buffer_ndx);
    }

    GrowString(buffer, buffer_size, "</GRIMAssertion>\n", buffer_ndx);

    *out_string = buffer;

    return GLOBUS_SUCCESS;
}

