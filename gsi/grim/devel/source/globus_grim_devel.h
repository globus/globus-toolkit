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

#define GLOBUS_GRIM_DEVEL_MODULE (&globus_i_grim_devel_module)
extern globus_module_descriptor_t globus_i_grim_devel_module;

typedef void * globus_grim_config_t;
typedef void * globus_grim_assertion_t;

/*************************************************************************
 *                   external api functions
 ************************************************************************/

/**
 *  @defgroup globus_grim_misc Grim Misc Functions
 */
/**
 *  @ingroup globus_grim_misc
 *
 *  Get the NID for this assertion type.
 *
 *  Gives the user the nid for the grim assertion.  This can then be used
 *  to set a policy.
 *
 *  @param nid
 *         A out parameter.  Uppon completion it will point to an integer
 *         representing the nid.
 */
globus_result_t
globus_grim_devel_get_NID(
    int *                                   nid);
/**
 *  @ingroup globus_grim_misc
 */
globus_result_t
globus_grim_get_default_configuration_filename(
    char **                                 conf_filename);

/**
 *  @defgroup globus_grim_assertion Grim Asserion Functions
 *
 *  These functions are used to extract information from an serialized
 *  assertion and to add information to an ADT to create serialized 
 *  assertion.
 */

/**
 *  @ingroup globus_grim_assertion
 *
 *  Initialize an assertion type.
 *
 *  This function initializes an assertion data type.  All
 *  attributes except subject and username receive default values, because
 *  subject and username are required to have a valid assertion.
 *
 *  @param assertion
 *         An out parameter.  Upon return this will contain the initialized
 *         assertion.
 * 
 *  @param subject
 *         The value to fill the ServiceGridId portion of the assertion.
 *
 *  @param username
 *         The local user name to be associated with the ServiceLocalId
 *         portion of the assertion.
 */
globus_result_t
globus_grim_assertion_init(
    globus_grim_assertion_t *               assertion,
    char *                                  subject,
    char *                                  username);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Initialize an assertion type from a buffer.
 *
 *  This function will parse an assertion and use the values contained
 *  in it to initialize an assertion structure.
 *
 *  @param assertion
 *         An out parameter.  Upon return this will contain the initialized
 *         assertion.
 *
 *  @param buffer
 *         A memory buffer containing the entire assertion xml assertion.
 *
 *  @param buffer_length
 *         The length of the above buffer.
 */
globus_result_t
globus_grim_assertion_init_from_buffer(
    globus_grim_assertion_t *               assertion,
    char *                                  buffer,
    int                                     buffer_length);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Convert an assertion object into serializable xml.
 *
 *  This will convert the assertion object into a memory buffer
 *  that can be written to the proxy file.
 *
 *  @param assertion
 *         The assertion object that the user wishes to serialize.
 *
 *  @param out_assertion_string
 *         An out parameter.  Upon return from this function this
 *         will point to a memory buffer containing the serialzed assertion.
 *         The user will need to free this buffer when they are finished.
 */
globus_result_t
globus_grim_assertion_serialize(
    globus_grim_assertion_t                 assertion,
    char **                                 out_assertion_string);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Destroy an assertion object.
 *
 *  This will clean up an assertion object and all memory associated with
 *  it.
 *
 *  @param assertion
 *         The assertion object ot destroy.
 */
globus_result_t
globus_grim_assertion_destroy(
    globus_grim_assertion_t                 assertion);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Get the subject.
 *
 *  This function returns the subject associated with the assertion to
 *  the user.
 *
 *  @param assertion
 *         The assertion object containing the subject of interest.
 *
 *  @param subject
 *         An out parameter.  Upon completion of this function it will 
 *         point to the subject.  The user should not free or alter this
 *         memory.
 */
globus_result_t
globus_grim_assertion_get_subject(
    globus_grim_assertion_t                 assertion,
    char **                                 subject);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Get the username
 *
 *  This function gets the username associated with the assertion for
 *  the user.
 *
 *  @param assertion
 *         The assertion object containing the username of interest.
 *
 *  @param username
 *         An out parameter.  Upon completion of this function it will 
 *         point to the username.  The user should not free this.
 *
 */
globus_result_t
globus_grim_assertion_get_username(
    globus_grim_assertion_t                 assertion,
    char **                                 username);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Get the dn array.
 *
 *  This function returns the dn array contained in the assertion.
 *
 *  @param assertion
 *         The assertion object that contains the dn_array.
 * 
 *  @param dn_array
 *         An out parameter.  Upon compleition of this function this
 *         will point to an array of dns.  The user should not free or 
 *         alter this memory.
 */
globus_result_t
globus_grim_assertion_get_dn_array(
    globus_grim_assertion_t                 assertion,
    char ***                                dn_array);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Set the dn array.
 *
 *  This function associates a NULL terminated array of dns with
 *  the assertion object.  This will disassociate any previously
 *  set dn_array.
 *
 *  @param assertion
 *         The assertion object on which the dn_array will be set.
 *
 *  @param dn_array
 *         The dn_array to set.
 */
globus_result_t
globus_grim_assertion_set_dn_array(
    globus_grim_assertion_t                 assertion,
    char **                                 dn_array);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Get the port_types array.
 *
 *  This function returns the port types array contained in the assertion.
 *
 *  @param assertion
 *         The assertion object that contains the port types array.
 *
 *  @param port_types_array
 *         An out parameter.  Upon compleition of this function this
 *         will point to an array of port types.  The user should not free or
 *         alter this memory.
 */
globus_result_t
globus_grim_assertion_get_port_types_array(
    globus_grim_assertion_t                 assertion,
    char ***                                port_types_array);

/**
 *  @ingroup globus_grim_assertion
 *
 *  Set the port type array.
 *
 *  This function associates a NULL terminated array of port types with
 *  the assertion object.  This will disassociate any previously
 *  set port type array.
 *
 *  @param assertion
 *         The assertion object on which the port type array will be set.
 *
 *  @param port_types_array
 *         The port_types_array to set.
 */
globus_result_t
globus_grim_assertion_set_port_types_array(
    globus_grim_assertion_t                 assertion,
    char **                                 port_types_array);

/**
 *  @defgroup globus_grim_config Grim Config Functions
 *
 *  These functions are used to extract information from a grim
 *  configuration file, or to get deafult grim configuration values.
 */

/**
 *  @ingroup globus_grim_config
 *
 *  Initialize a configure data type.
 *
 *  This will initialize the configure structure with default values.
 *  
 *  @param config
 *         An out parameter.  Upon return from this function it will point
 *         to the intialized config data type.
 */
globus_result_t
globus_grim_config_init(
    globus_grim_config_t *                  config);

/**
 *  @ingroup globus_grim_config
 *
 *  Destroy a config data type
 *
 *  This will clean up all resources associated with a config data type.
 * 
 *  @param config
 *         The data type to be destroyed.
 */
globus_result_t
globus_grim_config_destroy(
    globus_grim_config_t                    config);

/**
 *  @ingroup globus_grim_config
 *
 *  Load From File
 *
 *  Load the attributes for the config data type from the given file.
 *
 *  @param config
 *         The data type whos attributes will be set from the file.
 *
 *  @param fptr
 *         An open FILE pointer for a configuration file.
 */
globus_result_t
globus_grim_config_load_from_file(
    globus_grim_config_t                    config,
    FILE *                                  fptr);

/**
 *  @ingroup globus_grim_config
 *
 *  Get Max Time
 *
 *  Get the maximum amount of time a proxy may be valid.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param max_time
 *         An out paramter.  Upon Completion of this function it will 
 *         point to a integer representing the maximum number of hours
 *         associated with the config data type.
 */
globus_result_t
globus_grim_config_get_max_time(
    globus_grim_config_t                    config,
    int *                                   max_time);

/**
 *  @ingroup globus_grim_config
 *
 *  Set Max Time
 *
 *  Set the maximum amount of time a proxy may be valid.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param max_time
 *         The maximun amount of time in hours that a proxy may be valid.
 */
globus_result_t
globus_grim_config_set_max_time(
    globus_grim_config_t                    config,
    int                                     max_time);

/**
 *  @ingroup globus_grim_config
 *
 *  Get Default Time
 *
 *  Get the default amount of time a proxy may be valid.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param default_time
 *         An out paramter.  Upon Completion of this function it will 
 *         point to a integer representing the default number of hours
 *         associated with the config data type.
 */
globus_result_t
globus_grim_config_get_default_time(
    globus_grim_config_t                    config,
    int *                                   default_time);

/**
 *  @ingroup globus_grim_config
 *
 *  Set Default Time
 *
 *  Set the default amount of time a proxy may be valid.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param deault_time
 *         The default amount of time in hours that a proxy may be valid.
 */
globus_result_t
globus_grim_config_set_default_time(
    globus_grim_config_t                    config,
    int                                     default_time);

/**
 *  @ingroup globus_grim_config
 *
 *  Get Key Bits
 *
 *  Get the number of bits to be used in the key creation.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param key_bits
 *         An out paramter.  Upon Completion of this function it will 
 *         point to a integer representing the length in bits of the key.
 */
globus_result_t
globus_grim_config_get_key_bits(
    globus_grim_config_t                    config,
    int *                                   key_bits);

/**
 *  @ingroup globus_grim_config
 *
 *  Set Key Bits
 *
 *  Set the number of bits in the key.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param key_bits.
 *         The number of bits to be used in the key.
 */
globus_result_t
globus_grim_config_set_key_bits(
    globus_grim_config_t                    config,
    int                                     key_bits);

/**
 *  @ingroup globus_grim_config
 *
 *  Get the ca certificate directory
 *
 *  Get the path to the ca certificate directory.
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param ca_cert_dir
 *         An out paramter.  Upon Completion of this function it will 
 *         point to a string containing the path to the ca cert dir.
 */
globus_result_t
globus_grim_config_get_ca_cert_dir(
    globus_grim_config_t                    config,
    char **                                 ca_cert_dir);

/**
 *  @ingroup globus_grim_config
 *
 *  Set the ca cert dir
 *
 *  Set the directory path pf the ca certificate.
 *
 *  @param config
 *         The config data type to be queried.
 *  
 *  @param ca_cert_dir
 *         The path to the ca certicates.
 */
globus_result_t
globus_grim_config_set_ca_cert_dir(
    globus_grim_config_t                    config,
    char *                                  ca_cert_dir);

/**
 *  @ingroup globus_grim_config
 *
 *  Get the certificate filename
 *  
 *  Get the path to the certificate
 *  
 *  @param config
 *         The config data type to be queried.
 *
 *  @param cert_filename
 *         An out paramter.  Upon Completion of this function it will
 *         point to a string containing the path to the certificate.
 */
globus_result_t
globus_grim_config_get_cert_filename(
    globus_grim_config_t                    config,
    char **                                 cert_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Set the cert filename
 *
 *  Set the path to the cert filename
 *
 *  @param config
 *         The config data type to be queried.
 * 
 *  @param cert_filename
 *         The path to the certificate.
 */
globus_result_t
globus_grim_config_set_cert_filename(
    globus_grim_config_t                    config,
    char *                                  cert_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Get the key filename
 * 
 *  Get the path to the key
 * 
 *  @param config
 *         The config data type to be queried.
 *
 *  @param key_filename
 *         An out paramter.  Upon Completion of this function it will
 *         point to a string containing the path to the key.
 */
globus_result_t
globus_grim_config_get_key_filename(
    globus_grim_config_t                    config,
    char **                                 key_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Set the key filename
 *
 *  Set the path to the key filename
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param key_filename
 *         The path to the key.
 */
globus_result_t
globus_grim_config_set_key_filename(
    globus_grim_config_t                    config,
    char *                                  key_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Get the gridmap filename
 * 
 *  Get the path to the certificate
 * 
 *  @param config
 *         The config data type to be queried.
 *
 *  @param gridmap_filename
 *         An out paramter.  Upon Completion of this function it will
 *         point to a string containing the path to the gridmap file.
 */
globus_result_t
globus_grim_config_get_gridmap_filename(
    globus_grim_config_t                    config,
    char **                                 gridmap_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Set the gridmap filename.
 *
 *  Set the path to the gridmap filename
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param gridmap_filename
 *         The path to the gridmap file.
 */
globus_result_t
globus_grim_config_set_gridmap_filename(
    globus_grim_config_t                    config,
    char *                                  gridmap_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Get the port type filename
 * 
 *  Get the path to the port type file.
 * 
 *  @param config
 *         The config data type to be queried.
 *
 *  @param max_time
 *         An out paramter.  Upon Completion of this function it will
 *         point to a string containing the path to the port type file.
 */
globus_result_t
globus_grim_config_get_port_type_filename(
    globus_grim_config_t                    config,
    char **                                 port_type_filename);

/**
 *  @ingroup globus_grim_config
 *
 *  Set the port type filename.
 *
 *  Set the path to the port type filename
 *
 *  @param config
 *         The config data type to be queried.
 *
 *  @param port_type_filename
 *         The path to the port type file.    
 */
globus_result_t
globus_grim_config_set_port_type_filename(
    globus_grim_config_t                    config,
    char *                                  port_type_filename);

/** 
 *  @defgroup globus_grim_port_type Grim Port Type Functions
 *  
 *  These function provide a way to parse out port types associate with
 *  groups and/or users.
 */

/**
 *  @ingroup globus_grim_port_type
 *
 *  Parse the port type file
 * 
 *  parse the port type file for all port types associated with the
 *  give user and groups.
 *
 *  @param fptr
 *         A file pointer of the open port type file.
 * 
 *  @param username
 *         The user name for which to look up port types.  If this
 *         is null port types associated with any user will be returned.
 *
 *  @param groups
 *         a null termintaed array of group names for which port_types
 *         will be looked up.
 * 
 *  @param port_types
 *         An out parameter.  Upon completion of this function this will
 *         point to a null terminated array.  The user will need to free this
 *         array.
 */
globus_result_t
globus_grim_devel_port_type_file_parse(
    FILE *                                  fptr,
    char *                                  username,
    char **                                 groups,
    char ***                                port_types);

/**
 *  @ingroup globus_grim_port_type
 *
 *  Parse a port type file
 *
 *  parse the port type file for all port types independent of what 
 *  users and groups are associated.
 *
 *  @param fptr
 *         A file pointer of the open port type file.
 * 
 *  @param port_types
 *         An out parameter.  Upon completion of this function this will
 *         point to a null terminated array.  
 *
 */
globus_result_t
globus_grim_devel_get_all_port_types(
    FILE *                                  fptr,
    char ***                                port_types);

/**
 *  @ingroup globus_grim_port_type
 *
 *  Parse a port type file
 *
 *  parse the port type file for all port types assocaited with the
 *  current user (getuid()) and the groups to which that user belongs.
 *
 *  @param fptr
 *         A file pointer of the open port type file.
 *
 *  @param port_types
 *         An out parameter.  Upon completion of this function this will
 *         point to a null terminated array.
 *
 */
globus_result_t
globus_grim_devel_port_type_file_parse_uid(
    FILE *                                  fptr,
    char ***                                port_types);


#endif /* GLOBUS_GRIM_DEVEL_H */
