#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_sysconfig_system_config.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_i_gsi_system_config.h"
#include "globus_gsi_cert_utils.h"
#include <openssl/rand.h>
#include <errno.h>
#include "version.h"

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif
#endif

#ifdef WIN32
#include "winglue.h"
#include <io.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#endif

#define X509_CERT_DIR                   "X509_CERT_DIR"
#define X509_CERT_FILE                  "X509_CERT_FILE"
#define X509_USER_PROXY                 "X509_USER_PROXY"
#define X509_USER_CERT                  "X509_USER_CERT"
#define X509_USER_KEY                   "X509_USER_KEY"
#define X509_UNIQUE_PROXY_FILE          "x509up_p"
#define X509_USER_PROXY_FILE            "x509up_u"
#define SIGNING_POLICY_FILE_EXTENSION   ".signing_policy"

/* This is added after the CA name hash to make the policy filename */
#define SIGNING_POLICY_FILE_EXTENSION   ".signing_policy"

#ifdef WIN32
#define FILE_SEPERATOR "\\"
#define GSI_REGISTRY_DIR                "software\\Globus\\GSI"
#define X509_DEFAULT_USER_CERT          ".globus\\usercert.pem"
#define X509_DEFAULT_USER_KEY           ".globus\\userkey.pem"
#define X509_DEFAULT_PKCS12_FILE        ".globus\\usercred.p12"
#define X509_DEFAULT_TRUSTED_CERT_DIR   "SLANG: NEEDS TO BE DETERMINED"
#define X509_INSTALLED_TRUSTED_CERT_DIR "SLANG: NEEDS TO BE DETERMINED"
#define X509_LOCAL_TRUSTED_CERT_DIR     ".globus\\certificates"
#define X509_DEFAULT_CERT_DIR           "SLANG: NEEDS TO BE DETERMINED"
#define X509_INSTALLED_CERT_DIR         "etc"
#define X509_LOCAL_CERT_DIR             ".globus"
#else
#define FILE_SEPERATOR                  "/"
#define X509_DEFAULT_USER_CERT          ".globus/usercert.pem"
#define X509_DEFAULT_USER_KEY           ".globus/userkey.pem"
#define X509_DEFAULT_PKCS12_FILE        ".globus/usercred.p12"
#define X509_DEFAULT_TRUSTED_CERT_DIR   "/etc/grid-security/certificates"
#define X509_INSTALLED_TRUSTED_CERT_DIR "share/certificates"
#define X509_LOCAL_TRUSTED_CERT_DIR     ".globus/certificates"
#define X509_DEFAULT_CERT_DIR           "/etc/grid-security"
#define X509_INSTALLED_CERT_DIR         "etc"
#define X509_LOCAL_CERT_DIR             ".globus"
#endif

#define X509_HOST_PREFIX                "host"
#define X509_CERT_SUFFIX                "cert.pem"
#define X509_KEY_SUFFIX                 "key.pem"

#define X509_HASH_LENGTH                8

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#define GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_SYSCONFIG_MODULE, \
        errno, \
        GLOBUS_GSI_SYSCONFIG_ERROR_ERRNO, \
        "%s:%d: Could not allocate enough memory", \
        __FILE__, __LINE__))


int                                     globus_i_gsi_sysconfig_debug_level;
FILE *                                  globus_i_gsi_sysconfig_debug_fstream;

static int globus_l_gsi_sysconfig_activate(void);
static int globus_l_gsi_sysconfig_deactivate(void);

int globus_i_gsi_sysconfig_debug_level = 0;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_sysconfig_module =
{
    "globus_credential",
    globus_l_gsi_sysconfig_activate,
    globus_l_gsi_sysconfig_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_sysconfig_activate(void)
{
    int                                 result;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_sysconfig_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSI_SYSCONFIG_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_sysconfig_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_sysconfig_debug_level < 0)
        {
            globus_i_gsi_sysconfig_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_SYSCONFIG_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_sysconfig_debug_fstream = fopen(tmp_string, "w");
        if(globus_i_gsi_sysconfig_debug_fstream == NULL)
        {
            result = GLOBUS_NULL;
            goto exit;
        }
    }
    else
    {
        /* if the env. var. isn't set, use stderr */
        globus_i_gsi_sysconfig_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_sysconfig_deactivate(void)
{
    int                                 result;
    static char *                       _function_name_ =
        "globus_l_gsi_sysconfig_deactivate";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    fclose(globus_i_gsi_sysconfig_debug_fstream);
    return result;
}
/* globus_l_gsi_proxy_deactivate() */


globus_result_t
globus_i_gsi_sysconfig_create_cert_dir_string(
    char **                             cert_dir,
    char **                             cert_dir_value,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_gsi_statcheck_t              status;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_create_cert_dir_string";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *cert_dir = NULL;

    globus_libc_lock();

    va_start(ap, format);

    *cert_dir_value = globus_gsi_cert_utils_v_create_string(format, ap);

    if(*cert_dir_value == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }
     
    result = GLOBUS_I_GSI_SYSCONFIG_FILE_EXISTS(*cert_dir_value, &status);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_DIR);
        goto exit;
    }

    if(format && status == GLOBUS_VALID)
    {
        *cert_dir = *cert_dir_value;
    }
   
    va_end(ap);

    result = GLOBUS_SUCCESS;

 exit:

    globus_libc_unlock();
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
    

globus_result_t
globus_i_gsi_sysconfig_create_cert_string(
    char **                             cert_string,
    char **                             cert_string_value,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_gsi_statcheck_t              status;
    globus_result_t                     result;
    
    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_create_cert_string";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *cert_string = NULL;

    globus_libc_lock();

    va_start(ap, format);

    *cert_string_value = globus_gsi_cert_utils_v_create_string(format, ap);

    if(*cert_string_value == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }

    result = GLOBUS_I_GSI_SYSCONFIG_CHECK_CERTFILE(*cert_string_value, &status);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_STRING);
        goto exit;
    }

    if(format && status == GLOBUS_VALID)
    {
        *cert_string = *cert_string_value;
    }
    
    va_end(ap);
    
    result = GLOBUS_SUCCESS;

 exit:

    globus_libc_unlock();
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_sysconfig_create_key_string(
    char **                             key_string,
    char **                             key_string_value,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_gsi_statcheck_t              status;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_create_key_string";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *key_string = NULL;

    globus_libc_lock();

    va_start(ap, format);

    *key_string_value = globus_gsi_cert_utils_v_create_string(format, ap);
    
    if(*key_string_value == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }

    result = GLOBUS_I_GSI_SYSCONFIG_CHECK_KEYFILE(*key_string_value, &status);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_KEY_STRING);
        goto exit;
    }

    if(format && status == GLOBUS_VALID)
    {
        *key_string = *key_string_value;
    }

    va_end(ap);

    result = GLOBUS_SUCCESS;

 exit:

    globus_libc_unlock();
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#ifdef WIN32  /* define all the *_win32 functions */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * WIN32 - Get HOME Directory
 * @ingroup globus_i_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the HOME directory, currently c:\windows
 * 
 * @param home_dir
 *        The home directory of the current user
 * @return
 *        GLOBUS_SUCCESS if no error occured, otherwise
 *        an error object is returned.
 */
globus_result_t
globus_i_gsi_sysconfig_get_home_dir_win32(
    char **                             home_dir)
{
    globus_result_t                     result;

    const char *                        _function_name_ =
        "globus_i_gsi_sysconfig_get_home_dir_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *home_dir = "c:\\windows";

    if((*home_dir) == NULL)
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_HOME_DIR,
            ("Could not get a home directory for this machine"));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * WIN32 - File Exists
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Check that the file exists
 *
 * @param filename the file to check
 * @param status   the status of the file
 *
 * @return 
 *        GLOBUS_SUCCESS (even if the file doesn't exist) - in some
 *        abortive cases an error object identifier is returned
 */
globus_result_t
globus_i_gsi_sysconfig_file_exists_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    globus_result_t                     result;
    struct stat                         stx;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_file_exists_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;

        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIGENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_ERRNO,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    *status = GLOBUS_VALID;
    
 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}    
/* @} */


/**
 * WIN32 - Check File Status for Key
 * @ingroup globus_i_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * This is a convenience function used to check the status of a 
 * private key file.  The desired status is only the current user has
 * ownership and read permissions, everyone else should not be able
 * to access it.
 * 
 * @param filename
 *        The name of the file to check the status of
 * @param status
 *        The status of the file being checked
 *        see @ref globus_gsi_statcheck_t for possible values
 *        of this variable 
 *
 * @return 
 *        GLOBUS_SUCCESS if the status of the file was able
 *        to be determined.  Otherwise, an error object
 *        identifier
 *
 * @see globus_gsi_statcheck_t
 */
globus_result_t
globus_i_gsi_sysconfig_check_keyfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    struct stat                         stx;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_check_keyfile_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;

        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIGENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_KEY_STRING,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
    }

    *status = GLOBUS_VALID;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * WIN32 - Check File Status for Cert
 * @ingroup globus_i_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * This is a convenience function used to check the status of a 
 * certificate file.  The desired status is the current user has
 * ownership and read/write permissions, while group and others only
 * have read permissions.
 * 
 * @param filename
 *        The name of the file to check the status of
 * @param status
 *        The status of the file being checked
 *        see @ref globus_gsi_statcheck_t for possible values
 *        of this variable 
 *
 * @return 
 *        GLOBUS_SUCCESS if the status of the file was able
 *        to be determined.  Otherwise, an error object
 *        identifier
 *
 * @see globus_gsi_statcheck_t
 */
globus_result_t
globus_i_gsi_sysconfig_check_certfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    globus_result_t                     result;
    struct stat                         stx;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_check_certfile_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
 
    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;

        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIGENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_STRING,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
    }

    *status = GLOBUS_VALID;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * WIN32 - Get User ID
 * @ingroup globus_i_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get a unique string representing the current user.  
 * On Windows, SLANG: NOT DETERMINED
 */
globus_result_t
globus_i_gsi_sysconfig_get_user_id_string_win32(
    char **                             user_id_string)
{
    int                                 uid;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_get_user_id_string_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    /* SLANG: need to set the string to the username or whatever */

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * WIN32 - Get Process ID
 * @ingroup globus_i_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get a unique string representing the current process.  
 * On Windows, SLANG: NOT DETERMINED
 */
globus_result_t
globus_i_gsi_sysconfig_get_proc_id_string_win32(
    char **                             proc_id_string)
{
    int                                 uid;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_get_proc_id_string_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    /* SLANG: need to set the string to the process name or whatever */

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    
    return GLOBUS_SUCCESS;
}
/* @} */

#endif

/**
 * WIN32 - Get Trusted CA Cert Dir
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the Trusted Certificate Directory containing the trusted
 * Certificate Authority certificates.  This directory is determined
 * in the order shown below.  Failure in one method results in attempting
 * the next.
 *
 * <ol>
 * <li> <b>X509_CERT_DIR environment variable</b> - if this is set, the
 * trusted certificates will be searched for in that directory.  This
 * variable allows the end user to specify the location of trusted
 * certificates.
 * <li> <b>"x509_cert_dir" registry key</b> - If
 * this registry key is set on windows, the directory it points to should
 * contain the trusted certificates.  The path to the registry key is
 * software\Globus\GSI
 * <li> <b>\<user home directory\>\.globus\certificates</b> - If this
 * directory exists, and the previous methods of determining the trusted
 * certs directory failed, this directory will be used.  
 * <li> <b>Host Trusted Cert Dir</b> - This location is intended
 * to be independant of the globus installation ($GLOBUS_LOCATION), and 
 * is generally only writeable by the host system administrator.  
 * SLANG: This value is not currently set for WINDOWS
 * <li> <b>Globus Install Trusted Cert Dir</b> - this
 * is $GLOBUS_LOCATION\share\certificates.  
 * </ol>
 *
 * @param cert_dir
 *        The trusted certificates directory
 * @return
 *        GLOBUS_SUCCESS if no error occurred, and a sufficient trusted
 *        certificates directory was found.  Otherwise, an error object 
 *        identifier returned.
 */
globus_result_t
globus_gsi_sysconfig_get_cert_dir_win32(
    char **                             cert_dir)
{
    char *                              env_cert_dir = NULL;
    char *                              val_cert_dir[512];
    char *                              reg_cert_dir = NULL;
    char *                              local_cert_dir = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
    int                                 len;    
    HKEY                                hkDir = NULL;
    globus_result_t                     result;
    char *                              home;
    char *                              globus_location;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_cert_dir_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *cert_dir = NULL;

    if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                     cert_dir, 
                     & env_cert_dir,
                     getenv(X509_CERT_DIR))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    if (!(*cert_dir))
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_cert_dir)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_dir",0,&type,
                                      val_cert_dir,&lval) == ERROR_SUCCESS))
        {
            if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                             cert_dir, 
                             & reg_cert_dir,
                             val_cert_dir)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
        RegCloseKey(hkDir);
    }

    /* now check for a trusted CA directory in the user's home directory */
    if(!(*cert_dir))
    {
        if((result = globus_i_gsi_sysconfig_get_home_dir(&home)) != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
            
        if (home) 
        {
            if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                             cert_dir, 
                             & local_cert_dir,
                             "%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now look in $GLOBUS_LOCATION/share/certificates */
    if (!(*cert_dir))
    {
        if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                         cert_dir,
                         & installed_cert_dir,
                         X509_INSTALLED_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
    }

    /* now check for host based default directory */
    if (!(*cert_dir))
    {
        globus_location = getenv("GLOBUS_LOCATION");
        
        if (globus_location)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                             cert_dir,
                             & default_cert_dir,
                             "%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_DEFAULT_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
        1, (stderr, "Using cert_dir = %s\n", 
            (*cert_dir ? *cert_dir : "null")));

    if(!(*cert_dir))
    {
        result = globus_error_put(globus_error_construct_string(
            GLOBUS_GSI_SYSCONFIGENTIAL_MODULE,
            NULL,
            "The trusted certificates directory could not be"
            "found in any of the following locations: \n"
            "1) env. var. X509_CERT_DIR=%s\n"
            "2) registry key x509_cert_dir: %s\n"
            "3) %s\n4) %s\n5) %s\n",
            env_cert_dir,
            reg_cert_dir,
            local_cert_dir,
            installed_cert_dir,
            default_cert_dir));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done:

  error_exit:
    
    if(*cert_dir)
    {
        globus_free(*cert_dir);
        *cert_dir = NULL;
    }

 done:

    if(env_cert_dir && (env_cert_dir != (*cert_dir)))
    {
        globus_free(env_cert_dir);
    }
    if(reg_cert_dir && (reg_cert_dir != (*cert_dir)))
    {
        globus_free(reg_cert_dir);
    }
    if(local_cert_dir && (local_cert_dir != (*cert_dir)))
    {
        globus_free(local_cert_dir);
    }
    if(installed_cert_dir && (installed_cert_dir != (*cert_dir)))
    {
        globus_free(installed_cert_dir);
    }
    if(default_cert_dir && (default_cert_dir != (*cert_dir)))
    {
        globus_free(default_cert_dir);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * WIN32 - Get User Certificate Filename
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the User Certificate Filename based on the current user's
 * environment.  The following locations are searched for cert and key
 * files in order:
 * 
 * <ol>
 * <li>environment variables X509_USER_CERT and X509_USER_KEY
 * <li>registry keys x509_user_cert and x509_user_key in software\Globus\GSI
 * <li><users home directory>\.globus\usercert.pem and 
 *     <users home directory>\.globus\userkey.pem
 * <li><users home directory\.globus\usercred.p12 - this is a PKCS12 credential
 * </ol>
 *
 * @param user_cert
 *        pointer the filename of the user certificate
 * @param user_key
 *        pointer to the filename of the user key
 * @return
 *        GLOBUS_SUCCESS if the cert and key files were found in one
 *        of the possible locations, otherwise an error object identifier
 *        is returned
 */
globus_result_t
globus_gsi_sysconfig_get_user_cert_filename_win32(
    char **                             user_cert,
    char **                             user_key)
{
    int                                 len;
    char *                              home = NULL;
    char *                              env_user_cert = NULL;
    char *                              env_user_key = NULL;
    char *                              reg_user_cert = NULL;
    char *                              reg_user_key = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_pkcs12_user_cred = NULL;
    globus_result_t                     result;
    HKEY                                hkDir = NULL;
    char                                val_user_cert[512];
    char                                val_user_key[512];

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_user_cert_filename_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *user_cert = NULL;
    *user_key = NULL;

    /* first, check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     user_cert,
                     & env_user_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_cert_string(
                     user_key,
                     & env_user_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
       
    /* next, check windows registry keys for valid filenames */

    if(!(*user_cert) || !(*user_key))
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_user_cert)-1;
        if (hkDir && (RegQueryValueEx(
                          hkDir,
                          "x509_user_cert",
                          0,
                          &type,
                          val_user_cert,&lval) == ERROR_SUCCESS))
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             user_cert,
                             & reg_user_cert,
                             val_user_cert)) != GLOBUS_SUCCESS ||
                (result = globus_i_gsi_sysconfig_create_key_string(
                              user_key,
                              & reg_user_key,
                              val_user_key)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
        RegCloseKey(hkDir);
    }


    /* next, check default locations */
    if(!(*user_cert) || !(*user_key))
    {
        if(GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             user_cert,
                             & default_user_cert,
                             "%s%s%s",
                             home,
                             DEFEAULT_SEPERATOR,
                             X509_DEFAULT_USER_CERT)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                              key_cert,
                              & default_key_cert,
                              "%s%s%s",
                              home,
                              DEFAULT_SEPERATOR,
                              X509_DEFAULT_USER_KEY)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* if the cert & key don't exist in the default locations
     * or those specified by the environment variables, a
     * pkcs12 cert will be searched for
     */
    if(!(*user_cert) || !(*user_key))
    {
        if((result = globus_i_gsi_sysconfig_get_home_dir(&home)) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_key_string(
                              user_key,
                              & default_pkcs12_user_cred,
                              "%s%s%s",
                              home,
                              FILE_SEPERATOR,
                              X509_DEFAULT_PKCS12_FILE)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
            *user_cert = *user_key;
        }
    }

    if(!(*user_cert) || !(*user_key))
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) registry key x509_user_cert: %s\n"
             "3) %s\n4) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) registry key x509_user_key: %s\n"
             "3) %s\n4) %s\n",
             env_user_cert,
             reg_user_cert,
             default_user_cert,
             default_pkcs12_user_cred,
             env_user_key,
             reg_user_key,
             default_user_key,
             default_pkcs12_user_cred));

        goto error_exit;
    }

#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            (*user_cert) ? (*user_cert) : NULL, 
            (*user_key) ? (*user_key) : NULL);
#endif

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:
    
    if(*user_cert)
    {
        globus_free(*user_cert);
        *user_cert = NULL;
    }
    if(*user_key)
    {
        globus_free(*user_key);
        *user_key = NULL;
    }

 done:

    if(env_user_cert && env_user_cert != (*user_cert))
    {
        globus_free(env_user_cert);
    }
    if(env_user_key && env_user_key != (*user_key))
    {
        globus_free(env_user_key);
    }
    if(default_user_cert && default_user_cert != (*user_cert))
    {
        globus_free(default_user_cert);
    }
    if(default_user_key && default_user_key != (*user_key))
    {
        globus_free(default_user_key);
    }
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    
    return result;
}
/* @} */

/**
 * WIN32 - Get Host Certificate and Key Filenames
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the Host Certificate and Key Filenames based on the current user's
 * environment.  The host cert and key are searched for in the following 
 * locations (in order):
 *
 * <ol>
 * <li>X509_USER_CERT and X509_USER_KEY environment variables
 * <li>registry keys x509_user_cert and x509_user_key in software\Globus\GSI
 * <li>SLANG: NOT DETERMINED - this is the default location
 * <li><GLOBUS_LOCATION>\etc\host[cert|key].pem
 * <li><users home directory>\.globus\host[cert|key].pem
 * </ol>
 * 
 * @param host_cert
 *        pointer to the host certificate filename
 * @param host_key
 *        pointer to the host key filename
 *
 * @return
 *        GLOBUS_SUCCESS if the host cert and key were found, otherwise
 *        an error object identifier is returned 
 */
globus_result_t
globus_gsi_sysconfig_get_host_cert_filename_win32(
    char **                             host_cert,
    char **                             host_key)
{
    int                                 len;
    char *                              home = NULL;
    char *                              host_cert = NULL;
    char *                              host_key = NULL;
    char *                              env_host_cert = NULL;
    char *                              env_host_key = NULL;
    char *                              reg_host_cert = NULL;
    char *                              reg_host_key = NULL;
    char *                              default_host_cert = NULL;
    char *                              default_host_key = NULL;
    char *                              installed_host_cert = NULL;
    char *                              installed_host_key = NULL;
    char *                              local_host_cert = NULL;
    char *                              local_host_key = NULL;
    globus_result_t                     result;

    HKEY                                hkDir = NULL;
    char                                val_host_cert[512];
    char                                val_host_key[512];

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_host_cert_filename_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *host_cert = NULL;
    *host_key = NULL;

    /* first check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     host_cert,
                     & env_host_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_key_string(
                     host_key,
                     & env_host_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* now check the windows registry for valid filenames */
    if(!(*host_cert) || !(*host_key))
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_host_cert)-1;
        if (hkDir && (RegQueryValueEx(hkDir,
                                      "x509_user_cert",
                                      0,
                                      &type,
                                      val_host_cert,
                                      &lval) == ERROR_SUCCESS))
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & reg_host_cert,
                             val_host_cert)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_cert_string(
                             host_key,
                             & reg_host_key,
                             val_host_key)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
        RegCloseKey(hkDir);
    }

    /* now check default locations for valid filenames */
    if(!(*host_cert) || !(*host_key))
    {
        if((result = globus_i_gsi_sysconfig_get_home_dir(&home)) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & default_host_cert,
                             "%s%s%s%s",
                             X509_DEFAULT_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                              host_key,
                              & default_key_cert,
                              "%s%s%s%s",
                              X509_DEFAULT_CERT_DIR,
                              FILE_SEPERATOR,
                              X509_HOST_PREFIX,
                              X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now check intstalled location for host cert */
    if(!(*host_cert) || !(*host_key))
    {
        globus_location = getenv("GLOBUS_LOCATION");

        if(globus_location)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & installed_host_cert,
                             "%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                             host_key,
                             & installed_host_key,
                             "%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    if(!(*host_cert) || !(*host_key))
    {
        if(GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & local_host_cert,
                             "%s%s%s%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                             host_key,
                             & local_key_cert,
                             "%s%s%s%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            host_cert, host_key);
#endif

    if(!(*host_cert) || !(*host_key))
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) registry key x509_user_cert: %s\n"
             "3) %s\n4) %s5) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) registry key x509_user_key: %s\n"
             "3) %s\n4) %s5) %s\n",
             env_host_cert,
             reg_host_cert,
             default_host_cert,
             installed_host_cert,
             local_host_cert,
             env_host_key,
             reg_host_key,
             default_host_key,
             installed_host_key,
             local_host_key));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:

    if(*host_cert)
    {
        globus_free(*host_cert);
        *host_cert = NULL;
    }
    if(*host_key)
    {
        globus_free(*host_key);
        *host_key = NULL;
    }

 done:

    if(env_host_cert && env_host_cert != *host_cert)
    {
        globus_free(env_host_cert);
    }
    if(env_host_key && env_host_key != *host_key)
    {
        globus_free(env_host_key);
    }
    if(reg_host_cert && reg_host_cert != *host_cert)
    {
        globus_free(reg_host_cert);
    }
    if(reg_host_key && reg_host_key != *host_key)
    {
        globus_free(reg_host_key);
    }
    if(installed_host_cert && installed_host_cert != *host_cert)
    {
        globus_free(installed_host_cert);
    }
    if(installed_host_key && installed_host_key != *host_key)
    {
        globus_free(installed_host_key);
    }
    if(local_host_cert && local_host_cert != *host_cert)
    {
        globus_free(local_host_cert);
    }
    if(local_host_key && local_host_key != *host_key)
    {
        globus_free(local_host_key);
    }
    if(default_host_cert && default_host_cert != host_cert)
    {
        globus_free(default_host_cert);
    }
    if(default_host_key && default_host_key != host_key)
    {
        globus_free(default_host_key);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * WIN32 - Get Service Certificate and Key Filenames
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the Service Certificate Filename based on the current user's
 * environment.  The host cert and key are searched for in the following 
 * locations (in order):
 *
 * <ol>
 * <li>X509_USER_CERT and X509_USER_KEY environment variables
 * <li>registry keys x509_user_cert and x509_user_key in software\Globus\GSI
 * <li>SLANG: NOT DETERMINED - this is the default location
 * <li>GLOBUS_LOCATION\etc\{service_name}\{service_name}[cert|key].pem
 *     So for example, if my service was named: myservice, the location
 *     of the certificate would be: 
 *     GLOBUS_LOCATION\etc\myservice\myservicecert.pem
 * <li><users home>\.globus\{service_name}\{service_name}[cert|key].pem
 * </ol>
 * 
 * @param service_name
 *        The name of the service which allows us to determine the
 *        locations of cert and key files to look for
 * @param service_cert
 *        pointer to the host certificate filename
 * @param service_key
 *        pointer to the host key filename
 *
 * @return
 *        GLOBUS_SUCCESS if the service cert and key were found, otherwise
 *        an error object identifier 
 */
globus_result_t
globus_gsi_sysconfig_get_service_cert_filename_win32(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename)
{
    int                                 len;
    char *                              home = NULL;
    char *                              service_cert = NULL;
    char *                              service_key = NULL;
    char *                              env_service_cert = NULL;
    char *                              env_service_key = NULL;
    char *                              reg_service_cert = NULL;
    char *                              reg_service_key = NULL;
    char *                              default_service_cert = NULL;
    char *                              default_service_key = NULL;
    char *                              installed_service_cert = NULL;
    char *                              installed_service_key = NULL;
    char *                              local_service_cert = NULL;
    char *                              local_service_key = NULL;
    globus_result_t                     result;

    HKEY                                hkDir = NULL;
    char                                val_service_cert[512];
    char                                val_service_key[512];

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_service_cert_filename_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *service_cert = NULL;
    *service_key = NULL;

    /* first check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     service_cert,
                     & env_service_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_key_string(
                     service_key,
                     & env_service_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* now check the windows registry for valid filenames */
    if(!(*service_cert) || !(*service_key))
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_service_cert)-1;
        if (hkDir && (RegQueryValueEx(hkDir,
                                      "x509_user_cert",
                                      0,
                                      &type,
                                      val_service_cert,
                                      &lval) == ERROR_SUCCESS))
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             service_cert,
                             & reg_service_cert,
                             val_service_cert)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_cert_string(
                             service_key,
                             & reg_service_key,
                             val_service_key)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
        RegCloseKey(hkDir);
    }


    /* now check default locations for valid filenames */
    if(!(*service_cert) || !(*service_key))
    {
        if((result = globus_i_gsi_sysconfig_get_home_dir(&home)) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             service_cert,
                             & default_service_cert,
                             "%s%s%s%s%s%s",
                             X509_DEFAULT_CERT_DIR,
                             FILE_SEPERATOR,
                             service_name,
                             FILE_SEPERATOR,
                             service_name,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                              service_key,
                              & default_key_cert,
                              "%s%s%s%s%s%s",
                              X509_DEFAULT_CERT_DIR,
                              FILE_SEPERATOR,
                              service_name,
                              FILE_SEPERATOR,
                              service_name,
                              X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now check intstalled location for service cert */
    if(!(*service_cert) || !(*service_key))
    {
        globus_location = getenv("GLOBUS_LOCATION");

        if(globus_location)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             service_cert,
                             & installed_service_cert,
                             "%s%s%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             service_name,
                             FILE_SEPERATOR,
                             service_name,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                             service_key,
                             & installed_service_key,
                             "%s%s%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             service_name,
                             FILE_SEPERATOR,
                             service_name,
                             X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    if(!(*service_cert) || !(*service_key))
    {
        if(GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             service_cert,
                             & local_service_cert,
                             "%s%s%s%s%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_CERT_DIR,
                             FILE_SEPERATOR,
                             service_name,
                             FILE_SEPERATOR,
                             service_name,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                             service_key,
                             & local_key_cert,
                             "%s%s%s%s%s%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_CERT_DIR,
                             FILE_SEPERATOR,
                             service_name,
                             FILE_SEPERATOR,
                             service_name,
                             X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            service_cert, service_key);
#endif

    if(!(*service_cert) || !(*service_key))
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) registry key x509_user_cert: %s\n"
             "3) %s\n4) %s5) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) registry key x509_user_key: %s\n"
             "3) %s\n4) %s5) %s\n",
             env_service_cert,
             reg_service_cert,
             default_service_cert,
             installed_service_cert,
             local_service_cert,
             env_service_key,
             reg_service_key,
             default_service_key,
             installed_service_key,
             local_service_key));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:

    if(*service_cert)
    {
        globus_free(*service_cert);
        *service_cert = NULL;
    }
    if(*service_key)
    {
        globus_free(*service_key);
        *service_key = NULL;
    }

 done:

    if(env_service_cert && env_service_cert != *service_cert)
    {
        globus_free(env_service_cert);
    }
    if(env_service_key && env_service_key != *service_key)
    {
        globus_free(env_service_key);
    }
    if(reg_service_cert && reg_service_cert != *service_cert)
    {
        globus_free(reg_service_cert);
    }
    if(reg_service_key && reg_service_key != *service_key)
    {
        globus_free(reg_service_key);
    }
    if(installed_service_cert && installed_service_cert != *service_cert)
    {
        globus_free(installed_service_cert);
    }
    if(installed_service_key && installed_service_key != *service_key)
    {
        globus_free(installed_service_key);
    }
    if(local_service_cert && local_service_cert != *service_cert)
    {
        globus_free(local_service_cert);
    }
    if(local_service_key && local_service_key != *service_key)
    {
        globus_free(local_service_key);
    }
    if(default_service_cert && default_service_cert != service_cert)
    {
        globus_free(default_service_cert);
    }
    if(default_service_key && default_service_key != service_key)
    {
        globus_free(default_service_key);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * WIN32 - Get Proxy Filename
 * @ingroup globus_gsi_sysconfig_system_config_win32
 */
/* @{ */
/**
 * Get the proxy cert filename based on the following
 * search order:
 * 
 * <ol>
 * <li> X509_USER_PROXY environment variable - This environment variable
 * is set by the at run time for the specific application.  If
 * the proxy_file_type variable is set to GLOBUS_PROXY_OUTPUT
 *  (a proxy filename for writing is requested), 
 * and the X509_USER_PROXY is set, this will be the 
 * resulting value of the user_proxy filename string passed in.  If the
 * proxy_file_type is set to GLOBUS_PROXY_INPUT and X509_USER_PROXY is 
 * set, but the file it points to does not exist, 
 * or has some other readability issues, the 
 * function will continue checking using the other methods available.
 * 
 * <li> check the registry key: x509_user_proxy.  Just as with
 * the environment variable, if the registry key is set, and proxy_file_type
 * is GLOBUS_PROXY_OUTPUT, the string set to be the proxy 
 * filename will be this registry
 * key's value.  If proxy_file_type is GLOBUS_PROXY_INPUT, and the 
 * file doesn't exist, the function will check the next method 
 * for the proxy's filename.
 * 
 * <li> Check the default location for the proxy file.  The default
 * location should be 
 * set to reside in the temp directory on that host, with the filename
 * taking the format:  x509_u<user id>
 * where <user id> is some unique string for that user on the host
 * </ol>
 *
 * @param user_proxy
 *        the proxy filename of the user
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_sysconfig_get_proxy_filename_win32(
    char **                             user_proxy,
    globus_gsi_proxy_file_type_t        proxy_file_type)
{
    char *                              env_user_proxy = NULL;
    char *                              env_value = NULL;
    char *                              default_user_proxy = NULL;
    char *                              reg_user_proxy = NULL;
    HKEY                                hkDir = NULL;
    char                                val_user_proxy[512];
    int                                 len;
    globus_result_t                     result;
    char *                              user_id_string;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_proxy_filename_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *user_proxy = NULL;

    if((env_value = getenv(X509_USER_PROXY)) != NULL &&
       (result = globus_i_gsi_sysconfig_create_key_string(
                     user_proxy,
                     & env_user_proxy,
                     getenv(X509_USER_PROXY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    /* check if the proxy file type is for writing */
    if(!(*user_proxy) && env_user_proxy && proxy_file == GLOBUS_PROXY_OUTPUT)
    {
        *user_proxy = env_user_proxy;
    }

    if (!(*user_proxy))
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_user_proxy)-1;
        if (hkDir && (RegQueryValueEx(hkDir, "x509_user_proxy", 0, &type,
                                      val_user_proxy, &lval) == ERROR_SUCCESS))
        {
            if((result = globus_i_gsi_sysconfig_create_key_string(
                             proxy_cert,
                             & reg_user_proxy,
                             val_user_proxy)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
        RegCloseKey(hkDir);
    }

    if(!(*user_proxy) && reg_user_proxy && proxy_file == GLOBUS_PROXY_OUTPUT)
    {
        *user_proxy = reg_user_proxy;
    }

    if (!user_proxy)
    {
        if((result = globus_i_gsi_sysconfig_get_user_id_string(&user_id_string))
           != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
        if((result = globus_i_gsi_sysconfig_create_key_string(
                          user_proxy,
                          & default_user_proxy,
                          "%s%s%s%s",
                          DEFAULT_SECURE_TMP_DIR,
                          FILE_SEPERATOR,
                          X509_USER_PROXY_FILE,
                          user_id_string)) != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
    }

    if(!(*user_proxy) && 
       default_user_proxy && 
       proxy_file_type == GLOBUS_PROXY_FILE_OUTPUT)
    {
        *user_proxy = default_user_proxy;
    }

    if(!(*user_proxy))
    {            
        result = GLOBUS_GSI_SYSCONFIG_ERROR_RESULT( 
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME,
            ("A file location for%s the proxy cert could be found in: \n"
             "1) env. var. X509_USER_PROXY=%s\n"
             "2) registry key x509_user_proxy: %s\n"
             "3) %s\n",
             (proxy_file_type == GLOBUS_PROXY_FILE_INPUT) ? "" : " writing",
             env_user_proxy,
             reg_user_proxy,
             default_user_proxy));
        
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:
    
    if(*user_proxy)
    {
        globus_free(*user_proxy);
        *user_proxy = NULL;
    }

 done:

    if(reg_user_proxy && (reg_user_proxy != (*user_proxy)))
    {
        globus_free(reg_user_proxy);
    }
    if(default_user_proxy && (default_user_proxy != (*default_user_proxy)))
    {
        globus_free(default_user_proxy);
    }
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

globus_result_t
globus_gsi_sysconfig_get_ca_cert_file_win32(
    char *                              ca_cert_dir,
    globus_fifo_t *                     ca_cert_list)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_ca_cert_file_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

#error SLANG: need to fill this in

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}

#else /* if WIN32 is not defined */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * UNIX - Get HOME Directory
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the HOME Directory of the current user.  Should
 * be the $HOME environment variable.
 *
 * @param home_dir
 *        The home directory of the current user
 * @return
 *        GLOBUS_SUCCESS if no error occured, otherwise
 *        an error object is returned.
 */
globus_result_t
globus_i_gsi_sysconfig_get_home_dir_unix(
    char **                             home_dir)
{
    globus_result_t                     result;
    static char *                        _function_name_ =
        "globus_i_gsi_sysconfig_get_home_dir_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *home_dir = (char *) getenv("HOME");

    if((*home_dir) == NULL)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_HOME_DIR,
            ("Could not get a home directory for this machine"));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * UNIX - File Exists
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Check if the file exists
 *
 * @param filename the filename of the file to check for
 * @param status  the resulting status of the file
 *
 * @return
 *        GLOBUS_SUCCESS for almost all cases (even if the file
 *        doesn't exist), otherwise an error object identifier
 *        wrapping the system errno is returned
 */
globus_result_t
globus_i_gsi_sysconfig_file_exists_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    struct stat                         stx;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_file_exists_win32";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;
            
        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIG_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_CHECKING_FILE_EXISTS,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    *status = GLOBUS_VALID;
    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}    
/* @} */

/**
 * UNIX - Check File Status for Key
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * This is a convenience function used to check the status of a 
 * private key file.  The desired status is only the current user has
 * ownership and read permissions, everyone else should not be able
 * to access it.
 * 
 * @param filename
 *        The name of the file to check the status of
 * @param status
 *        The status of the file being checked
 *        see @ref globus_gsi_statcheck_t for possible values
 *        of this variable 
 *
 * @return 
 *        GLOBUS_SUCCESS if the status of the file was able
 *        to be determined.  Otherwise, an error object
 *        identifier
 *
 * @see globus_gsi_statcheck_t
 */
globus_result_t
globus_i_gsi_sysconfig_check_keyfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    struct stat                         stx;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_check_keyfile_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;

        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIG_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_KEY_STRING,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_uid != getuid())
    {
        *status = GLOBUS_NOT_OWNED;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    /* check that the key file is not wx by user, or rwx by group or others */
    if (stx.st_mode & (S_IXUSR | 
                       S_IRGRP | S_IWGRP | S_IXGRP |
                       S_IROTH | S_IWOTH | S_IXOTH))
    {
        GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
            2, (stderr, "checkstat:%s:mode:%o\n",filename,stx.st_mode)); 

        *status = GLOBUS_BAD_PERMISSIONS;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    *status = GLOBUS_VALID;
    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * UNIX - Check File Status for Cert
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * This is a convenience function used to check the status of a 
 * certificate file.  The desired status is the current user has
 * ownership and read/write permissions, while group and others only
 * have read permissions.
 * 
 * @param filename
 *        The name of the file to check the status of
 * @param status
 *        The status of the file being checked
 *        see @ref globus_gsi_statcheck_t for possible values
 *        of this variable 
 *
 * @return 
 *        GLOBUS_SUCCESS if the status of the file was able
 *        to be determined.  Otherwise, an error object
 *        identifier
 *
 * @see globus_gsi_statcheck_t
 */
globus_result_t
globus_i_gsi_sysconfig_check_certfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status)
{
    struct stat                         stx;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_check_certfile_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
    
    if (stat(filename,&stx) == -1)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            *status = GLOBUS_DOES_NOT_EXIST;
            result = GLOBUS_SUCCESS;
            goto exit;

        case EACCES:

            *status = GLOBUS_BAD_PERMISSIONS;
            result = GLOBUS_SUCCESS;
            goto exit;

        default:
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_SYSCONFIG_MODULE,
                    errno,
                    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
                    __FILE__":__LINE__:%s: Error getting status of keyfile\n",
                    _function_name_));
            goto exit;
        }
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

    if (stx.st_uid != getuid())
    {
        *status = GLOBUS_NOT_OWNED;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    /* check that the cert file is not x by user, or wx by group or others */
    if (stx.st_mode & (S_IXUSR |
                       S_IWGRP | S_IXGRP |
                       S_IWOTH | S_IXOTH))
    {
        GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
            2, (stderr, "checkstat:%s:mode:%o\n",filename,stx.st_mode));

        *status = GLOBUS_BAD_PERMISSIONS;
        result = GLOBUS_SUCCESS;
        goto exit;
    }
    
    if (stx.st_size == 0)
    {
        *status = GLOBUS_ZERO_LENGTH;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    *status = GLOBUS_VALID;
    result = GLOBUS_SUCCESS;

 exit:
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * UNIX - Get User ID
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get a unique string representing the current user.  This is just
 * the uid converted to a string.  
 *
 * @param user_id_string
 *        A unique string representing the user
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred
 */
globus_result_t
globus_i_gsi_sysconfig_get_user_id_string_unix(
    char **                             user_id_string)
{
    int                                 uid;
    int                                 len = 10;
    int                                 length;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_get_user_id_string_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    uid = getuid();

    if((*user_id_string = globus_malloc(len)) == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }

    while(1)
    {
        length = snprintf(*user_id_string, len,
                           "%d", uid);
        if(length > -1 && length < len)
        {
            break;
        }
        
        if(length > -1)
        {
            len = length + 1;
        }
        else
        {
            len *= 2;
        }
        
        if((*user_id_string = realloc(*user_id_string, len)) == NULL)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto exit;
        }
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * UNIX - Get Process ID
 * @ingroup globus_i_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get a unique string representing the current process.  This is just
 * the pid converted to a string.  
 *
 * @param proc_id_string
 *        A unique string representing the process
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred
 */
globus_result_t
globus_i_gsi_sysconfig_get_proc_id_string_unix(
    char **                             proc_id_string)
{
    int                                 pid;
    int                                 len = 10;
    int                                 length;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_sysconfig_get_proc_id_string_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    pid = getpid();

    if((*proc_id_string = globus_malloc(len)) == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }

    while(1)
    {
        length = snprintf(*proc_id_string, len,
                           "%d", pid);
        if(length > -1 && length < len)
        {
            break;
        }
        
        if(length > -1)
        {
            len = length + 1;
        }
        else
        {
            len *= 2;
        }
        
        if((*proc_id_string = realloc(*proc_id_string, len)) == NULL)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto exit;
        }
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

#endif

/**
 * UNIX - Get Trusted CA Cert Dir
 * @ingroup globus_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the Trusted Certificate Directory containing the trusted
 * Certificate Authority certificates.  This directory is determined
 * in the order shown below.  Failure in one method results in attempting
 * the next.
 *
 * <ol>
 * <li> <b>X509_CERT_DIR environment variable</b> - if this is set, the
 * trusted certificates will be searched for in that directory.  This
 * variable allows the end user to specify the location of trusted
 * certificates.
 * <li> <b>$HOME/.globus/certificates</b> - If this
 * directory exists, and the previous methods of determining the trusted
 * certs directory failed, this directory will be used.  
 * <li> <b>/etc/grid-security/certificates</b> - This location is intended
 * to be independant of the globus installation ($GLOBUS_LOCATION), and 
 * is generally only writeable by the host system administrator.  
 * <li> <b>$GLOBUS_LOCATION/share/certificates</b>
 * </ol>
 *
 * @param cert_dir
 *        The trusted certificates directory
 * @return
 *        GLOBUS_SUCCESS if no error occurred, and a sufficient trusted
 *        certificates directory was found.  Otherwise, an error object 
 *        identifier returned.
 */
globus_result_t
globus_gsi_sysconfig_get_cert_dir_unix(
    char **                             cert_dir)
{
    char *                              env_cert_dir = NULL;
    char *                              local_cert_dir = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
    globus_result_t                     result;
    char *                              home;
    char *                              globus_location;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_cert_dir_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
    
    *cert_dir = NULL;

    if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                     cert_dir, 
                     & env_cert_dir,
                     getenv(X509_CERT_DIR))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* now check for a trusted CA directory in the user's home directory */
    if(!(*cert_dir))
    {
        if((result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home)) 
           != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
            
        if (home) 
        {
            if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                             cert_dir, 
                             & local_cert_dir,
                             "%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_LOCAL_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now look in $GLOBUS_LOCATION/share/certificates */
    if (!(*cert_dir))
    {
        if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                         cert_dir,
                         & installed_cert_dir,
                         X509_INSTALLED_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
    }

    /* now check for host based default directory */
    if (!(*cert_dir))
    {
        globus_location = getenv("GLOBUS_LOCATION");
        
        if (globus_location)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_dir_string(
                             cert_dir,
                             & default_cert_dir,
                             "%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_DEFAULT_TRUSTED_CERT_DIR)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
        2, (stderr, "Using cert_dir = %s\n", 
            (*cert_dir ? *cert_dir : "null")));

    if(!(*cert_dir))
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_DIR,
            ("The trusted certificates directory could not be"
             "found in any of the following locations: \n"
             "1) env. var. X509_CERT_DIR=%s\n"
             "2) %s\n3) %s\n4) %s\n",
             env_cert_dir,
             local_cert_dir,
             installed_cert_dir,
             default_cert_dir));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

  error_exit:
    
    if(*cert_dir)
    {
        globus_free(*cert_dir);
        *cert_dir = NULL;
    }

 done:

    if(env_cert_dir && (env_cert_dir != (*cert_dir)))
    {
        globus_free(env_cert_dir);
    }
    if(local_cert_dir && (local_cert_dir != (*cert_dir)))
    {
        globus_free(local_cert_dir);
    }
    if(installed_cert_dir && (installed_cert_dir != (*cert_dir)))
    {
        globus_free(installed_cert_dir);
    }
    if(default_cert_dir && (default_cert_dir != (*cert_dir)))
    {
        globus_free(default_cert_dir);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * UNIX - Get User Certificate Filename
 * @ingroup globus_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the User Certificate Filename based on the current user's
 * environment.  The following locations are searched for cert and key
 * files in order:
 * 
 * <ol>
 * <li>environment variables X509_USER_CERT and X509_USER_KEY
 * <li>$HOME/.globus/usercert.pem and 
 *     $HOME/.globus/userkey.pem
 * <li>$HOME/.globus/usercred.p12 - this is a PKCS12 credential
 * </ol>
 *
 * @param user_cert
 *        pointer the filename of the user certificate
 * @param user_key
 *        pointer to the filename of the user key
 * @return
 *        GLOBUS_SUCCESS if the cert and key files were found in one
 *        of the possible locations, otherwise an error object identifier
 *        is returned
 */
globus_result_t
globus_gsi_sysconfig_get_user_cert_filename_unix(
    char **                             user_cert,
    char **                             user_key)
{
    char *                              home = NULL;
    char *                              env_user_cert = NULL;
    char *                              env_user_key = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_pkcs12_user_cred = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_user_cert_filename_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *user_cert = NULL;
    *user_key = NULL;

    /* first, check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     user_cert,
                     & env_user_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_cert_string(
                     user_key,
                     & env_user_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* next, check default locations */
    if(!(*user_cert) || !(*user_key))
    {
        if(GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home) == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             user_cert,
                             & default_user_cert,
                             "%s%s%s",
                             home,
                             FILE_SEPERATOR,
                             X509_DEFAULT_USER_CERT)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                              user_key,
                              & default_user_key,
                              "%s%s%s",
                              home,
                              FILE_SEPERATOR,
                              X509_DEFAULT_USER_KEY)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* if the cert & key don't exist in the default locations
     * or those specified by the environment variables, a
     * pkcs12 cert will be searched for
     */
    if(!(*user_cert) || !(*user_key))
    {
        if((result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home)) 
           == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_key_string(
                              user_key,
                              & default_pkcs12_user_cred,
                              "%s%s%s",
                              home,
                              FILE_SEPERATOR,
                              X509_DEFAULT_PKCS12_FILE)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
            *user_cert = *user_key;
        }
    }

    if(!(*user_cert) || !(*user_key))
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_DIR,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) %s\n3) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) %s\n3) %s\n",
             env_user_cert,
             default_user_cert,
             default_pkcs12_user_cred,
             env_user_key,
             default_user_key,
             default_pkcs12_user_cred));

        goto error_exit;
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
        2, (stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            (*user_cert) ? (*user_cert) : NULL, 
            (*user_key) ? (*user_key) : NULL));

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:
    
    if(*user_cert)
    {
        globus_free(*user_cert);
        *user_cert = NULL;
    }
    if(*user_key)
    {
        globus_free(*user_key);
        *user_key = NULL;
    }

 done:

    if(env_user_cert && env_user_cert != (*user_cert))
    {
        globus_free(env_user_cert);
    }
    if(env_user_key && env_user_key != (*user_key))
    {
        globus_free(env_user_key);
    }
    if(default_user_cert && default_user_cert != (*user_cert))
    {
        globus_free(default_user_cert);
    }
    if(default_user_key && default_user_key != (*user_key))
    {
        globus_free(default_user_key);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * UNIX - Get Host Certificate and Key Filenames
 * @ingroup globus_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the Host Certificate and Key Filenames based on the current user's
 * environment.  The host cert and key are searched for in the following 
 * locations (in order):
 *
 * <ol>
 * <li>X509_USER_CERT and X509_USER_KEY environment variables
 * <li>registry keys x509_user_cert and x509_user_key in software\Globus\GSI
 * <li>SLANG: NOT DETERMINED - this is the default location
 * <li><GLOBUS_LOCATION>\etc\host[cert|key].pem
 * <li><users home directory>\.globus\host[cert|key].pem
 * </ol>
 * 
 * @param host_cert
 *        pointer to the host certificate filename
 * @param host_key
 *        pointer to the host key filename
 *
 * @return
 *        GLOBUS_SUCCESS if the host cert and key were found, otherwise
 *        an error object identifier is returned 
 */
globus_result_t
globus_gsi_sysconfig_get_host_cert_filename_unix(
    char **                             host_cert,
    char **                             host_key)
{
    char *                              home = NULL;
    char *                              env_host_cert = NULL;
    char *                              env_host_key = NULL;
    char *                              default_host_cert = NULL;
    char *                              default_host_key = NULL;
    char *                              installed_host_cert = NULL;
    char *                              installed_host_key = NULL;
    char *                              local_host_cert = NULL;
    char *                              local_host_key = NULL;
    char *                              globus_location = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_host_cert_filename_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *host_cert = NULL;
    *host_key = NULL;

    /* first check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     host_cert,
                     & env_host_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_key_string(
                     host_key,
                     & env_host_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* now check default locations for valid filenames */
    if(!(*host_cert) || !(*host_key))
    {
        if((result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home)) 
           == GLOBUS_SUCCESS)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & default_host_cert,
                             "%s%s%s%s",
                             X509_DEFAULT_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                              host_key,
                              & default_host_key,
                              "%s%s%s%s",
                              X509_DEFAULT_CERT_DIR,
                              FILE_SEPERATOR,
                              X509_HOST_PREFIX,
                              X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now check intstalled location for host cert */
    if(!(*host_cert) || !(*host_key))
    {
        globus_location = getenv("GLOBUS_LOCATION");

        if(globus_location)
        {
            if((result = globus_i_gsi_sysconfig_create_cert_string(
                             host_cert,
                             & installed_host_cert,
                             "%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_CERT_SUFFIX)) != GLOBUS_SUCCESS ||
               (result = globus_i_gsi_sysconfig_create_key_string(
                             host_key,
                             & installed_host_key,
                             "%s%s%s%s%s%s",
                             globus_location,
                             FILE_SEPERATOR,
                             X509_INSTALLED_CERT_DIR,
                             FILE_SEPERATOR,
                             X509_HOST_PREFIX,
                             X509_KEY_SUFFIX)) != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    if(!(*host_cert) || !(*host_key))
    {
        result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home);
        if(result == GLOBUS_SUCCESS)
        {
            result = globus_i_gsi_sysconfig_create_cert_string(
                host_cert,
                & local_host_cert,
                "%s%s%s%s%s%s",
                home,
                FILE_SEPERATOR,
                X509_LOCAL_CERT_DIR,
                FILE_SEPERATOR,
                X509_HOST_PREFIX,
                X509_CERT_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }

            result = globus_i_gsi_sysconfig_create_key_string(
                host_key,
                & local_host_key,
                "%s%s%s%s%s%s",
                home,
                FILE_SEPERATOR,
                X509_LOCAL_CERT_DIR,
                FILE_SEPERATOR,
                X509_HOST_PREFIX,
                X509_KEY_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            host_cert, host_key);
#endif

    if(!(*host_cert) || !(*host_key))
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) %s\n3) %s4) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) %s\n3) %s4) %s\n",
             env_host_cert,
             default_host_cert,
             installed_host_cert,
             local_host_cert,
             env_host_key,
             default_host_key,
             installed_host_key,
             local_host_key));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:

    if(*host_cert)
    {
        globus_free(*host_cert);
        *host_cert = NULL;
    }
    if(*host_key)
    {
        globus_free(*host_key);
        *host_key = NULL;
    }

 done:

    if(env_host_cert && env_host_cert != *host_cert)
    {
        globus_free(env_host_cert);
    }
    if(env_host_key && env_host_key != *host_key)
    {
        globus_free(env_host_key);
    }
    if(installed_host_cert && installed_host_cert != *host_cert)
    {
        globus_free(installed_host_cert);
    }
    if(installed_host_key && installed_host_key != *host_key)
    {
        globus_free(installed_host_key);
    }
    if(local_host_cert && local_host_cert != *host_cert)
    {
        globus_free(local_host_cert);
    }
    if(local_host_key && local_host_key != *host_key)
    {
        globus_free(local_host_key);
    }
    if(default_host_cert && default_host_cert != *host_cert)
    {
        globus_free(default_host_cert);
    }
    if(default_host_key && default_host_key != *host_key)
    {
        globus_free(default_host_key);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * UNIX - Get Service Certificate and Key Filenames
 * @ingroup globus_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the Service Certificate Filename based on the current user's
 * environment.  The host cert and key are searched for in the following 
 * locations (in order):
 *
 * <ol>
 * <li>X509_USER_CERT and X509_USER_KEY environment variables
 * <li>/etc/grid-security/{service_name}/{service_name}[cert|key].pem
 * <li>GLOBUS_LOCATION\etc\{service_name}\{service_name}[cert|key].pem
 *     So for example, if my service was named: myservice, the location
 *     of the certificate would be: 
 *     GLOBUS_LOCATION\etc\myservice\myservicecert.pem
 * <li><users home>\.globus\{service_name}\{service_name}[cert|key].pem
 * </ol>
 * 
 * @param service_name
 *        The name of the service which allows us to determine the
 *        locations of cert and key files to look for
 * @param service_cert
 *        pointer to the host certificate filename
 * @param service_key
 *        pointer to the host key filename
 *
 * @return
 *        GLOBUS_SUCCESS if the service cert and key were found, otherwise
 *        an error object identifier 
 */
globus_result_t
globus_gsi_sysconfig_get_service_cert_filename_unix(
    char *                              service_name,
    char **                             service_cert,
    char **                             service_key)
{
    char *                              home = NULL;
    char *                              env_service_cert = NULL;
    char *                              env_service_key = NULL;
    char *                              default_service_cert = NULL;
    char *                              default_service_key = NULL;
    char *                              installed_service_cert = NULL;
    char *                              installed_service_key = NULL;
    char *                              local_service_cert = NULL;
    char *                              local_service_key = NULL;
    char *                              globus_location = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_service_cert_filename_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *service_cert = NULL;
    *service_key = NULL;

    /* first check environment variables for valid filenames */

    if((result = globus_i_gsi_sysconfig_create_cert_string(
                     service_cert,
                     & env_service_cert,
                     getenv(X509_USER_CERT))) != GLOBUS_SUCCESS ||
       (result = globus_i_gsi_sysconfig_create_key_string(
                     service_key,
                     & env_service_key,
                     getenv(X509_USER_KEY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* now check default locations for valid filenames */
    if(!(*service_cert) || !(*service_key))
    {
        result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home);
        if(result == GLOBUS_SUCCESS)
        {
            result = globus_i_gsi_sysconfig_create_cert_string(
                service_cert,
                & default_service_cert,
                "%s%s%s%s%s%s",
                X509_DEFAULT_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_CERT_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }

            result = globus_i_gsi_sysconfig_create_key_string(
                service_key,
                & default_service_key,
                "%s%s%s%s%s%s",
                X509_DEFAULT_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_KEY_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    /* now check intstalled location for service cert */
    if(!(*service_cert) || !(*service_key))
    {
        globus_location = getenv("GLOBUS_LOCATION");

        if(globus_location)
        {
            result = globus_i_gsi_sysconfig_create_cert_string(
                service_cert,
                & installed_service_cert,
                "%s%s%s%s%s%s%s%s",
                globus_location,
                FILE_SEPERATOR,
                X509_INSTALLED_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_CERT_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
               
            result = globus_i_gsi_sysconfig_create_key_string(
                service_key,
                & installed_service_key,
                "%s%s%s%s%s%s%s%s",
                globus_location,
                FILE_SEPERATOR,
                X509_INSTALLED_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_KEY_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }
    
    if(!(*service_cert) || !(*service_key))
    {
        result = GLOBUS_I_GSI_SYSCONFIG_GET_HOME_DIR(&home);
        if(result == GLOBUS_SUCCESS)
        {
            result = globus_i_gsi_sysconfig_create_cert_string(
                service_cert,
                & local_service_cert,
                "%s%s%s%s%s%s%s",
                home,
                FILE_SEPERATOR,
                X509_LOCAL_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_CERT_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
            
            result = globus_i_gsi_sysconfig_create_key_string(
                service_key,
                & local_service_key,
                "%s%s%s%s%s%s%s%s",
                home,
                FILE_SEPERATOR,
                X509_LOCAL_CERT_DIR,
                FILE_SEPERATOR,
                service_name,
                FILE_SEPERATOR,
                service_name,
                X509_KEY_SUFFIX);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_exit;
            }
        }
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(
        2, (stderr, "Using x509_user_cert=%s\n      x509_user_key =%s\n",
            *service_cert, *service_key));

    if(!(*service_cert) || !(*service_key))
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME,
            ("The user cert could not be found in: \n"
             "1) env. var. X509_USER_CERT=%s\n"
             "2) %s\n3) %s4) %s\n\n"
             "The user key could not be found in:\n,"
             "1) env. var. X509_USER_KEY=%s\n"
             "2) %s\n3) %s4) %s\n",
             env_service_cert,
             default_service_cert,
             installed_service_cert,
             local_service_cert,
             env_service_key,
             default_service_key,
             installed_service_key,
             local_service_key));

        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:

    if(*service_cert)
    {
        globus_free(*service_cert);
        *service_cert = NULL;
    }
    if(*service_key)
    {
        globus_free(*service_key);
        *service_key = NULL;
    }

 done:

    if(env_service_cert && env_service_cert != *service_cert)
    {
        globus_free(env_service_cert);
    }
    if(env_service_key && env_service_key != *service_key)
    {
        globus_free(env_service_key);
    }
    if(installed_service_cert && installed_service_cert != *service_cert)
    {
        globus_free(installed_service_cert);
    }
    if(installed_service_key && installed_service_key != *service_key)
    {
        globus_free(installed_service_key);
    }
    if(local_service_cert && local_service_cert != *service_cert)
    {
        globus_free(local_service_cert);
    }
    if(local_service_key && local_service_key != *service_key)
    {
        globus_free(local_service_key);
    }
    if(default_service_cert && default_service_cert != *service_cert)
    {
        globus_free(default_service_cert);
    }
    if(default_service_key && default_service_key != *service_key)
    {
        globus_free(default_service_key);
    }

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * UNIX - Get Proxy Filename
 * @ingroup globus_gsi_sysconfig_system_config_unix
 */
/* @{ */
/**
 * Get the proxy cert filename based on the following
 * search order:
 * 
 * <ol>
 * <li> X509_USER_PROXY environment variable - This environment variable
 * is set by the at run time for the specific application.  If
 * the proxy_file_type variable is set to GLOBUS_PROXY_OUTPUT
 *  (a proxy filename for writing is requested), 
 * and the X509_USER_PROXY is set, this will be the 
 * resulting value of the user_proxy filename string passed in.  If the
 * proxy_file_type is set to GLOBUS_PROXY_INPUT and X509_USER_PROXY is 
 * set, but the file it points to does not exist, 
 * or has some other readability issues, the 
 * function will continue checking using the other methods available.
 * 
 * <li> Check the default location for the proxy file of /tmp/x509_u<user_id>
 * where <user id> is some unique string for that user on the host
 * </ol>
 *
 * @param user_proxy
 *        the proxy filename of the user
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_sysconfig_get_proxy_filename_unix(
    char **                             user_proxy,
    globus_gsi_proxy_file_type_t        proxy_file_type)
{
    char *                              env_user_proxy = NULL;
    char *                              env_value = NULL;
    char *                              default_user_proxy = NULL;
    globus_result_t                     result;
    char *                              user_id_string;

    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_proxy_filename_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
    
    *user_proxy = NULL;

    if((env_value = getenv(X509_USER_PROXY)) != NULL &&
       (result = globus_i_gsi_sysconfig_create_key_string(
                     user_proxy,
                     & env_user_proxy,
                     getenv(X509_USER_PROXY))) != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    /* check if the proxy file type is for writing */
    if(!(*user_proxy) && env_user_proxy && 
       proxy_file_type == GLOBUS_PROXY_FILE_OUTPUT)
    {
        *user_proxy = env_user_proxy;
    }

    if (!*user_proxy)
    {
        result = GLOBUS_I_GSI_SYSCONFIG_GET_USER_ID_STRING(&user_id_string);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
        if((result = globus_i_gsi_sysconfig_create_key_string(
                          user_proxy,
                          & default_user_proxy,
                          "%s%s%s%s",
                          DEFAULT_SECURE_TMP_DIR,
                          FILE_SEPERATOR,
                          X509_USER_PROXY_FILE,
                          user_id_string)) != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
    }

    if(!(*user_proxy) && 
       default_user_proxy && 
       proxy_file_type == GLOBUS_PROXY_FILE_OUTPUT)
    {
        *user_proxy = default_user_proxy;
    }

    if(!(*user_proxy))
    {            
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT( 
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME,
            ("A file location for%s the proxy cert could not be found in: \n"
             "1) env. var. X509_USER_PROXY=%s\n"
             "2) %s\n",
             (proxy_file_type == GLOBUS_PROXY_FILE_INPUT) ? "" : " writing",
             env_user_proxy,
             default_user_proxy));
        
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:
    
    if(*user_proxy)
    {
        globus_free(*user_proxy);
        *user_proxy = NULL;
    }

 done:

    if(default_user_proxy && (default_user_proxy != (*user_proxy)))
    {
        globus_free(default_user_proxy);
    }
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */

globus_result_t
globus_gsi_sysconfig_get_signing_policy_filename_unix(
    X509_NAME *                         ca_name,
    char *                              cert_dir,
    char **                             signing_policy_filename)
{
    char *                              signing_policy = NULL;
    globus_gsi_statcheck_t              status;
    globus_result_t                     result = GLOBUS_SUCCESS;
    unsigned long                       hash;
    
    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_signing_policy_filename_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    *signing_policy_filename = NULL;

    if (cert_dir == NULL)
    {
        result = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&cert_dir);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME);
            goto exit;
        }
    }

    if(ca_name == NULL)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME,
            ("NULL parameter ca_name passed to: %s", _function_name_));
        goto exit;
    }

    hash = X509_NAME_hash(ca_name);

    signing_policy = globus_gsi_cert_utils_create_string(
        "%s%s%08lx%s", 
        cert_dir, FILE_SEPERATOR, hash, SIGNING_POLICY_FILE_EXTENSION);
    
    if(signing_policy == NULL)
    {
        result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        goto exit;
    }

    result = GLOBUS_I_GSI_SYSCONFIG_FILE_EXISTS(signing_policy, &status);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME);
        goto exit;
    }
    
    if(status == GLOBUS_VALID)
    {
        *signing_policy_filename = signing_policy;
    }

 exit:
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_sysconfig_get_ca_cert_files_unix(
    char *                              ca_cert_dir,
    globus_fifo_t *                     ca_cert_list)
{
    DIR *                               dir_handle = NULL;
    struct dirent *                     tmp_entry = NULL;
    int                                 file_length;
    char *                              full_filename_path = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_ca_cert_file_unix";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    if(!ca_cert_dir)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CA_CERT_FILENAMES,
            ("NULL parameter ca_cert_dir passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!ca_cert_list)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CA_CERT_FILENAMES,
            ("NULL parameter ca_cert_list passed to function: %s",
             _function_name_));
        goto exit;
    }

    dir_handle = opendir(ca_cert_dir);
    if(dir_handle == NULL)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                GLOBUS_GSI_SYSCONFIG_MODULE,
                errno,
                GLOBUS_GSI_SYSCONFIG_ERROR_ERRNO,
                "Error opening directory: %s", ca_cert_dir));
        goto exit;
    }

    while((tmp_entry = readdir(dir_handle)) != NULL)
    {
        file_length = strlen(tmp_entry->d_name);
        /* check the following:
         * 
         * - file length is greater than or equal to 10
         * - first 8 characters are alpha-numeric
         * - 9th character is '.'
         * - characters after the '.' are numeric
         */
        if(file_length >= (X509_HASH_LENGTH + 2) &&
           (*(tmp_entry->d_name + X509_HASH_LENGTH) == '.') &&
           (strspn(tmp_entry->d_name, "0123456789abcdefABCDEF") 
            == X509_HASH_LENGTH) &&
           (strspn((tmp_entry->d_name + (X509_HASH_LENGTH + 1)), 
                   "0123456789") == (file_length - 9)))
        {
            full_filename_path = 
                globus_gsi_cert_utils_create_string(
                    "%s%s%s", ca_cert_dir, FILE_SEPERATOR, tmp_entry->d_name);
            
            if(full_filename_path == NULL)
            {
                GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CA_CERT_FILENAMES,
                    ("Couldn't get full pathname for CA cert"));
                goto exit;
            }

            globus_fifo_enqueue(ca_cert_list, (void *)full_filename_path);
        }
    }

 exit:
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;

}
#endif /* done defining *_unix functions */


/**
 * Get Unique Proxy Filename
 * @ingroup globus_gsi_sysconfig_system_config
 */
/* @{ */
/**
 * Get a unique proxy cert filename.  This is mostly used
 * for delegated proxy credentials.  Each filename returned
 * is going to be unique for each time the function is called.
 * 
 * @param unique_filename
 *        the unique filename for a delegated proxy cert
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_sysconfig_get_unique_proxy_filename(
    char **                             unique_filename)
{
    char *                              default_unique_filename = NULL;
    globus_result_t                     result;
    char *                              proc_id_string;
    char *                              unique_tmp_name[L_tmpnam];
    static int                          i = 0;
    static char *                       _function_name_ =
        "globus_gsi_sysconfig_get_unique_proxy_filename";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
    
    *unique_filename = NULL;

    if((result = GLOBUS_I_GSI_SYSCONFIG_GET_PROC_ID_STRING(&proc_id_string))
       != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_DELEG_FILENAME);
        goto error_exit;
    }

    if(tmpnam(*unique_tmp_name) == NULL)
    {
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_DELEG_FILENAME,
            ("Could not get a unique filename for the temporary proxy cert"));
        goto error_exit;
    }
    
    if((result = globus_i_gsi_sysconfig_create_key_string(
        unique_filename,
        & default_unique_filename,
        "%s%s%s%s.%s.%d",
        DEFAULT_SECURE_TMP_DIR,
        FILE_SEPERATOR,
        X509_UNIQUE_PROXY_FILE,
        proc_id_string,
        unique_tmp_name,
        ++i)) != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_DELEG_FILENAME);
        goto error_exit;
    }

    *unique_filename = default_unique_filename;

    if(!(*unique_filename))
    {            
        GLOBUS_GSI_SYSCONFIG_ERROR_RESULT( 
            result,
            GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_DELEG_FILENAME,
            ("A file location for writing the unique proxy cert"
             " could not be found in: %s\n",
             default_unique_filename));
        
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;
    goto done;

 error_exit:
    
    if(*unique_filename)
    {
        globus_free(*unique_filename);
        *unique_filename = NULL;
    }

 done:

    if(default_unique_filename && 
       (default_unique_filename != (*unique_filename)))
    {
        globus_free(default_unique_filename);
    }
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;
    return result;
}
/* @} */
