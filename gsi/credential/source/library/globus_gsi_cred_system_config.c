
#include "globus_gsi_cred_system_config.h"
#include "globus_i_gsi_credential.h"
#include <openssl/rand.h>

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif
#endif

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
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
#define X509_USER_DELEG_FILE            "x509up_p"
#define X509_USER_PROXY_FILE            "x509up_u"

/* This is added after the CA name hash to make the policy filename */
#define SIGNING_POLICY_FILE_EXTENSION   ".signing_policy"

#ifdef WIN32
#define GSI_REGISTRY_DIR                "software\\Globus\\GSI"
#define X509_DEFAULT_CERT_DIR           ".globus\\certificates"
#define X509_DEFAULT_USER_CERT          ".globus\\usercert.pem"
#define X509_DEFAULT_USER_KEY           ".globus\\userkey.pem"
#define X509_DEFAULT_PKCS12_FILE        ".globus\\usercred.p12"
#define X509_DEFAULT_HOST_PKCS12_FILE   "SLANG: NEEDS_TO_BE_DETERMINED"
#define X509_INSTALLED_CERT_DIR         "share\\certificates"
#define X509_INSTALLED_HOST_CERT_DIR    "SLANG: NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_CERT          "SLANG: NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_KEY           "SLANG: NEEDS_TO_BE_DETERMINED"
#define DEFAULT_SECURE_TMP_DIR          "c:"
#else
#define X509_DEFAULT_CERT_DIR           ".globus/certificates"
#define X509_DEFAULT_USER_CERT          ".globus/usercert.pem"
#define X509_DEFAULT_USER_KEY           ".globus/userkey.pem"
#define X509_DEFAULT_PKCS12_FILE        ".globus/usercred.p12"
#define X509_DEFAULT_HOST_PKCS12_FILE   "/etc/grid-security/hostcred.p12"
#define X509_INSTALLED_CERT_DIR         "share/certificates"
#define X509_INSTALLED_HOST_CERT_DIR    "/etc/grid-security/certificates"
#define X509_DEFAULT_HOST_CERT          "/etc/grid-security/hostcert.pem"
#define X509_DEFAULT_HOST_KEY           "/etc/grid-security/hostkey.pem"
#endif

#ifdef WIN32
#    define GLOBUS_I_GSI_GET_HOME_DIR globus_i_gsi_get_home_dir_win32
#    define GLOBUS_I_GSI_CHECK_KEYFILE globus_i_gsi_check_keyfile_win32
#    define GLOBUS_I_GSI_CHECK_CERTFILE globus_i_gsi_check_certfile_win32
#    define GLOBUS_GSI_CRED_GET_CERT_DIR globus_gsi_cred_get_cert_dir_win32
#    define GLOBUS_GSI_CRED_GET_USER_CERT_FILENAME \
            globus_gsi_cred_get_user_cert_filename_win32
#    define GLOBUS_GSI_CRED_GET_HOST_CERT_FILENAME \
            globus_gsi_cred_get_host_cert_filename_win32
#    define GLOBUS_GSI_CRED_GET_SERVICE_CERT_FILENAME \
            globus_gsi_cred_get_service_cert_filename_win32
#else
#    define GLOBUS_I_GSI_GET_HOME_DIR globus_i_gsi_get_home_dir_unix
#    define GLOBUS_I_GSI_CHECK_KEYFILE globus_i_gsi_check_keyfile_unix
#    define GLOBUS_I_GSI_CHECK_CERTFILE globus_i_gsi_check_certfile_unix
#    define GLOBUS_GSI_CRED_GET_CERT_DIR globus_gsi_cred_get_cert_dir_unix
#    define GLOBUS_GSI_CRED_GET_USER_CERT_FILENAME \
            globus_gsi_cred_get_user_cert_filename_unix
#    define GLOBUS_GSI_CRED_GET_HOST_CERT_FILENAME \
            globus_gsi_cred_get_host_cert_filename_unix
#    define GLOBUS_GSI_CRED_GET_SERVICE_CERT_FILENAME \
            globus_gsi_cred_get_service_cert_filename_unix
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#define GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR \
    globus_error_put(globus_error_wrap_errno_error(
        GLOBUS_GSI_CREDENTIAL_MODULE, \
        errno, \
        GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG, \
        "%s:%s: Could not allocate enough memory: %d bytes", \
        __FILE__, __LINE__, len))

/**
 * Get HOME Directory
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the HOME Directory of the current user.   Depending
 * on what platform this is being run, the behavior (the
 * resulting home_dir string) may vary.
 *
 * UNIX:  On unix platforms, the resulting home directory will be
 *        the same as the currently set HOME environment variable.
 *        If the HOME environment variable is not set, an error will
 *        be returned, and home_dir will point to NULL.
 * 
 * WINDOWS: SLANG -- NOT DETERMINED
 *
 * @param home_dir_p
 *        The home directory of the current user
 * @return
 *        GLOBUS_SUCCESS if no error occured, otherwise
 *        an error object is returned.
 */
globus_result_t
globus_i_gsi_get_home_dir(
    char **                             home_dir)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_i_gsi_get_home_dir";

#ifdef WIN32
    /* SLANG:  This should probably be changed */
    *home_dir = "c:\\windows";
#else
    *home_dir = (char *) getenv("HOME");
#endif

    if((*home_dir) == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG);
    }
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * Check File Status
 * @ingroup globus_i_gsi_system_config
 */
/* @{ */
/**
 * This is a convenience function used to check the status of a file
 * 
 * @param filename
 *        The name of the file to check the status of
 * @return 
 *        0 passed all the of the following tests
 *        1 does not exist
 *        2 not owned by user
 *        3 readable by someone else
 *        4 zero length
 */
int
globus_i_gsi_checkstat(
    const char *                        filename)
{
    struct stat                         stx;

    if (stat(filename,&stx) != 0)
    {
        return 1;
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

#if !defined(WIN32) && !defined(TARGET_ARCH_CYGWIN)
    if (stx.st_uid != getuid())
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:uid:%d:%d\n",filename,
                stx.st_uid, getuid());
#endif
        return 2;
    }

    if (stx.st_mode & 066)
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:mode:%o\n",filename,stx.st_mode);
#endif
        return 3;
    }
    
#endif /* !WIN32 && !TARGET_ARCH_CYGWIN */

    if (stx.st_size == 0)
    {
        return 4;
    }
    return 0;
}
/* @} */

/**
 * Get User ID
 */
/* @{ */
/**
 * Get a unique string representing the current user.  On Unix, this is just
 * the uid converted to a string.  On Windows, SLANG: NOT DETERMINED
 */
globus_result_t
globus_i_gsi_get_user_id_string(
    char **                             user_id_string)
{
#ifndef WIN32
    int                                 uid;
#endif

#ifdef WIN32
    /* SLANG: need to set the string to the username or whatever */
#else
    uid = getuid();
    *user_id_string = (char *) globus_malloc(sizeof(uid_t)*8);
    sprintf(*user_id_string, "%d", uid);
#endif
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * Get Trusted CA Cert Dir
 * @ingroup globus_gsi_cred_operations
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
 * <li> <b>On Windows Only - "x509_cert_dir" registry key</b> - If
 * this registry key is set on windows, the directory it points to should
 * contain the trusted certificates.
 * <li> <b>\<user home directory\>/.globus/certificates</b> - If this
 * directory exists, and the previous methods of determining the trusted
 * certs directory failed, this directory will be used.  On Unix, the
 * <user home directory> is equal to the HOME environment variable. On
 * Windows, SLANG -- NOT DETERMINED
 * <li> <b>Host Trusted Cert Dir</b> - This location is intended
 * to be independant of the globus installation ($GLOBUS_LOCATION), and 
 * is generally only writeable by the host system administrator.  On
 * Unix, /etc/grid-security/certificates is used.  
 * On Windows, SLANG - NOT DETERMINED
 * <li> <b>Globus Install Trusted Cert Dir</b> - On Unix systems, this
 * is $GLOBUS_LOCATION/share/certificates.  
 * On Windows systems - SLANG -- NOT DETERMINED
 * </ol>
 *
 * @param cert_dir
 *        The trusted certificates directory
 * @return
 *        GLOBUS_SUCCESS if no error occurred, and a sufficient trusted
 * certificates directory was found.  Otherwise, an error object identifier
 * returned.
 */
globus_result_t
globus_gsi_cred_get_cert_dir(
    char **                             cert_dir_name)
{
    char *                              cert_dir = NULL;
    char *                              env_cert_dir = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
    int                                 len;    
#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_cert_dir[512];
#endif
    globus_result_t                     result;
    char *                              home;

    /* check the environment variable */
    env_cert_dir = (char *) getenv(X509_CERT_DIR);
    
    if(env_cert_dir && globus_i_gsi_checkstat(env_cert_dir) == 0)
    {
        len = strlen(env_cert_dir) + 1;
        cert_dir = (char *) globus_malloc(sizeof(char) * len);
        if(!cert_dir)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }
        strncpy(cert_dir, env_cert_dir, len);
    }

#ifdef WIN32
    if (!cert_dir)
    {
        strncpy(val_cert_dir, "<not set>", (strlen("<not set>") + 1));
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        lval = sizeof(val_cert_dir)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_dir",0,&type,
                                      val_cert_dir,&lval) == ERROR_SUCCESS))
        {
            if(globus_i_gsi_checkstat(val_cert_dir) == 0)
            {
                len = strlen(val_cert_dir) + 1;
                cert_dir = (char *) globus_malloc(sizeof(char) * len);
                if(!cert_dir)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(cert_dir, val_cert_dir, len);
            }
        }
        RegCloseKey(hkDir);
    }
#endif

    /* now check for a trusted CA directory in the user's home
     * directory
     */
    if(!cert_dir)
    {
        globus_i_gsi_get_home_dir(&home);
        if (home) 
        {
            len = strlen(home) + 
                strlen(FILE_SEPERATOR) + 
                strlen(X509_DEFAULT_CERT_DIR) + 
                1 /* NULL TERMINATOR */;
            default_cert_dir = (char *)globus_malloc(len);
            if (!default_cert_dir)
            {
                result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                goto error_exit;
            }
            sprintf(default_cert_dir, "%s%s%s",
                    home, FILE_SEPERATOR, X509_DEFAULT_CERT_DIR);
            
            if (globus_i_gsi_checkstat(default_cert_dir) == 0)
            {
                len = strlen(default_cert_dir) + 1;
                cert_dir = (char *) globus_malloc(sizeof(char) * len);
                if(!cert_dir)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(cert_dir, default_cert_dir, len);
            } 
        }
    }

    /* 
     * Now check for host based default directory
     */
    if (!cert_dir)
    {
        if (globus_i_gsi_checkstat(X509_INSTALLED_HOST_CERT_DIR) == 0)
        {
            /* default_cert_dir exists */
            len = strlen(X509_INSTALLED_HOST_CERT_DIR) + 1;
            cert_dir = (char *) globus_malloc(sizeof(char) * len);
            if(!cert_dir)
            {
                result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                goto error_exit;
            }
            strncpy(cert_dir, X509_INSTALLED_HOST_CERT_DIR, len);
        }
    }

    /* now look in $GLOBUS_LOCATION/share/certificates */
    if (!cert_dir)
    {
        char *globus_location;

        globus_location = getenv("GLOBUS_LOCATION");
        
        if (globus_location)
        {
            len = strlen(globus_location) +
                strlen(FILE_SEPERATOR) +
                strlen(X509_INSTALLED_CERT_DIR)
                + 1 /* NULL TERMINATOR */;

            installed_cert_dir = (char *) globus_malloc(sizeof(char) * len);
            if  (!installed_cert_dir)
            {
                result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                goto error_exit;
            }
            sprintf(installed_cert_dir,
                    "%s%s%s",
                    globus_location,
                    FILE_SEPERATOR,
                    X509_INSTALLED_CERT_DIR);

            if(globus_i_gsi_checkstat(installed_cert_dir) == 0)
            {
                cert_dir = installed_cert_dir;
            }
        }
    }

#ifdef DEBUG
    fprintf(stderr, "Using cert_dir = %s\n",
            (cert_dir ? cert_dir : "null"));
#endif /* DEBUG */

    if(!cert_dir)
    {
        result = globus_error_put(globus_error_construct_string(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            NULL,
            "The trusted certificates directory could not be"
            "found in any of the following locations: \n"
            "env. var. X509_CERT_DIR=%s\n"
#ifdef WIN32
            "registry key x509_cert_dir: %s\n"
#endif
            "%s\n4) %s\n5) %s\n",
            env_cert_dir ? env_cert_dir : "NULL",
#ifdef WIN32
            val_cert_dir ? val_cert_dir : "NULL",
#endif
            default_cert_dir ? default_cert_dir : "NULL",
            X509_INSTALLED_HOST_CERT_DIR,
            installed_cert_dir));
        
        if(installed_cert_dir)
        {
            globus_free(installed_cert_dir);
        }
        if(default_cert_dir)
        {
            globus_free(default_cert_dir);
        }
        return result;
    }

    if(installed_cert_dir != cert_dir && installed_cert_dir)
    {
        globus_free(installed_cert_dir);
    }
    if(default_cert_dir != cert_dir && default_cert_dir)
    {
        globus_free(default_cert_dir);
    }
    *cert_dir_name = cert_dir;
    return GLOBUS_SUCCESS;

  error_exit:
    
    if(installed_cert_dir)
    {
        globus_free(installed_cert_dir);
    }
    if(default_cert_dir)
    {
        globus_free(default_cert_dir);
    }

    return result;
}
/* @} */

/**
 * Get User Certificate Filename
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the User Certificate Filename based on the current user's
 * environment.  
 * 
 * @param user_cert_p
 *        pointer the filename of the user certificate
 * @param user_key_p
 *        pointer to the filename of the user key
 * @return
 *        GLOBUS_SUCCESS or an object error identifier
 */
globus_result_t
globus_gsi_cred_get_user_cert_filename(
    char **                             user_cert_filename,
    char **                             user_key_filename)
{
    int                                 len;
    char *                              home = NULL;
    char *                              user_cert = NULL;
    char *                              user_key = NULL;
    char *                              env_user_cert = NULL;
    char *                              env_user_key = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_pkcs12_user_cert = NULL;
    globus_result_t                     result;

#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_user_cert[512];
    char                                val_user_key[512];
#endif

    env_user_cert = (char *)getenv(X509_USER_CERT);

    if(env_user_cert && globus_i_gsi_checkstat(env_user_cert) == 0)
    {
        len = strlen(env_user_cert) + 1;
        user_cert = (char *) globus_malloc ((void *) user_cert, 
                                             sizeof(char) * len);
        if(!user_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }
        strncpy(user_cert, env_user_cert, len);
    }

    env_user_key  = (char *)getenv(X509_USER_KEY);    

    if(env_user_key && globus_i_gsi_checkstat(env_user_key) == 0)
    {
        len = strlen(env_user_key) + 1;
        user_key = (char *) globus_realloc ((void *) user_key,
                                            sizeof(char) * len);
        if(!user_key)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }
        strncpy(user_key, env_user_key, len);
    }

#ifdef WIN32
    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
    
    if(!user_cert)
    {
        strncpy(val_user_cert, "<not set>", (strlen("<not set>") + 1));
        lval = sizeof(val_user_cert)-1;
        if (hkDir && (RegQueryValueEx(
            hkDir,
            "x509_user_cert",
            0,
            &type,
            val_user_cert,&lval) == ERROR_SUCCESS))
        {
            if(globus_i_gsi_checkstat(val_user_cert) == 0)
            {
                len = strlen(val_user_cert) + 1;
                user_cert = (char *) globus_realloc (sizeof(char) * len);
                if(!user_cert)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(user_cert, val_user_cert, len);
            }
        }
    }

    if(!user_key)
    {
        strncpy(val_user_key, "<not set>", (strlen("<not set>") + 1));
        lval = sizeof(val_user_key)-1;
        if (hkDir && (RegQueryValueEx(
            hkDir,
            "x509_user_key",
            0,
            &type,
            val_user_key,&lval) == ERROR_SUCCESS))
        {
            if(globus_i_gsi_checkstat(val_user_key) == 0)
            {
                len = strlen(val_user_key) + 1;
                user_key = (char *) globus_realloc (sizeof(char) * len);
                if(!user_key)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(user_key, val_user_key, len);
            }
        }
    }

    RegCloseKey(hkDir);
#endif

    if(((result = globus_i_gsi_get_home_dir(&home)) == GLOBUS_SUCCESS)
       && !user_cert)
    {
        len = strlen(home) + 
            strlen(DEFAULT_SEPERATOR) + 
            strlen(X509_DEFAULT_USER_CERT) + 
            1 /* NULL TERMINATOR */;
        default_user_cert = (char *) globus_realloc((void *) default_user_cert,
                                                    len);

        if (!default_user_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }

        sprintf(default_user_cert,"%s%s%s",
                home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT);

        if(globus_i_gsi_checkstat(default_user_cert) == 0)
        {
            user_cert = default_user_cert;
        }
    }

    if(result == GLOBUS_SUCCESS && !user_key)
    {
        len = strlen(home) + 
            strlen(FILE_SEPERATOR) + 
            strlen(X509_DEFAULT_USER_KEY) + 1;

        default_user_key = (char *) globus_realloc((void *) default_user_key,
                                                   len);

        if (!default_user_key)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }

        sprintf(default_user_key, "%s%s%s",
                home,FILE_SEPERATOR, X509_DEFAULT_USER_KEY);

        if(globus_i_gsi_checkstat(default_user_key) == 0)
        {
            user_key = default_user_key;
        }
    }

    /* if the cert & key don't exist in the default locations
     * or those specified by the environment variables, a
     * pkcs12 cert will be searched for
     */
    if(!user_cert || !user_key)
    {
        if(user_cert) 
        {
            globus_free(user_cert);
        }

        if(user_key)  
        {
            globus_free(user_key);
        }

        len = strlen(home) + 
            strlen(FILE_SEPERATOR) + 
            strlen(X509_DEFAULT_PKCS12_FILE) + 1;

        default_pkcs12_user_cert = 
            (char *)globus_realloc((void *) default_pkcs12_user_cert,
                                   sizeof(char) * len);

        if (!default_pkcs12_user_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        } 
        
        sprintf(default_pkcs12_user_cert,"%s%s%s",
                home, FILE_SEPERATOR, X509_DEFAULT_PKCS12_FILE);

        if(globus_i_gsi_checkstat(default_pkcs12_user_cert) == 0)
        {
            user_cert = default_pkcs12_user_cert;
            user_key = default_pkcs12_user_cert;                    
        }
    }

    if(!user_cert && !user_key)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_user_cert_filename",
            __LINE__,
            "The user cert could not be found in: \n"
            "env. var. X509_USER_CERT=%s\n"
#ifdef WIN32
            "registry key x509_user_cert: %s\n"
#endif            
            "%s\n%s\n\n"
            "The user key could not be found in:\n,"
            "env. var. X509_USER_KEY=%s\n"
#ifdef WIN32
            "registry key x509_user_key: %s\n"
#endif            
            "%s\n%s\n",
            env_user_cert ? env_user_cert : "<not set>",
#ifdef WIN32
            val_user_cert ? val_user_cert : "NULL",
#endif
            default_user_cert ? default_user_cert : "NULL",
            default_pkcs12_user_cert ? default_pkcs12_user_cert : "NULL",
            env_user_key ? env_user_key : "<not set>",
#ifdef WIN32
            val_user_key ? val_user_key : "NULL",
#endif
            default_user_key ? default_user_key : "NULL",
            default_pkcs12_user_cert ? default_pkcs12_user_cert : "NULL");

        if(default_user_cert)
        {
            globus_free(default_user_cert);
        }
        if(default_user_key)
        {
            globus_free(default_user_key);
        }
        if(default_pkcs12_user_cert)
        {
            globus_free(default_pkcs12_user_cert);
        }

        return result;
    }

    if(!user_cert)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_user_cert_filename",
            __LINE__,
            "The user cert could not be found in: \n"
            "env. var. X509_USER_CERT=%s\n"
#ifdef WIN32
            "registry key x509_user_cert: %s\n"
#endif            
            "%s\n%s\n",
            env_user_cert ? env_user_cert : "<not set>",
#ifdef WIN32
            val_user_cert ? val_user_cert : "NULL",
#endif
            default_user_cert ? default_user_cert : "NULL",
            default_pkcs12_user_cert ? default_pkcs12_user_cert : "NULL");
        
        if(default_user_key != user_key && default_user_key)
        {
            globus_free(user_key);
        }
        if(user_key)
        {
            globus_free(user_cert);
        }
        if(default_user_cert)
        {
            globus_free(default_user_cert);
        }
        if(default_pkcs12_user_cert)
        {
            globus_free(default_pkcs12_user_cert);
        }

        return result;
    }

    if(!user_key)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_user_cert_filename",
            __LINE__,
            "The user key could not be found in:\n,"
            "env. var. X509_USER_KEY=%s\n"
#ifdef WIN32
            "registry key x509_user_key: %s\n"
#endif            
            "%s\n%s\n",
            env_user_key ? env_user_key : "<not set>",
#ifdef WIN32
            val_user_key ? val_user_key : "NULL",
#endif
            default_user_key ? default_user_key : "NULL",
            default_pkcs12_user_cert ? default_pkcs12_user_cert : "NULL");

        if(default_user_cert && default_user_cert != user_cert)
        {
            globus_free(default_user_cert);
        }
        if(user_cert)
        {
            globus_free(user_cert);
        }
        if(default_user_key)
        {
            globus_free(default_user_key);
        }
        if(default_pkcs12_user_cert)
        {
            globus_free(default_pkcs12_user_cert);
        }
        
        return result;
    }

    if(default_user_cert && default_user_cert != user_cert)
    {
        globus_free(default_user_cert);
    }
    if(default_user_key && default_user_key != user_key)
    {
        globus_free(default_user_key);
    }

    *user_cert_filename = user_cert;
    *user_key_filename  = user_key;
    
#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            user_cert, user_key);
#endif

    return GLOBUS_SUCCESS;

 error_exit:
    
    if(default_user_cert != user_cert && default_user_cert)
    {
        globus_free(default_user_cert);
    }
    if(user_cert)
    {
        globus_free(user_cert);
    }
    if(default_user_key != user_key && default_user_key)
    {
        globus_free(default_user_key);
    }
    if(user_key)
    {
        globus_free(user_key);
    }
    return result;
}
/* @} */


/**
 * Get User Certificate and Key Filename
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the User Certificate Filename based on the current user's
 * environment.  
 * 
 * @param host_cert_p
 *        pointer to the host certificate filename
 * @param host_key_p
 *        pointer to the host key filename
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier 
 */
globus_result_t
globus_gsi_cred_get_host_cert_filename(
    char **                             host_cert_filename,
    char **                             host_key_filename)
{
    int                                 len;
    char *                              home = NULL;
    char *                              host_cert = NULL;
    char *                              host_key = NULL;
    char *                              env_host_cert = NULL;
    char *                              env_host_key = NULL;
    char *                              default_host_cert = NULL;
    char *                              default_host_key = NULL;
    char *                              default_pkcs12_host_cert = NULL;
    globus_result_t                     result;

#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_host_cert[512];
    char                                val_host_key[512];
#endif

    env_host_cert = (char *)getenv(X509_USER_CERT);

    if(env_host_cert && globus_i_gsi_checkstat(env_host_cert) == 0)
    {
        len = strlen(env_host_cert) + 1;
        host_cert = (char *) globus_malloc ((void *) host_cert,
                                             sizeof(char) * len);
        if(!host_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }
        strncpy(host_cert, env_host_cert, len);
    }

    env_host_key  = (char *)getenv(X509_USER_KEY);    

    if(env_host_key && globus_i_gsi_checkstat(env_host_key) == 0)
    {
        len = strlen(env_host_key) + 1;
        host_key = (char *) globus_realloc ((void *) host_key,
                                            sizeof(char) * len);
        if(!host_key)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }
        strncpy(host_key, env_host_key, len);
    }

#ifdef WIN32
    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
    
    if(!host_cert)
    {
        strncpy(val_host_cert, "<not set>", (strlen("<not set>") + 1));
        lval = sizeof(val_host_cert)-1;
        if (hkDir && (RegQueryValueEx(
            hkDir,
            "x509_user_cert",
            0,
            &type,
            val_host_cert,&lval) == ERROR_SUCCESS))
        {
            if(globus_i_gsi_checkstat(val_host_cert) == 0)
            {
                len = strlen(val_host_cert) + 1;
                host_cert = (char *) globus_realloc (sizeof(char) * len);
                if(!host_cert)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(host_cert, val_host_cert, len);
            }
        }
    }

    if(!host_key)
    {
        strncpy(val_host_key, "<not set>", (strlen("<not set>") + 1));
        lval = sizeof(val_host_key)-1;
        if (hkDir && (RegQueryValueEx(
            hkDir,
            "x509_user_key",
            0,
            &type,
            val_host_key,&lval) == ERROR_SUCCESS))
        {
            if(globus_i_gsi_checkstat(val_host_key) == 0)
            {
                len = strlen(val_host_key) + 1;
                host_key = (char *) globus_realloc (sizeof(char) * len);
                if(!host_key)
                {
                    result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                    goto error_exit;
                }
                strncpy(host_key, val_host_key, len);
            }
        }
    }

    RegCloseKey(hkDir);
#endif

    if(((result = globus_i_gsi_get_home_dir(&home)) == GLOBUS_SUCCESS)
       && !host_cert)
    {
        len = strlen(X509_DEFAULT_HOST_CERT) + 1;
        default_host_cert = (char *) globus_realloc((void *) default_host_cert,
                                                    len);

        if (!default_host_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }

        sprintf(default_host_cert,"%s%s%s",
                home, FILE_SEPERATOR, X509_DEFAULT_HOST_CERT);

        if(globus_i_gsi_checkstat(default_host_cert) == 0)
        {
            host_cert = default_host_cert;
        }
    }

    if(result == GLOBUS_SUCCESS && !host_key)
    {
        len = strlen(X509_DEFAULT_HOST_KEY) + 1;

        default_host_key = (char *) globus_realloc((void *) default_host_key,
                                                   len);

        if (!default_host_key)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        }

        sprintf(default_host_key, "%s%s%s",
                home,FILE_SEPERATOR, X509_DEFAULT_HOST_KEY);

        if(globus_i_gsi_checkstat(default_host_key) == 0)
        {
            host_key = default_host_key;
        }
    }

    /* if the cert & key don't exist in the default locations
     * or those specified by the environment variables, a
     * pkcs12 cert will be searched for
     */
    if(!host_cert || !host_key)
    {
        if(host_cert) 
        {
            globus_free(host_cert);
        }

        if(host_key)  
        {
            globus_free(host_key);
        }

        len = strlen(X509_DEFAULT_HOST_PKCS12_FILE) + 1;

        default_pkcs12_host_cert = 
            (char *)globus_realloc((void *) default_pkcs12_host_cert,
                                   sizeof(char) * len);

        if (!default_pkcs12_host_cert)
        {
            result = GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            goto error_exit;
        } 
        
        sprintf(default_pkcs12_host_cert,"%s%s%s",
                home, FILE_SEPERATOR, X509_DEFAULT_HOST_PKCS12_FILE);

        if(globus_i_gsi_checkstat(default_pkcs12_host_cert) == 0)
        {
            host_cert = default_pkcs12_host_cert;
            host_key = default_pkcs12_host_cert;                    
        }
    }

    if(!host_cert && !host_key)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_host_cert_filename",
            __LINE__,
            "The user cert could not be found in: \n"
            "env. var. X509_USER_CERT=%s\n"
#ifdef WIN32
            "registry key x509_user_cert: %s\n"
#endif            
            "%s\n%s\n\n"
            "The user key could not be found in:\n,"
            "env. var. X509_USER_KEY=%s\n"
#ifdef WIN32
            "registry key x509_user_key: %s\n"
#endif            
            "%s\n%s\n",
            env_host_cert ? env_host_cert : "<not set>",
#ifdef WIN32
            val_host_cert ? val_host_cert : "NULL",
#endif
            default_host_cert ? default_host_cert : "NULL",
            default_pkcs12_host_cert ? default_pkcs12_host_cert : "NULL",
            env_host_key ? env_host_key : "<not set>",
#ifdef WIN32
            val_host_key ? val_host_key : "NULL",
#endif
            default_host_key ? default_host_key : "NULL",
            default_pkcs12_host_cert ? default_pkcs12_host_cert : "NULL");

        if(default_host_cert)
        {
            globus_free(default_host_cert);
        }
        if(default_host_key)
        {
            globus_free(default_host_key);
        }
        if(default_pkcs12_host_cert)
        {
            globus_free(default_pkcs12_host_cert);
        }

        return result;
    }

    if(!host_cert)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_host_cert_filename",
            __LINE__,
            "The user cert could not be found in: \n"
            "env. var. X509_USER_CERT=%s\n"
#ifdef WIN32
            "registry key x509_user_cert: %s\n"
#endif            
            "%s\n%s\n",
            env_host_cert ? env_host_cert : "<not set>",
#ifdef WIN32
            val_host_cert,
#endif
            default_host_cert,
            default_pkcs12_host_cert);
        
        if(default_host_key != host_key && default_host_key)
        {
            globus_free(host_key);
        }
        if(host_key)
        {
            globus_free(host_cert);
        }
        if(default_host_cert)
        {
            globus_free(default_host_cert);
        }
        if(default_pkcs12_host_cert)
        {
            globus_free(default_pkcs12_host_cert);
        }

        return result;
    }

    if(!host_key)
    {
        result = globus_i_gsi_credential_error_result(
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_host_cert_filename",
            __LINE__,
            "The user key could not be found in:\n,"
            "env. var. X509_USER_KEY=%s\n"
#ifdef WIN32
            "registry key x509_user_key: %s\n"
#endif            
            "%s\n%s\n",
            env_host_key ? env_host_key : "<not set>",
#ifdef WIN32
            val_host_key ? val_host_key : "NULL",
#endif
            default_host_key ? default_host_key : "NULL",
            default_pkcs12_host_cert ? default_pkcs12_host_cert : "NULL");

        if(default_host_cert && default_host_cert != host_cert)
        {
            globus_free(default_host_cert);
        }
        if(host_cert)
        {
            globus_free(host_cert);
        }
        if(default_host_key)
        {
            globus_free(default_host_key);
        }
        if(default_pkcs12_host_cert)
        {
            globus_free(default_pkcs12_host_cert);
        }
        
        return result;
    }

    if(default_host_cert && default_host_cert != host_cert)
    {
        globus_free(default_host_cert);
    }
    if(default_host_key && default_host_key != host_key)
    {
        globus_free(default_host_key);
    }

    *host_cert_filename = host_cert;
    *host_key_filename  = host_key;
    
#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            host_cert, host_key);
#endif

    return GLOBUS_SUCCESS;

 error_exit:
    
    if(default_host_cert != host_cert && default_host_cert)
    {
        globus_free(default_host_cert);
    }
    if(host_cert)
    {
        globus_free(host_cert);
    }
    if(default_host_key != host_key && default_host_key)
    {
        globus_free(default_host_key);
    }
    if(host_key)
    {
        globus_free(host_key);
    }
    return result;
}
/* @} */


globus_result_t
globus_gsi_cred_get_service_cert_filename(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename)
{
}

/**
 * Get Proxy Filename
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the proxy cert filename based on the following
 * search order:
 * 
 * <ol>
 * <li> X509_USER_PROXY environment variable - This environment variable
 * is set by the at run time for the specific application.  If
 * the proxy_in variable is set to false (a proxy filename for writing 
 * is requested), and the X509_USER_PROXY is set, this will be the 
 * resulting value of the user_proxy filename string passed in.  If the
 * proxy_in variable is true and X509_USER_PROXY is set, but the file
 * it points to does not exist, or has some other readability issues, the 
 * function will continue checking using the other methods available.
 * 
 * <li> If on Windows, check the registry key: x509_user_proxy.  Just as with
 * the environment variable, if the registry key is set, and proxy_in
 * is false, the string set to be the proxy filename will be this registry
 * key's value.  If proxy_in is true, and the file doesn't exist, the
 * function will check the next method for the proxy's filename.
 * 
 * <li> Check the default location for the proxy file.  The default
 * location depends on the system (windows or unix), but should be
 * set to reside in the temp directory on that host, with the filename
 * taking the format:  x509_u<user id>
 * where <user id> is some unique string for that user on the host
 * </ol>
 *
 * @param user_proxy_p
 *        the proxy filename of the user
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_cred_get_proxy_filename(
    char **                             proxy_filename,
    int                                 proxy_in)
{
    char *                              user_proxy = NULL;
    char *                              env_user_proxy = NULL;
    char *                              default_user_proxy = NULL;
#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_user_proxy[512];
#endif
    int                                 len;
    int                                 stat;
    globus_result_t                     result;
    char *                              user_id_string;

    env_user_proxy = (char *) getenv(X509_USER_PROXY);

    if(env_user_proxy)
    {
        stat = globus_i_gsi_checkstat(env_user_proxy);
        if(stat == 0 || (stat == 1 && !proxy_in))
        {
            len = strlen(env_user_proxy) + 1;
            user_proxy = (char *) globus_malloc (sizeof(char) * len);
            if(!user_proxy)
            {
                return GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
            }
            strncpy(user_proxy, env_user_proxy, len);
        }
    }

#ifdef WIN32
    if (!user_proxy)
    {
        RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
        strncpy(val_user_proxy, "<not set>", (strlen("<not set>") + 1));
        lval = sizeof(val_user_proxy)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_user_proxy",0,&type,
                                      val_user_proxy,&lval) == ERROR_SUCCESS))
        {
            stat = globus_i_gsi_checkstat(val_user_proxy);
            if(stat == 0 || (stat == 1 && !proxy_in))
            {
                len = strlen(val_user_proxy) + 1;
                user_proxy = (char *) globus_malloc(sizeof(char) * len);
                if(!user_proxy)
                {
                    return GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
                }
                strncpy(user_proxy, val_user_proxy, len);
            }
        }
        RegCloseKey(hkDir);
    }
#endif

    if (!user_proxy)
    {
        globus_i_gsi_get_user_id_string(&user_id_string);
        len = strlen(DEFAULT_SECURE_TMP_DIR) 
            + strlen(X509_USER_PROXY_FILE) 
            + strlen(user_id_string) + 1;
        
        default_user_proxy = (char *) globus_malloc(len);
        if (!default_user_proxy)
        {
            return GLOBUS_GSI_SYSTEM_CONFIG_MALLOC_ERROR;
        }
        sprintf(default_user_proxy,"%s%s%s%s",
                DEFAULT_SECURE_TMP_DIR,
                FILE_SEPERATOR,
                X509_USER_PROXY_FILE,
                user_id_string);
        
        stat = globus_i_gsi_checkstat(default_user_proxy);
        if(stat == 0 || (stat == 1 && !proxy_in)) 
        {
            user_proxy = default_user_proxy;
        }
    }

    if(!user_proxy)
    {            
        result = globus_i_gsi_credential_error_result( 
            GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG,
            __FILE__,
            "globus_i_gsi_get_user_proxy_filename",
            __LINE__, 
            "No location for %sthe proxy cert could be found in: \n"
            "env. var. X509_USER_PROXY=%s\n"
#ifdef WIN32
            "registry key x509_user_proxy: %s\n"
#endif
            "%s\n",
            proxy_in ? "" : "writing",
            env_user_proxy ? env_user_proxy : "<not set>",
#ifdef WIN32
            val_user_proxy ? val_user_proxy : "NULL",
#endif                
            default_user_proxy ? default_user_proxy : "NULL");

        if(default_user_proxy && default_user_proxy != user_proxy)
        {
            globus_free(default_user_proxy);
        }
        if(user_proxy)
        {
            globus_free(user_proxy);
        }
        return result;
    }

    if(default_user_proxy && default_user_proxy != user_proxy)
    {
        globus_free(default_user_proxy);
    }
    
    *proxy_filename = user_proxy;
    return GLOBUS_SUCCESS;
}
/* @} */

#endif
