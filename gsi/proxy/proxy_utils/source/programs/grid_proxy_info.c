/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file grid_proxy_info.h
 * Globus GSI Proxy Utils
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_common.h"
#include "globus_error.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"
#include "globus_openssl.h"
#ifdef WIN32
#include "globus_gssapi_config.h"
#endif

int                                     debug = 0;

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-f proxyfile][-subject][...][-e [-h H][-b B]]\n"

static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -debug                    Displays debugging output\n" \
"    -file <proxyfile>  (-f)   Non-standard location of proxy\n" \
"    [printoptions]            Prints information about proxy\n" \
"    -exists [options]  (-e)   Returns 0 if valid proxy exists, 1 otherwise\n"\
"\n" \
"    [printoptions]\n" \
"        -subject       (-s)   Distinguished name (DN) of subject\n" \
"        -issuer        (-i)   DN of issuer (certificate signer)\n" \
"        -identity             DN of the identity represented by the proxy\n" \
"        -type                 Type of proxy (full or limited)\n" \
"        -timeleft             Time (in seconds) until proxy expires\n" \
"        -strength             Key size (in bits)\n" \
"        -all                  All above options in a human readable format\n"\
"        -text                 All of the certificate\n"\
"        -path                 Pathname of proxy file\n"
"\n" \
"    [options to -exists]      (if none are given, H = B = 0 are assumed)\n" \
"        -valid H:M     (-v)   time requirement for proxy to be valid\n" \
"        -hours H       (-h)   time requirement for proxy to be valid\n" \
"                              (deprecated, use -valid instead)\n"
"        -bits  B       (-b)   strength requirement for proxy to be valid\n" \
"\n";


#   define args_show_version() \
    { \
        char buf[64]; \
        sprintf( buf, \
                 "%s-%s", \
                 PACKAGE, \
                 VERSION); \
        fprintf(stderr, "%s\n", buf); \
        globus_module_deactivate_all(); \
        exit(0); \
    }

#   define args_show_short_help() \
    { \
        fprintf(stderr, \
                SHORT_USAGE_FORMAT \
                "\nUse -help to display full usage.\n", \
                program); \
        globus_module_deactivate_all(); \
    }

#   define args_show_full_usage() \
    { \
        fprintf(stderr, SHORT_USAGE_FORMAT \
                "%s", \
                program, \
                LONG_USAGE); \
        globus_module_deactivate_all(); \
        exit(0); \
    }

#   define args_error_message(errmsg) \
    { \
        fprintf(stderr, "\nERROR: %s\n", errmsg); \
        args_show_short_help(); \
        globus_module_deactivate_all(); \
        exit(1); \
    }

#   define args_error(argp, errmsg) \
    { \
        char buf[1024]; \
        sprintf(buf, "option %s : %s", argp, errmsg); \
        args_error_message(buf); \
    }

void
globus_i_gsi_proxy_utils_print_error(
    globus_result_t                     result,
    int                                 debug,
    const char *                        filename,
    int                                 line);

#define GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR \
    globus_i_gsi_proxy_utils_print_error(result, debug, __FILE__, __LINE__)

#define STATUS_OK               0
#define STATUS_EXPIRED          1
#define STATUS_NOT_FOUND        2
#define STATUS_CANT_LOAD        3
#define STATUS_NO_NAME          4
#define STATUS_BAD_OPTS         5
#define STATUS_INTERNAL         6

int 
main(
    int                                 argc, 
    char *                              argv[])
{
    char *                              program;
    int                                 strength          = 0;
    int                                 bits              = 0;
    int                                 time_valid        = 0;
    int                                 exists_flag       = 0;
    int                                 time_valid_flag   = 0;
    int                                 hours_flag        = 0;
    int                                 bits_flag         = 0;
    int                                 is_valid          = 0;
    int                                 arg_index;
    char *                              argp;
    char *                              proxy_filename = NULL;
    char *                              subject;
    char *                              issuer;
    char *                              identity;
    globus_gsi_cert_utils_cert_type_t   cert_type;
    char *                              cert_type_name;
    time_t                              lifetime;
    globus_gsi_cred_handle_t            proxy_cred = NULL;
    X509 *                              proxy_cert = NULL;
    EVP_PKEY *                          proxy_pubkey = NULL;
    globus_result_t                     result;
    globus_bool_t                       print_all = GLOBUS_TRUE;

    if(globus_module_activate(GLOBUS_OPENSSL_MODULE) !=
       (int)GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\n\nERROR: Couldn't load module: GLOBUS_OPENSSL_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        exit(1);
    }

    
    if(globus_module_activate(GLOBUS_GSI_PROXY_MODULE) != (int)GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\n\nERROR: Couldn't load module: GLOBUS_GSI_PROXY_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        exit(1);
    }

    if (strrchr(argv[0], '/'))
    {
        program = strrchr(argv[0], '/') + 1;
    }
    else
    {
        program = argv[0];
    }

    /* Parsing phase 1: check all arguments that they are valid */
    for (arg_index = 1; arg_index < argc; arg_index++)
    {
        argp = argv[arg_index];

        if (strncmp(argp, "--", 2) == 0)
        {
            if (argp[2] != '\0')
            {
                args_error(argp, "double-dashed options "
                           "are not allowed");
            }
            else
            {
                arg_index = argc + 1;                   /* no more parsing */
                continue;
            }
        }
        if ((strcmp(argp, "-help") == 0) ||
            (strcmp(argp, "-usage") == 0))
        {
            args_show_full_usage();
        }
        else if (strcmp(argp, "-version") == 0)
        {
            args_show_version();
        }
        else if ((strcmp(argp, "-file") == 0) ||
                 (strcmp(argp, "-f") == 0)   )
        {
            if ((arg_index + 1 >= argc) || (argv[arg_index + 1][0] == '-'))
            {
                args_error(argp, "needs a file name argument");
            }
            else
            {
                proxy_filename = argv[++arg_index];
            }
        }
        else if ((strcmp(argp, "-exists") == 0) ||
                 (strcmp(argp, "-e") == 0))
        {
            if (exists_flag)
            {
                args_error(argp, "can only be given once");
            }
            exists_flag++;
        }
        else if ((strcmp(argp,"-hours")==0) ||
                 (strcmp(argp,"-h")==0)       )
        {
            if (!exists_flag || hours_flag)
            {
                args_error(argp, "suboption to -exists");
            }
            hours_flag++;
            if (( arg_index + 1 >= argc) || (argv[arg_index + 1][0] == '-'))
            {
                args_error(argp, "need a non-negative integer argument");
            }
            else
                time_valid = atoi(argv[++arg_index]) * 60;
        }
        else if ((strcmp(argp, "-valid") == 0) ||
                 (strcmp(argp, "-v") == 0)       )
        {
            int                         hours = 0;
            int                         minutes = 0;
            if (!exists_flag || time_valid_flag)
            {
                args_error(argp, "suboption to -exists");
            }
            time_valid_flag++;
            if ((arg_index + 1 >= argc) || (argv[arg_index + 1][0] == '-'))
            {
                args_error(argp, "need a non-negative integer argument");
            }
            else if(sscanf(argv[++arg_index], "%d:%d", &hours, &minutes) < 2)
            {
                args_error(argp, "value must be in the format: H:M");
            }

            if(hours < 0)
            {
                args_error(argp, "specified hours must be a nonnegative integer");
            }

            if(minutes < 0 || minutes > 60)
            {
                args_error(argp, "specified minutes must be in the range 0-60");
            }
            time_valid = (hours * 60) + minutes;
        }
        else if ((strcmp(argp, "-bits") == 0) ||
                 (strcmp(argp, "-b") == 0)       )
        {
            if (!exists_flag || bits_flag)
            {
                args_error(argp, "suboption to -exists");
            }
            bits_flag++;
            if ((arg_index + 1 >= argc) || (argv[arg_index + 1][0] == '-'))
            {
                args_error(argp, "need a non-negative integer argument");
            }
            else
                bits = atoi(argv[++arg_index]);
        }
        else if ((strcmp(argp, "-subject") == 0)  ||
                 (strcmp(argp, "-s") == 0)        ||
                 (strcmp(argp, "-identity") == 0) ||
                 (strcmp(argp, "-issuer") == 0)   ||
                 (strcmp(argp, "-i") == 0)        ||
                 (strcmp(argp, "-strength") == 0) ||
                 (strcmp(argp, "-type") == 0)     ||
                 (strcmp(argp, "-timeleft") == 0) ||
                 (strcmp(argp, "-text") == 0)     ||
                 (strcmp(argp, "-all") == 0)      ||
                 (strcmp(argp, "-path") == 0))
        {
            continue;
        }
        else if ((strcmp(argp, "-debug") == 0))
        {
            debug = 1;
        }
        else
            args_error(argp, "unrecognized option");
    }

    if(proxy_filename)
    {
        result = GLOBUS_GSI_SYSCONFIG_CHECK_KEYFILE(proxy_filename);
    }
    else
    { 
        result = GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(
            &proxy_filename,
            GLOBUS_PROXY_FILE_INPUT);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
       globus_libc_fprintf(
           stderr,
           "\nERROR: Couldn't find a valid proxy.\n");
       GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    result = globus_gsi_cred_handle_init(&proxy_cred, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't initialize proxy credential handle\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }
    
    result = globus_gsi_cred_read_proxy(proxy_cred, proxy_filename);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't read proxy from: %s\n", proxy_filename);
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    result = globus_gsi_cred_get_cert(proxy_cred, &proxy_cert);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get the proxy certificate from "
            "the proxy credential.\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    if ((proxy_pubkey = X509_get_pubkey(proxy_cert)) == NULL)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: unable to load public key from proxy\n");
        globus_module_deactivate_all();
        exit(1);
    }

    /* The things we will need to know below: subject, issuer,
       strength, validity, type */

    /* subject */
    result = globus_gsi_cred_get_subject_name(proxy_cred, &subject);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get a valid subject "
            "name from the proxy credential.\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    /* issuer */

    result = globus_gsi_cred_get_issuer_name(proxy_cred, &issuer);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get a valid issuer "
            "name from the proxy credential.\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }
    /* issuer */

    result = globus_gsi_cred_get_identity_name(proxy_cred, &identity);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get a valid identity "
            "name from the proxy credential.\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }
    
    /* validity: set time_diff to time to expiration (in seconds) */
    result = globus_gsi_cred_get_lifetime(proxy_cred,
                                          &lifetime);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get a valid lifetime "
            "for the proxy credential.\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    /* strength: set strength to key size (in bits) */
    strength = 8 * EVP_PKEY_size(proxy_pubkey);

    /* check if proxy is valid in our own defined sense */
    if (exists_flag)
    {
        is_valid = (lifetime >= (time_valid * 60)) && 
                   (strength >= bits) ? 0 : 1;
    }
    else
    {
        is_valid = 0;
    }

    /* type: restricted, limited or full */
    result = globus_gsi_cred_get_cert_type(proxy_cred,
                                           &cert_type);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get the proxy type "
            "from the proxy credential\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }
    
    switch(cert_type)
    {
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY:
        cert_type_name = "RFC 3820 compliant impersonation proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_INDEPENDENT_PROXY:
        cert_type_name = "RFC 3820 compliant independent proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY:
        cert_type_name = "RFC 3820 compliant limited proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_RESTRICTED_PROXY:
        cert_type_name = "RFC 3820 compliant restricted proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY:
        cert_type_name = "Proxy draft (pre-RFC) compliant impersonation proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY:
        cert_type_name = "Proxy draft (pre-RFC) compliant independent proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY:
        cert_type_name = "Proxy draft (pre-RFC) compliant limited proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY:
        cert_type_name = "Proxy draft (pre-RFC) compliant restricted proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY:
        cert_type_name = "full legacy globus proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY:
        cert_type_name = "limited legacy globus proxy";
        break;
      case GLOBUS_GSI_CERT_UTILS_TYPE_EEC:
        cert_type_name = "end entity credential";
        break;        
      default:
        globus_libc_fprintf(
            stderr,
            "\nERROR: Not a proxy\n\n");
        globus_module_deactivate_all();
        exit(1);
    }
    
    for (arg_index = 1; arg_index < argc; arg_index++)
    {
	argp = argv[arg_index];
	if ((strcmp(argp,"-subject") == 0) ||
            (strcmp(argp, "-s") == 0))
	{
	    printf("%s\n", subject);
            print_all = GLOBUS_FALSE;
	}
	else if ((strcmp(argp, "-issuer") == 0) ||
                 (strcmp(argp, "-i") == 0))
	{
	    printf("%s\n", issuer);
            print_all = GLOBUS_FALSE;
	}
	else if (strcmp(argp, "-identity") == 0)
	{
	    printf("%s\n", identity);
            print_all = GLOBUS_FALSE;
	}
	else if (strcmp(argp, "-timeleft") == 0)
	{
	    printf("%ld\n", (long) ((lifetime >= 0) ? lifetime : -1));
            print_all = GLOBUS_FALSE;
	}
	else if (strcmp(argp, "-type") == 0)
	{
	    printf("%s\n", cert_type_name);
            print_all = GLOBUS_FALSE;
	}
	else if (strcmp(argp, "-strength") == 0)
	{
	    printf("%d\n", strength);
            print_all = GLOBUS_FALSE;
	}
	else if (strcmp(argp, "-text") == 0)
	{
            X509_print_fp(stdout, proxy_cert);
            print_all = GLOBUS_FALSE;
        }
        else if (strcmp(argp, "-all") == 0)
        {
            printf("subject  : %s\n" 
                   "issuer   : %s\n"
                   "identity : %s\n" 
                   "type     : %s\n" 
                   "strength : %d bits\n"
                   "path     : %s\n"
		   "timeleft : ",
		   subject,
		   issuer,
                   identity,
		   cert_type_name,
		   strength,
                   proxy_filename);

            if (lifetime <= 0)
                lifetime = 0;

            printf("%ld:%02ld:%02ld",
                   (long)(lifetime / 3600),
                   (long)(lifetime % 3600) / 60,
                   (long)lifetime % 60 );

            if (lifetime > 3600 * 24)
                printf("  (%.1f days)", (float)(lifetime / 3600) / 24.0);
            printf("\n");
            print_all = GLOBUS_FALSE;
        }
        else if ((strcmp(argp, "-valid") == 0) ||
                 (strcmp(argp, "-bits") == 0) ||
                 (strcmp(argp, "-file") == 0) ||
                 (strcmp(argp, "-f") == 0))
        {
            arg_index++;
            continue;
        }
        else if (strcmp(argp, "-path") == 0)
        {
            printf("%s\n", proxy_filename);
            print_all = GLOBUS_FALSE;
        }
    }

    if (print_all == GLOBUS_TRUE && exists_flag == 0)
    {
        printf("subject  : %s\n" 
               "issuer   : %s\n"
               "identity : %s\n" 
               "type     : %s\n" 
               "strength : %d bits\n"
               "path     : %s\n"
               "timeleft : ",
               subject,
               issuer,
               identity,
               cert_type_name,
               strength,
               proxy_filename);
        
        if (lifetime <= 0)
            lifetime = 0;
        
        printf("%ld:%02ld:%02ld",
               (long)(lifetime / 3600),
               (long)(lifetime % 3600) / 60,
               (long)lifetime % 60 );
        
        if (lifetime > 3600 * 24)
            printf("  (%.1f days)", (float)(lifetime / 3600) / 24.0);
        printf("\n");
    }

    #ifdef WIN32
    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    OPENSSL_free(identity);
    #else
    free(subject);
    free(issuer);
    free(identity);
    #endif
    
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);

    return (is_valid);
}

void
globus_i_gsi_proxy_utils_print_error(
    globus_result_t                     result,
    int                                 debug,
    const char *                        filename,
    int                                 line)
{
    globus_object_t *                   error_obj;
    char *                              error_string = NULL;

    error_obj = globus_error_get(result);
    error_string = globus_error_print_chain(error_obj);

    if(debug)
    {
        globus_libc_fprintf(stderr, "       %s:%d: %s", filename, line, error_string);
    }
    else 
    {
        globus_libc_fprintf(stderr, "       %s\nUse -debug for further information.\n", error_string);
    }
    if(error_string)
    {
       globus_libc_free(error_string);
    }
    globus_object_free(error_obj);
    globus_module_deactivate_all();
    exit(1);
}
