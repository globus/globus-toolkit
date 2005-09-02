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
 * @file grid_proxy_destroy.h
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
#include "globus_gsi_system_config.h"
#ifdef WIN32
#include "globus_gssapi_config.h"
#endif

int                                     debug = 0;

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-dryrun][-default][-all][--] [file1...]\n"

static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -debug                    Display debugging information\n" \
"    -dryrun                   Prints what files would have been destroyed\n" \
"    -default                  Destroys file at default proxy location\n" \
"    -all                      Destroys any user (default) and delegated "
"                              proxies that are found\n" \
"    --                        End processing of options\n" \
"    file1 file2 ...           Destroys files listed\n" \
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
                program ? program : "(null)", \
                LONG_USAGE); \
        globus_module_deactivate_all(); \
        exit(0); \
    }

#   define args_error_message(errmsg) \
    { \
        fprintf(stderr, "\nERROR: %s\n", errmsg ? errmsg : "(null)"); \
        args_show_short_help(); \
        globus_module_deactivate_all(); \
        exit(1); \
    }

#   define args_error(argval, errmsg) \
    { \
        char buf[1024]; \
        sprintf(buf, "option %s : %s", argval, errmsg); \
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

static int
globus_i_gsi_proxy_utils_clear_and_remove(
    char *                              filename,
    int                                 flag); 

int main(
    int                                 argc, 
    char **                             argv)
{
    int                                 all_flag      = 0;
    int                                 default_flag  = 0;
    int                                 dryrun_flag   = 0;
    int                                 filename_flag = 0;
    int                                 i;
    char *                              argp;
    char *                              program;
    char *                              default_file;
    char *                              default_full_file = NULL;
    char *                              dummy_dir_string;
    globus_result_t                     result = GLOBUS_SUCCESS;

    if(globus_module_activate(GLOBUS_GSI_PROXY_MODULE) != (int)GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't load module: GLOBUS_GSI_PROXY_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        exit(1);
    }

    if (strrchr(argv[0],'/'))
    {
        program = strrchr(argv[0],'/') + 1;
    }
    else
    {
        program = argv[0];
    }

    for (i = 1; i < argc; i++)
    {
        argp = argv[i];

        /* '--' indicates end of options */
        if (strcmp(argp,"--") == 0)
        {
            i++;
            break;
        }

        /* If no leading dash assume it's start of filenames */
        if (strncmp(argp, "-", 1) != 0)
        {
            break;
        }
        else if (strcmp(argp, "-all") == 0)
        {
            all_flag++;
        }
        else if (strcmp(argp, "-default") == 0)
        {
            default_flag++;
        }
        else if (strcmp(argp, "-dryrun") == 0)
        {
            dryrun_flag++;
        }
        else if (strncmp(argp, "--", 2) == 0)
        {
            args_error(argp, "double-dashed options not allowed");
        }
        else if((strcmp(argp, "-help") == 0) ||
                (strcmp(argp, "-usage") == 0) )
        {
            args_show_full_usage();
        }
        else if (strcmp(argp, "-version") == 0)
        {
            args_show_version();
        }
        else if (strcmp(argp, "-debug") == 0)
        {
            debug = 1;
        }            
        else 
        {
            args_error(argp, "unknown option");
        }
    }

    /* remove the files listed on the command line first */

    if(i < argc)
    {
        filename_flag = 1;
    }
    
    for (; i < argc; i++)
    {
        globus_i_gsi_proxy_utils_clear_and_remove(argv[i], dryrun_flag);
    }

    if(!filename_flag || default_flag || all_flag)
    {
        result = GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(&default_full_file,
                                                         GLOBUS_PROXY_FILE_INPUT);
        if(result != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(
                stderr,
                "\nERROR: Proxy file doesn't exist or has bad permissions\n");
            GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
        }
    }

    if (default_flag)
    {
        globus_i_gsi_proxy_utils_clear_and_remove(default_full_file, 
                                                  dryrun_flag);
    }

    if (all_flag)
    {
        result = GLOBUS_GSI_SYSCONFIG_SPLIT_DIR_AND_FILENAME(default_full_file,
                                                             &dummy_dir_string,
                                                             &default_file);
        if(result != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(
                stderr,
                "\nERROR: Failed to determine the secure "
                "tmp directory proxies are stored in\n");
            GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
        }
        
        result = GLOBUS_GSI_SYSCONFIG_REMOVE_ALL_OWNED_FILES(
            default_file);
        if(result != GLOBUS_SUCCESS)
        {
            free(default_full_file);
            globus_libc_fprintf(
                stderr,
                "\nERROR: Couldn't remove the all the files "
                "owned by you in secure tmp directory.\n");
            GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
        }
    }
        
    /* 
     * no options, remove the default file, which is the ENV
     * or the /tmp/x509up_u<uid> file
     */

    if (!default_flag && !all_flag && !filename_flag)
    {
        globus_i_gsi_proxy_utils_clear_and_remove(default_full_file,
                                                  dryrun_flag);
    }

 done:

    if(default_full_file)
    { 
        free(default_full_file);
    }

    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);

    return 0;
}


static int
globus_i_gsi_proxy_utils_clear_and_remove(
    char *                              filename,
    int                                 flag) 
{
    int                                 f;
    int                                 rec;
    int                                 left;
    long                                size;
    char                                msg[65] 
        = "Destroyed by globus_proxy_destroy\r\n";

    if (flag)
        fprintf(stderr, "Would remove %s\n", filename ? filename : "(null)");
    else
    {
        #ifdef WIN32
        _chmod(filename, S_IREAD|S_IWRITE);
        #endif
        
        f = open(filename, O_RDWR);
        if (f) 
        {
            size = lseek(f, 0L, SEEK_END);
            lseek(f, 0L, SEEK_SET);
            if (size > 0) 
            {
                rec = size / 64;
                left = size - rec * 64;
                while (rec)
                {
                    write(f, msg, 64);
                    rec--;
                }
                if (left) 
                    write(f, msg, left);
            }
            close(f);
        }
        remove(filename);
    }
    return 0;
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
