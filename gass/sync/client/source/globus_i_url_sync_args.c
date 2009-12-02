/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * CVS Information
 *
 * $Source$
 * $Date$
 * $Revision$
 */

#include "globus_i_url_sync_args.h"
#include "globus_url.h"
#include "globus_libc.h"
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>

globus_url_t *          globus_i_url_sync_args_source;
globus_url_t *          globus_i_url_sync_args_destination;
globus_bool_t           globus_i_url_sync_args_verbose;
globus_bool_t           globus_i_url_sync_args_debug;

static globus_url_t     globus_l_url_sync_args_source;
static globus_url_t     globus_l_url_sync_args_destination;

/*
 * globus_l_url_sync_usage -- prints usage for this program
 */
static void
globus_l_url_sync_usage(char *prog)
{
    globus_libc_fprintf(stderr, "Usage: %s: [OPTIONS] SOURCE DESTINATION\n", prog);
}
/* globus_l_url_sync_usage */

/*
 * globus_l_url_sync_badarg -- prints error for bad argument
 */
static void
globus_l_url_sync_badarg(char *badarg)
{
    globus_libc_fprintf(stderr, "Bad argument: %s\n", badarg);
}
/* globus_l_url_sync_badarg */

/*
 * globus_i_url_sync_parse_args -- parses command-line arguments
 */
globus_result_t
globus_i_url_sync_parse_args(
        int             argc,
        char            *argv[])
{
    int                 c, result;

    /* Defaults */
    globus_i_url_sync_args_verbose  = GLOBUS_FALSE;
    globus_i_url_sync_args_debug    = GLOBUS_FALSE;

    /* Parse args */
    while ((c = getopt(argc, argv, "dhv")) != -1)
    {
         switch (c)
         {
             case 'd':
                 globus_i_url_sync_args_debug = GLOBUS_TRUE;
                 break;
             case 'v':
                 globus_i_url_sync_args_verbose = GLOBUS_TRUE;
                 break;
             case '?':
             case 'h':
             default:
                 goto usage;
         }
    }

    /* Get source, destination */
    if (optind != argc-2)
    {
        goto usage;
    }

    result = globus_url_parse(argv[optind], &globus_l_url_sync_args_source);
    if (result != GLOBUS_URL_SUCCESS)
    {
        globus_l_url_sync_badarg(argv[optind]);
        globus_url_destroy(&globus_l_url_sync_args_source);
        goto usage;
    }
    globus_i_url_sync_args_source = &globus_l_url_sync_args_source;

    if (globus_i_url_sync_args_verbose)
        globus_libc_fprintf(stderr, "Source: %s\n", argv[optind]);

    result = globus_url_parse(argv[optind+1], &globus_l_url_sync_args_destination);
    if (result != GLOBUS_URL_SUCCESS)
    {
        globus_l_url_sync_badarg(argv[optind+1]);
        globus_url_destroy(&globus_l_url_sync_args_source);
        globus_url_destroy(&globus_l_url_sync_args_destination);
        goto usage;
    }
    globus_i_url_sync_args_destination = &globus_l_url_sync_args_destination;

    if (globus_i_url_sync_args_verbose)
        globus_libc_fprintf(stderr, "Destination: %s\n", argv[optind+1]);

    return GLOBUS_SUCCESS;

usage:
    globus_l_url_sync_usage(argv[0]);
    return GLOBUS_FAILURE;
}
/* globus_i_url_sync_parse_args */

