/*
 * Copyright 1999-2009 University of Chicago
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_job_manager.c Resource Allocation Job Manager
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_gram_job_manager.h"
#include "globus_common.h"

static int
globus_l_gram_tokenize(
    char *                              command,
    char **                             args,
    int *                               n);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Initialize configuration based on command-line arguments
 *
 * @param config
 *     LRMA-specific configuration state
 * @param argc
 *     Count of command-line arguments to the job manager.
 * @param argv
 *     Array of command-line arguments to the job manager.
 * @param rsl
 *     Out: Value of RSL specified in the command-line arguments. NULL if
 *     RSL is not specified.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED
 *     Command-line includes -help
 */
int
globus_gram_job_manager_config_init(
    globus_gram_job_manager_config_t *  config,
    int                                 argc,
    char **                             argv,
    char **                             rsl)
{
    int                                 i;
    int                                 rc = 0;
    char                                hostname[MAXHOSTNAMELEN];

    memset(config, 0, sizeof(globus_gram_job_manager_config_t));

    *rsl = NULL;

    /* if -conf is passed then get the arguments from the file
     * specified
     */
    if (argc > 2 && !strcmp(argv[1],"-conf"))
    {
        char ** newargv;
        char * newbuf;
        int newargc = 52;
        int length;
        FILE *fp;

        newargv = (char**) malloc(newargc * sizeof(char *)); /* not freed */
        newargv[0] = argv[0];

        /* get file length via fseek & ftell */
        if ((fp = fopen(argv[2], "r")) == NULL)
        {
            fprintf(stderr, "failed to open configuration file\n");
            exit(1);
        }
        fseek(fp, 0, SEEK_END);
        length = ftell(fp);
        if (length <=0)
        {
           fprintf(stderr,"failed to determine length of configuration file\n");
           exit(1);
        }
        rewind(fp);

        newbuf = (char *) malloc(length+1);  /* dont free */
        i = fread(newbuf, 1, length, fp);
        if (i < 0)
        {
            fprintf(stderr, "Unable to read parameters from configuration "
                            "file\n");
            exit(1);
        }
        newbuf[i] = '\0';
        fclose(fp);

        newargv[0] = argv[0];
        newargc--;
        globus_l_gram_tokenize(newbuf, &newargv[1], &newargc);

        for (i=3; i<argc; i++)
            newargv[++newargc] = strdup(argv[i]);

        argv = newargv;
        argc = newargc + 1;
    }

    /*
     * Parse the command line arguments
     */
    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-save-logfile") == 0)
                 && (i + 1 < argc))
        {
            if (strcmp(argv[i+1], "always") == 0)
            {
                config->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ALWAYS;
            }
            else if(strcmp(argv[i+1], "on_error") == 0)
            {
                config->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR;
            }
            else if(strcmp(argv[i+1], "on-error") == 0)
            {
                config->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR;
            }
            i++;
        }
        else if(strcmp(argv[i], "-rsl") == 0)
        {
            if(i + 1 < argc)
            {
                *rsl = strdup(argv[++i]);
            }
            else
            {
                fprintf(stderr, "-rsl argument requires and rsl\n");
                exit(1);
            }
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            config->kerberos = GLOBUS_TRUE;
        }
        else if ((strcmp(argv[i], "-home") == 0) && (i + 1 < argc))
        {
            config->globus_location = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-target-globus-location") == 0)
                 && (i + 1 < argc))
        {
            config->target_globus_location = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-type") == 0) && (i + 1 < argc))
        {
            config->jobmanager_type = strdup(argv[++i]);
        }
        else if((strcmp(argv[i], "-history") == 0) && (i + 1 < argc))
        {
            config->job_history_dir = strdup(argv[++i]);
        }
        else if (strcmp(argv[i], "-cache-location") == 0)
        {
            config->cache_location = strdup(argv[++i]);
        }
        else if (strcmp(argv[i], "-scratch-dir-base") == 0)
        {
            config->scratch_dir_base = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-condor-arch") == 0) && (i + 1 < argc))
        {
            config->condor_arch = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-condor-os") == 0) && (i + 1 < argc))
        {
            config->condor_os = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-host") == 0)
                 && (i + 1 < argc))
        {
            config->globus_gatekeeper_host = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-port") == 0)
                 && (i + 1 < argc))
        {
            config->globus_gatekeeper_port = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-subject") == 0)
                 && (i + 1 < argc))
        {
            config->globus_gatekeeper_subject = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-host-manufacturer") == 0)
                 && (i + 1 < argc))
        {
            config->globus_host_manufacturer = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-host-cputype") == 0)
                 && (i + 1 < argc))
        {
            config->globus_host_cputype = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-host-osname") == 0)
                 && (i + 1 < argc))
        {
            config->globus_host_osname = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-host-osversion") == 0)
                 && (i + 1 < argc))
        {
            config->globus_host_osversion = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-tcp-port-range") == 0)
                 && (i + 1 < argc))
        {
            config->tcp_port_range = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-state-file-dir") == 0)
                 && (i + 1 < argc))
        {
            config->job_state_file_dir = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-x509-cert-dir") == 0)
                 && (i + 1 < argc))
        {
            config->x509_cert_dir = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-extra-envvars") == 0)
                 && (i + 1 < argc))
        {
            config->extra_envvars = strdup(argv[++i]);
        }
        else if ((strcasecmp(argv[i], "-seg-module" ) == 0)
                 && (i + 1 < argc))
        {
            config->seg_module = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-audit-directory") == 0) 
                && (i+1 < argc))
        {
            config->auditing_dir = strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-toolkit-version") == 0)
                && (i+1 < argc))
        {
            config->globus_version = strdup(argv[++i]);
        }
        else if (strcmp(argv[i], "-disable-streaming") == 0)
        {
            config->streaming_disabled = GLOBUS_TRUE;
        }
        else if (strcmp(argv[i], "-single") == 0)
        {
            config->single = GLOBUS_TRUE;
        }
        else if ((strcasecmp(argv[i], "-help" ) == 0) ||
                 (strcasecmp(argv[i], "--help") == 0))
        {
            fprintf(stderr,
                    "Usage: globus-gram-jobmanager\n"
                    "\n"
                    "Required Arguments:\n"
                    "\t-type jobmanager type, i.e. fork, lsf ...\n"
                    "\t-globus-host-manufacturer manufacturer\n"
                    "\t-globus-host-cputype cputype\n"
                    "\t-globus-host-osname osname\n"
                    "\t-globus-host-osversion osversion\n"
                    "\t-globus-gatekeeper-host host\n"
                    "\t-globus-gatekeeper-port port\n"
                    "\t-globus-gatekeeper-subject subject\n"
                    "\n"
                    "Non-required Arguments:\n"
                    "\t-home globus_location\n"
                    "\t-target-globus-location globus_location\n"
                    "\t-condor-arch arch, i.e. SUN4x\n"
                    "\t-condor-os os, i.e. SOLARIS26\n"
                    "\t-history job-history-directory\n" 
                    "\t-save-logfile [ always | on_error ]\n"
                    "\t-scratch-dir-base scratch-directory\n"
                    "\t-state-file-dir state-directory\n"
                    "\t-globus-tcp-port-range <min port #>,<max port #>\n"
                    "\t-x509-cert-dir DIRECTORY\n"
                    "\t-cache-location PATH\n"
                    "\t-k\n"
                    "\t-extra-envvars VAR1,VAR2,...\n"
                    "\t-seg-module SEG-MODULE\n"
                    "\t-audit-directory DIRECTORY\n"
                    "\t-globus-toolkit-version VERSION\n"
                    "\n"
                    "Note: if type=condor then\n"
                    "      -condor-os & -condor-arch are required.\n"
                    "\n");
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
            goto out;
        }
        else
        {
            fprintf(stderr, "Warning: Ignoring unknown argument %s\n\n",
                    argv[i]);
        }
    }

    /* Verify that required values are present */
    if(config->jobmanager_type == NULL)
    {
        fprintf(stderr,
                "JM: Jobmanager service misconfigured: missing -type option\n");

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
        goto out;
    }

    if(strcasecmp(config->jobmanager_type, "condor") == 0)
    {
        if(config->condor_arch == NULL)
        {
            fprintf(stderr,
                    "JMI: Condor_arch must be specified when "
                    "jobmanager type is condor\n");

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH;
            goto out;
        }
        if(config->condor_os == NULL)
        {
           fprintf(stderr,
                   "JMI: condor_os must be specified when "
                   "jobmanager type is condor\n");
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_OS;
            goto out;
        }
    }

    /* Now initialize values from our environment */
    config->home = strdup(getenv("HOME"));
    if (config->home == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }

    config->logname = strdup(getenv("LOGNAME"));
    if (config->home == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }

    if (config->globus_location == NULL)
    {
        rc = globus_location(&config->globus_location);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto out;
        }
    }
    if (config->target_globus_location == NULL)
    {
        config->target_globus_location = strdup(
                config->globus_location);
        if (config->target_globus_location == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto out;
        }
    }
    if (config->scratch_dir_base == NULL)
    {
        config->scratch_dir_base = strdup(
                config->home);
        if (config->scratch_dir_base == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto out;
        }
    }

    rc = globus_libc_gethostname(hostname, sizeof(hostname));
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto out;
    }

    config->hostname = strdup(hostname);
    if (config->hostname == GLOBUS_NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto out;
    }

    rc = globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto out;
    }

    rc = globus_gram_job_manager_gsi_get_subject(&config->subject);
    if (rc != GLOBUS_SUCCESS)
    {
        goto out;
    }


out:
    return rc;
}
/* globus_gram_job_manager_config_init() */

/**
 * Free all memory allocated when the globus_gram_job_manager_config_init() was called.
 *
 * @param config
 *     Configuration structure destroy.
 */
void
globus_gram_job_manager_config_destroy(
    globus_gram_job_manager_config_t *  config)
{
    if (config->globus_location)
    {
        free(config->globus_location);
    }
    if (config->target_globus_location)
    {
        free(config->target_globus_location);
    }
    if (config->jobmanager_type)
    {
        free(config->jobmanager_type);
    }
    if (config->job_history_dir)
    {
        free(config->job_history_dir);
    }
    if (config->cache_location)
    {
        free(config->cache_location);
    }
    if (config->scratch_dir_base)
    {
        free(config->scratch_dir_base);
    }
    if (config->condor_arch)
    {
        free(config->condor_arch);
    }
    if (config->condor_os)
    {
        free(config->condor_os);
    }
    if (config->globus_gatekeeper_host)
    {
        free(config->globus_gatekeeper_host);
    }
    if (config->globus_gatekeeper_port)
    {
        free(config->globus_gatekeeper_port);
    }
    if (config->globus_gatekeeper_subject)
    {
        free(config->globus_gatekeeper_subject);
    }
    if (config->globus_host_manufacturer)
    {
        free(config->globus_host_manufacturer);
    }
    if (config->globus_host_cputype)
    {
        free(config->globus_host_cputype);
    }
    if (config->globus_host_osname)
    {
        free(config->globus_host_osname);
    }
    if (config->globus_host_osversion)
    {
        free(config->globus_host_osversion);
    }
    if (config->tcp_port_range)
    {
        free(config->tcp_port_range);
    }
    if (config->job_state_file_dir)
    {
        free(config->job_state_file_dir);
    }
    if (config->x509_cert_dir)
    {
        free(config->x509_cert_dir);
    }
    if (config->extra_envvars)
    {
        free(config->extra_envvars);
    }
    if (config->seg_module)
    {
        free(config->seg_module);
    }
    if (config->auditing_dir)
    {
        free(config->auditing_dir);
    }
    if (config->globus_version)
    {
        free(config->globus_version);
    }
    if (config->subject)
    {
        free(config->subject);
    }
    if (config->home)
    {
        free(config->home);
    }
    if (config->logname)
    {
        free(config->logname);
    }
    if (config->hostname)
    {
        free(config->hostname);
    }
}
/* globus_gram_job_manager_config_destroy() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Split string into command-line arguments
 *
 * The @a command string is split into whitespace-delimited strings and adds
 * them to the @a args array. If the string begins with single quote or double
 * quote it will be combined with following strings until the closing quote is
 * found. At most *n-1 arguments can be parsed from the @a command string. *n
 * will be modified to contain the number of tokens in the @a args array when
 * this function returns.
 * 
 * @param command
 *     String to tokenize
 * @param args
 *     Pointer to array of strings of at most *n elements.
 * @param n
 *     In: maximum number of lements in @a args. Out: actual number of 
 *     elements in @a args.
 *
 * @retval 0
 *     Success
 * @retval -1
 *     Too many arguments
 */
static
int
globus_l_gram_tokenize(char * command, char ** args, int * n)
{
  int i, x;
  char * cp;
  char * cp2;
  char ** arg;
  char * tmp_str = NULL;

  arg = args;
  i = *n - 1;

  for (cp = strtok(command, " \t\n"); cp != 0; )
  {
      if ( cp[0] == '\'' && cp[strlen(cp) - 1] != '\'' )
      {
         cp2 = strtok(NULL, "'\n");
         tmp_str = malloc(sizeof(char *) * (strlen(cp) + strlen(cp2) + 2));
         sprintf(tmp_str, "%s %s", &cp[1], cp2);
      }
      else if ( cp[0] == '"' && cp[strlen(cp) - 1] != '"' )
      {
         cp2 = strtok(NULL, "\"\n");
         tmp_str = malloc(sizeof(char *) * (strlen(cp) + strlen(cp2) + 2));
         sprintf(tmp_str, "%s %s", &cp[1], cp2);
      }
      else
      {
         if (( cp[0] == '"' && cp[strlen(cp) - 1] == '"' ) ||
             ( cp[0] == '\'' && cp[strlen(cp) - 1] == '\'' ))
         {
             tmp_str = malloc(sizeof(char *) * strlen(cp));
             x = strlen(cp)-2;
             strncpy(tmp_str, &cp[1], x);
             tmp_str[x] = '\0';
         }
         else
         {
             tmp_str = cp;
         }
      }

      *arg = tmp_str;
      i--;
      if (i == 0)
          return(-1); /* too many args */
      arg++;
      cp = strtok(NULL, " \t\n");
  }

  *arg = (char *) 0;
  *n = *n - i - 1;
  return(0);

}
/* globus_l_gram_tokenize() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

