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

#include "globus_common.h"

#if HAVE_UTIME_H
#   include <utime.h>
#endif

#include <stdio.h>

#ifdef HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_common.h"
#include "globus_callout.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"
#include "globus_nexus.h"
#include "globus_duct_control.h"
#include "globus_gass_cache.h"
#include "globus_io.h"
#include "globus_gass_transfer.h"
#include "globus_ftp_client.h"
#include "globus_gram_jobmanager_callout_error.h"

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */


static int
globus_l_gram_tokenize(
    char *				command,
    char **				args,
    int *				n);

static
int
globus_l_jobmanager_fault_callback(
    void *				user_arg,
    int					fault_code);

static
int
globus_l_gram_job_manager_activate(void);

int
main(
    int 				argc,
    char **				argv)
{
    int					i;
    int					rc;
    int					length;
    FILE *				fp;
    struct stat				statbuf;
    globus_gram_jobmanager_request_t *  request;
    char *                              sleeptime_str;
    long                                sleeptime;
    int	                                debugging_without_client = 0;
    globus_reltime_t			delay;

    /*
     * Stdin and stdout point at socket to client
     * Make sure no buffering.
     * stderr may also, depending on the option in the grid-services
     */
    setbuf(stdout,NULL);

    /* if -conf is passed then get the arguments from the file
     * specified
     */
    if (argc > 2 && !strcmp(argv[1],"-conf"))
    {
        char ** newargv;
        char * newbuf;
        int newargc = 52;
        int  pfd;

        newargv = (char**) malloc(newargc * sizeof(char *)); /* not freeded */
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
        fclose(fp);

        pfd = open(argv[2],O_RDONLY);
        newbuf = (char *) malloc(length+1);  /* dont free */
        i = read(pfd, newbuf, length);
        if (i < 0)
        {
            fprintf(stderr, "Unable to read parameters from configuration "
                            "file\n");
            exit(1);
        }
        newbuf[i] = '\0';
        close(pfd);

        newargv[0] = argv[0];
        newargc--;
        globus_l_gram_tokenize(newbuf, &newargv[1], &newargc);

        for (i=3; i<argc; i++)
            newargv[++newargc] = globus_libc_strdup(argv[i]);

        argv = newargv;
        argc = newargc + 1;
    }

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-globus-tcp-port-range") == 0)
                 && (i + 1 < argc))
        {
            char * tmp_tcp_port_range;

            tmp_tcp_port_range = globus_libc_strdup(argv[++i]);
            globus_libc_setenv("GLOBUS_TCP_PORT_RANGE",
                               tmp_tcp_port_range,
                               GLOBUS_TRUE);
        }
    }

    rc = globus_l_gram_job_manager_activate();
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }

    globus_nexus_enable_fault_tolerance(
        globus_l_jobmanager_fault_callback,
        GLOBUS_NULL);

    if (globus_gram_job_manager_request_init(&request) != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
            "ERROR: globus_jobmanager_request_init() failed.\n");
        exit(1);
    }

    globus_mutex_lock(&request->mutex);

    globus_symboltable_init(&request->symbol_table,
                            globus_hashtable_string_hash,
                            globus_hashtable_string_keyeq);

    globus_symboltable_create_scope(&request->symbol_table);
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
		request->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ALWAYS;
            }
            else if(strcmp(argv[i+1], "on_error") == 0)
            {
		request->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR;
            }
            else if(strcmp(argv[i+1], "on-error") == 0)
            {
		request->logfile_flag = GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR;
            }
            i++;
        }
	else if(strcmp(argv[i], "-rsl") == 0)
	{
	    if(i + 1 < argc)
	    {
		request->rsl_spec = globus_libc_strdup(argv[++i]);
		debugging_without_client = 1;
	    }
	    else
	    {
		fprintf(stderr, "-rsl argument requires and rsl\n");
		exit(1);
	    }
	}
        else if (strcmp(argv[i], "-k") == 0)
        {
            request->kerberos = GLOBUS_TRUE;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                 && (i + 1 < argc))
        {
            request->globus_location = globus_libc_strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-type") == 0)
                 && (i + 1 < argc))
        {
            request->jobmanager_type = globus_libc_strdup(argv[++i]);
        }
	else if((strcmp(argv[i], "-job-reporting-dir") == 0)
		&& (i + 1 < argc))
	{
	    request->job_reporting_dir = globus_libc_strdup(argv[++i]);
	}
        else if((strcmp(argv[i], "-history") == 0)
                && (i + 1 < argc))
        {
            request->job_history_dir = globus_libc_strdup(argv[++i]);
        }
        else if (strcmp(argv[i], "-publish-jobs") == 0)
        {
            request->publish_jobs = GLOBUS_TRUE;
        }
        else if (strcmp(argv[i], "-publish-users") == 0)
        {
            /* NOP */ ;
        }
	else if (strcmp(argv[i], "-cache-location") == 0)
	{
	    request->cache_location = globus_libc_strdup(argv[++i]);
	}
	else if (strcmp(argv[i], "-scratch-dir-base") == 0)
	{
	    request->scratch_dir_base = globus_libc_strdup(argv[++i]);
	}
        else if ((strcmp(argv[i], "-condor-arch") == 0)
                 && (i + 1 < argc))
        {
            request->condor_arch = globus_libc_strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-condor-os") == 0)
                 && (i + 1 < argc))
        {
            request->condor_os = globus_libc_strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-org-dn") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_ORG_DN",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-host") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_HOST",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-port") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_PORT",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-subject") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_SUBJECT",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-rdn") == 0)
                 && (i + 1 < argc))
        {
            request->rdn = globus_libc_strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-globus-host-dn") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_HOST_DN",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-host-manufacturer") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_HOST_MANUFACTURER",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-host-cputype") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_HOST_CPUTYPE",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-host-osname") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_HOST_OSNAME",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-host-osversion") == 0)
                 && (i + 1 < argc))
        {
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_HOST_OSVERSION",
                                (void *) globus_libc_strdup(argv[++i]));
        }
        else if ((strcmp(argv[i], "-globus-tcp-port-range") == 0)
                 && (i + 1 < argc))
        {
            request->tcp_port_range = globus_libc_strdup(argv[++i]);
        }
        else if ((strcmp(argv[i], "-machine-type") == 0)
                 && (i + 1 < argc))
        {
	    i++;  /* ignore */
        }
        else if ((strcmp(argv[i], "-state-file-dir") == 0)
                 && (i + 1 < argc))
        {
	    request->job_state_file_dir = globus_libc_strdup(argv[++i]);
            globus_libc_setenv("GLOBUS_SPOOL_DIR",
                               request->job_state_file_dir,
                               GLOBUS_TRUE);

        }
        else if ((strcmp(argv[i], "-x509-cert-dir") == 0)
                 && (i + 1 < argc))
	{
	    request->x509_cert_dir = globus_libc_strdup(argv[++i]);
	}
        else if ((strcmp(argv[i], "-extra-envvars") == 0)
                 && (i + 1 < argc))
        {
            request->extra_envvars = globus_libc_strdup(argv[++i]);
        }
        else if ((strcasecmp(argv[i], "-seg-module" ) == 0)
                 && (i + 1 < argc))
        {
            request->seg_module = argv[++i];
        }
        else if ((strcasecmp(argv[i], "-help" ) == 0) ||
                 (strcasecmp(argv[i], "--help") == 0))
        {
            fprintf(stderr,
                    "Usage: globus-gram-jobmanager\n"
                    "\n"
                    "Required Arguments:\n"
                    "\t-type jobmanager type, i.e. fork, lsf ...\n"
                    "\t-rdn relative distinguished name\n"
                    "\t-globus-org-dn organization's domain name\n"
                    "\t-globus-host-dn host domain name\n"
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
                    "\t-condor-arch arch, i.e. SUN4x\n"
                    "\t-condor-os os, i.e. SOLARIS26\n"
                    "\t-history job-history-directory\n" 
                    "\t-publish-jobs\n"
                    "\t-publish-users\n"
                    "\t-save-logfile [ always | on_error ]\n"
		    "\t-scratch-dir-base scratch-directory\n"
		    "\t-state-file-dir state-directory\n"
                    "\t-globus-tcp-port-range <min port #>,<max port #>\n"
		    "\t-x509-cert-dir DIRECTORY\n"
		    "\t-job-reporting-dir DIRECTORY\n"
		    "\t-cache-location PATH\n"
		    "\t-k\n"
		    "\t-globus-org-dn DN\n"
		    "\t-machine-type TYPE\n"
                    "\t-extra-envvars VAR1,VAR2,...\n"
                    "\t-seg-module SEG-MODULE\n"
                    "\n"
                    "Note: if type=condor then\n"
                    "      -condor-os & -condor-arch are required.\n"
                    "\n");
	    if(globus_libc_getenv("X509_USER_PROXY"))
	    {
		remove(globus_libc_getenv("X509_USER_PROXY"));
	    }
            exit(1);
        }
        else
        {
            fprintf(stderr, "Warning: Ignoring unknown argument %s\n\n",
                    argv[i]);
        }
    }
    if ((sleeptime_str = globus_libc_getenv("GLOBUS_JOB_MANAGER_SLEEP")))
    {
	sleeptime = atoi(sleeptime_str);
	globus_libc_usleep(sleeptime * 1000 * 1000);
    }

    if(request->globus_location != NULL)
    {
        globus_libc_setenv("GLOBUS_LOCATION",
                           request->globus_location,
                           GLOBUS_TRUE);
    }
    GlobusTimeReltimeSet(delay, 0, 0);

    globus_callback_register_oneshot(
	    NULL,
	    &delay,
	    globus_gram_job_manager_state_machine_callback,
	    request);

    while(request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_DONE &&
	  request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE && 
	  request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
    {
	globus_cond_wait(&request->cond, &request->mutex);
    }

    /*
     * If we ran without a client, display final state and error if applicable
     */
    if(debugging_without_client)
    {
	fprintf(stderr,
		"Final Job Status: %d%s%s%s\n",
		request->status,
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		? " (failed because " : "",
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		    ? globus_gram_protocol_error_string(request->failure_code)
		    : "",
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		    ? ")" : "");
    }
    else if((!request->relocated_proxy) &&
	    globus_gram_job_manager_gsi_used(request) &&
	    request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_DONE &&
	    globus_libc_getenv("X509_USER_PROXY"))
    {
	remove(globus_libc_getenv("X509_USER_PROXY"));
    }
    globus_mutex_unlock(&request->mutex);
    rc = globus_module_deactivate_all();
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "deactivation failed with rc=%d\n",
		rc);
	exit(1);
    }

    globus_gram_job_manager_request_log(
	    request,
	    "JM: exiting globus_gram_job_manager.\n");

    switch(request->logfile_flag)
    {
      case GLOBUS_GRAM_JOB_MANAGER_SAVE_ALWAYS:
	  break;
      case GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR:
	if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE
	   && !request->dry_run)
	{
	    break;
	}
	/* FALLSTHROUGH */
      case GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE:
	if (strcmp(request->jobmanager_logfile, "/dev/null") != 0)
	{
	    /*
	     * Check to see if the jm log file exists.  If so, then
	     * delete it.
	     */
	    if (stat(request->jobmanager_logfile, &statbuf) == 0)
	    {
		if (remove(request->jobmanager_logfile) != 0)
		{
		    fprintf(stderr,
			    "failed to remove job manager log file = %s\n",
			    request->jobmanager_logfile);
		}
	    }
	}
    }

    return(0);
}
/* main() */

/******************************************************************************
Function:       globus_l_gram_tokenize()
Description:
Parameters:
Returns:
******************************************************************************/
static int
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

} /* globus_l_gram_tokenize() */

/******************************************************************************
Function: globus_l_jobmanager_fault_callback()

Description:

Parameters:

Returns:
******************************************************************************/
static
int
globus_l_jobmanager_fault_callback(
    void *				user_arg,
    int					fault_code)
{
    /*
    if(graml_log_fp)
    {
	globus_gram_job_manager_request_log(
	    graml_log_fp,
	    "jobmanager received nexus fault code %d\n",
	    fault_code);
    }
    */

    return 0;
} /* globus_l_jobmanager_fault_callback() */

static
int
globus_l_gram_job_manager_activate(void)
{
    int rc;

    /* Initialize modules that I use */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "common module activation failed with rc=%d\n", rc);
	goto common_failed;
    }
    rc = globus_module_activate(GLOBUS_CALLOUT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "callout module activation failed with rc=%d\n", rc);
	goto callout_failed;
    }
    rc = globus_module_activate(GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "jobmanager callout error module activation failed with rc=%d\n", rc);
	goto jobmanager_callout_error_failed;
    }
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "gssapi activation failed with rc=%d\n", rc);
        goto gss_assist_failed;
    }

    rc = globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "gsi sysconfig activation failed with rc=%d\n", rc);
        goto gsi_sysconfig_failed;
    }
    
    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "io activation failed with rc=%d\n", rc);
	goto io_failed;
    }

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gram protocol activation failed with rc=%d\n", rc);
	goto gram_protocol_failed;
    }

    rc = globus_module_activate(GLOBUS_GASS_CACHE_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_cache activation failed with rc=%d\n", rc);
	goto gass_cache_failed;
    }

    rc = globus_module_activate(GLOBUS_DUCT_CONTROL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s activation failed with rc=%d\n",
		GLOBUS_DUCT_CONTROL_MODULE->module_name, rc);
	goto duct_control_failed;
    }
    rc = globus_module_activate(GLOBUS_NEXUS_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "nexus module activation failed with rc=%d\n", rc);
	goto nexus_failed;
    }

    rc = globus_module_activate(GLOBUS_GASS_TRANSFER_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass transfer module activation failed with rc=%d\n", rc);
	goto gass_transfer_failed;
    }

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "ftp client module activation failed with rc=%d\n", rc);
	goto ftp_client_failed;
    }
    
ftp_client_failed:
gass_transfer_failed:
nexus_failed:
duct_control_failed:
gass_cache_failed:
gram_protocol_failed:
io_failed:
gss_assist_failed:
gsi_sysconfig_failed:
callout_failed:
jobmanager_callout_error_failed:
    if(rc)
    {
	globus_module_deactivate_all();
    }
common_failed:
    return rc;
}
/* globus_l_gram_job_manager_activate() */

