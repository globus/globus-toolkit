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

#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_job_manager_validation.h"
#include "version.h"

#include <string.h>

#define COMMAND "globus-gram-rsl-reporter" 
#define CLASS "Mds-Service-Gram-Rsl-Attribute"
#define MY_MAX_GENTIME_LEN 16

static char * globus_l_oneline_usage = 
    COMMAND " [-version] [-help] -type MANAGERTYPE";

static char * globus_l_long_usage =
    "Syntax: "COMMAND" [options] -type MANAGERTYPE -dn \"DN\"\n"
    "        "COMMAND" -version\n" 
    "        "COMMAND" -help\n"
    "\n"
    "OPTIONS\n"
    "    -help                     Display help\n"
    "    -version                  Display version\n"
    "    -type SCHEDULERTYPE       Print RSL validation information\n"
    "    -dn DN                    Use this for the DN\n"
    "    -keep-to-seconds N        Number of seconds the objects are valid\n"
    "                              the default is 28800 (8 hours)\n"
    "    -gl GLOBUS_LOCATION       Define the globus location for\n"
    "                              the specified scheduler type\n";

enum 
{
    arg_dn = 1,
    arg_type,
    arg_gl,
    arg_keep_to_seconds
};

static char *arg_dn_names[] = { "-dn", "-d", NULL};
static char *arg_type_names[] = { "-type", "-t", NULL};
static char *arg_gl_names[] = {"-gl", "-g", NULL};
static char *arg_keep_to_seconds_names[] = {"-keep-to-seconds", "-k", NULL};

globus_args_option_descriptor_t globus_l_args[] =
{ 
    { arg_dn, arg_dn_names, 1, NULL, NULL },
    { arg_type, arg_type_names, 1, NULL, NULL },
    { arg_gl, arg_gl_names, 1, NULL, NULL},
    { arg_keep_to_seconds, arg_keep_to_seconds_names, 1, NULL, NULL},
};

static int
globus_l_gram_generalized_time (char * buffer,
                         int    max_len,
                         time_t current_utc_sec,
                         int    offset_seconds);

#define ARRAY_COUNT(x) (sizeof(x) / sizeof(x[0]))

/******************************************************************************
Function:       globus_l_gram_generalized_time()
Description:
Parameters:
Returns:
******************************************************************************/
/* this function leaves off the suffix "Z" because some buggy
 * strftime() functions seem to misinterpret it as an escape */
static int
globus_l_gram_generalized_time (char * buffer,
                                int    max_len,
                                time_t current_utc_sec,
                                int    offset_seconds)
{
  struct tm * component_time;
  time_t utc_seconds;

  utc_seconds = current_utc_sec + offset_seconds;

  component_time = gmtime (&utc_seconds);

  return strftime (buffer, max_len, "%Y%m%d%H%M.%S", component_time);
}



int
main(int argc, char *argv[])
{
    int					rc;
    globus_list_t *			options_found;
    globus_list_t *			tmp;
    globus_gram_jobmanager_request_t *	request;
    globus_args_option_instance_t *	instance;
    char *				dn = NULL;
    globus_gram_job_manager_validation_record_t *
					record;
    char				*attribute;
    char				*gl = NULL;
    time_t                              current_utc_sec;
    int                                 keep_to_seconds=28800;
    char                                valid_from[MY_MAX_GENTIME_LEN];
    char                                valid_to[MY_MAX_GENTIME_LEN];
    char                                keep_to[MY_MAX_GENTIME_LEN];

    globus_module_activate(GLOBUS_COMMON_MODULE);
    rc = globus_args_scan(&argc, &argv, ARRAY_COUNT(globus_l_args),
	                  globus_l_args, COMMAND, &local_version,
	                  globus_l_oneline_usage, globus_l_long_usage,
		          &options_found, NULL);

    if(rc < 0)
    {
        rc = (rc == GLOBUS_FAILURE) ? 1 : 0;
	goto scan_args_failed;
    }
    
    rc = globus_gram_job_manager_request_init(&request);
    if(rc != GLOBUS_SUCCESS)
    {
	goto request_init_failed;
    }
    
    tmp = options_found;
    while(!globus_list_empty(tmp))
    {
	instance = globus_list_first(tmp);
	tmp = globus_list_rest(tmp);

	switch(instance->id_number)
	{
	    case arg_dn:
		dn = globus_libc_strdup(instance->values[0]);
		break;
	    case arg_type:
		request->jobmanager_type =
		    globus_libc_strdup(instance->values[0]);
		break;
	    case arg_gl:
	        gl = globus_libc_strdup(instance->values[0]);
	        break;
	    case arg_keep_to_seconds:
	        keep_to_seconds = atoi(instance->values[0]);
                if (keep_to_seconds < 1)
                {
		    fprintf(stderr, "\nError:  Invalid -keep-to-seconds!  Must be > 0\n\n");
		    goto invalid_keepto;
                }
	        break;
	    default:
		fprintf(stderr, "Uknown option!");
		goto unknown_option;
	}
    }

    if (gl == NULL)
        goto scan_args_failed;

    globus_libc_setenv("GLOBUS_LOCATION", gl, GLOBUS_TRUE);

    if(!request->jobmanager_type)
    {
	rc = GLOBUS_FAILURE;
	goto missing_required_parameter;
    }
    rc = globus_gram_job_manager_validation_init(request);
    if(rc != GLOBUS_SUCCESS)
    {
	goto validation_init_failed;
    }

    /* get the valid_from and valid_to timestamps */
    valid_from[0] = '\0';
    current_utc_sec = time (NULL);
    globus_l_gram_generalized_time (valid_from,
                   MY_MAX_GENTIME_LEN,
                   current_utc_sec,
                   0);
    globus_l_gram_generalized_time (valid_to,
                   MY_MAX_GENTIME_LEN,
                   current_utc_sec,
                   keep_to_seconds);
    strcpy(keep_to, valid_to);
    
    printf("dn: Mds-Job-Attribute-name=All Attributes,%s\n", dn);
    printf("objectclass: Mds\n");
    printf("objectclass: MdsJobAttributes\n"\
	    "objectclass: MdsJobAttribute\n"\
	    "Mds-Job-Attribute-name: All Attributes\n");
    if (valid_from)
    {
        printf("Mds-validfrom: %sZ\n", valid_from);
        printf("Mds-validto: %sZ\n", valid_to);
        printf("Mds-keepto: %sZ\n", keep_to);
    }
    printf("\n");

    tmp = request->validation_records;
    while(!globus_list_empty(tmp))
    {
	record = globus_list_first(tmp);
	tmp = globus_list_rest(tmp);

	if(record->publishable)
	{
		assert(record->attribute);
		attribute = record->attribute;
		printf("dn: Mds-Job-Attribute-Name=%s, "\
			"Mds-Job-Attribute-name=All Attributes, %s\n", 
			attribute, dn);
                printf("objectclass: Mds\n");
		printf("objectclass: MdsJobAttribute\n");
		printf("objectclass: MdsJobAttributes\n");
		printf("Mds-Job-Attribute-Name: %s\n", attribute);
		if (record->default_value)
			printf("default-value: %s\n", record->default_value);
		if (record->enumerated_values)
			printf("enumerated-values: %s\n", record->enumerated_values);
		if (record->required_when)
			printf("required-when: %d\n", record->required_when);
		if (record->default_when)
			printf("default-when: %d\n", record->default_when);
		if (record->valid_when)
			printf("valid-when: %d\n", record->valid_when);
                if (valid_from)
                {
                    printf("Mds-validfrom: %sZ\n", valid_from);
                    printf("Mds-validto: %sZ\n", valid_to);
                    printf("Mds-keepto: %sZ\n", keep_to);
                }
		printf("\n");
	}
    }

validation_init_failed:
missing_required_parameter:
unknown_option:
invalid_keepto:
    globus_gram_job_manager_request_destroy(request);
request_init_failed:
scan_args_failed:
    globus_module_deactivate_all();

    return rc;
}
/* main() */
