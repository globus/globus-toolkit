#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_job_manager_validation.h"

#define COMMAND "globus-gram-job-manager-print-validation" 

static char * globus_l_oneline_usage = 
    COMMAND " [-version] [-help] [-ldif] -type MANAGERTYPE";

static char * globus_l_long_usage =
    "Syntax: "COMMAND" [options] -type MANAGERTYPE\n"
    "        "COMMAND" -version\n" 
    "        "COMMAND" -help\n"
    "\n"
    "OPTIONS\n"
    "    -help                               Display help\n"
    "    -version                            Display version\n"
    "    -ldif | -l                          Print validation file in "
    "LDIF format\n"
    "    -type SCHEDULERTYPE                 Print RSL validation information"
    " for\n"
    "                                        the specified scheduler type\n";

enum 
{
    arg_ldif = 1,
    arg_type
};

static char *arg_ldif_names[] = { "-ldif", "-l", NULL };
static char *arg_type_names[] = { "-type", "-t", NULL };

globus_args_option_descriptor_t globus_l_args[] =
{ 
    { arg_ldif, arg_ldif_names, 0, NULL, NULL },
    { arg_type, arg_type_names, 1, NULL, NULL }
};

#define ARRAY_COUNT(x) (sizeof(x) / sizeof(x[0]))

int
main(int argc, char *argv[])
{
    int					rc;
    globus_list_t *			options_found;
    globus_list_t *			tmp;
    globus_gram_jobmanager_request_t *	request;
    globus_args_option_instance_t *	instance;
    globus_bool_t			ldif = GLOBUS_FALSE;
    globus_gram_job_manager_validation_record_t *
					record;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    rc = globus_args_scan(&argc, &argv, ARRAY_COUNT(globus_l_args),
	                  globus_l_args, COMMAND, VERSION,
	                  globus_l_oneline_usage, globus_l_long_usage,
		          &options_found, NULL);
    if(rc < 0)
    {
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
	    case arg_ldif:
		ldif = GLOBUS_TRUE;
		break;
	    case arg_type:
		request->jobmanager_type =
		    globus_libc_strdup(instance->values[0]);
		break;
	    default:
		fprintf(stderr, "Uknown option!");
		goto unknown_option;
	}
    }
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

    tmp = request->validation_records;
    while(!globus_list_empty(tmp))
    {
	record = globus_list_first(tmp);
	tmp = globus_list_rest(tmp);

	if(record->publishable)
	{
	    printf("%s\n", record->attribute);
	}
    }

validation_init_failed:
missing_required_parameter:
unknown_option:
    globus_gram_job_manager_request_destroy(request);
request_init_failed:
scan_args_failed:
    globus_module_deactivate_all();

    return rc;
}
/* main() */
