#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_job_manager_validation.h"

#define COMMAND "globus-gram-rsl-reporter" 
#define CLASS "Mds-Service-Gram-Rsl-Attribute"

static char * globus_l_oneline_usage = 
    COMMAND " [-version] [-help] -type MANAGERTYPE";

static char * globus_l_long_usage =
    "Syntax: "COMMAND" [options] -type MANAGERTYPE -dn \"DN\"\n"
    "        "COMMAND" -version\n" 
    "        "COMMAND" -help\n"
    "\n"
    "OPTIONS\n"
    "    -help                               Display help\n"
    "    -version                            Display version\n"
    "    -type SCHEDULERTYPE                 Print RSL validation information"
    "	 -dn DN				     Use this for the DN"
    "    -gl GLOBUS_LOCATION		     Define the globus location"
    " for\n"
    "                                        the specified scheduler type\n";

enum 
{
    arg_dn = 1,
    arg_type,
    arg_gl
};

static char *arg_dn_names[] = { "-dn", "-d", NULL};
static char *arg_type_names[] = { "-type", "-t", NULL};
static char *arg_gl_names[] = {"-gl", "-g", NULL};

globus_args_option_descriptor_t globus_l_args[] =
{ 
    { arg_dn, arg_dn_names, 1, NULL, NULL },
    { arg_type, arg_type_names, 1, NULL, NULL },
    { arg_gl, arg_gl_names, 1, NULL, NULL},
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
    char *				dn = NULL;
    globus_gram_job_manager_validation_record_t *
					record;
    char				*attribute;
    char				*gl = NULL;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    rc = globus_args_scan(&argc, &argv, ARRAY_COUNT(globus_l_args),
	                  globus_l_args, COMMAND, VERSION,
	                  globus_l_oneline_usage, globus_l_long_usage,
		          &options_found, NULL);

    rc = globus_gram_job_manager_request_init(&request);
    if(rc != GLOBUS_SUCCESS)
    {
	goto request_init_failed;
    }

    if(rc < 0)
    {
	goto scan_args_failed;
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

    printf("dn: Mds-Job-Attribute-name=All Attributes,%s\n", dn);
    printf("objectclass: MdsJobAttributes\n"\
	    "objectclass: MdsJobAttribute\n"\
	    "Mds-Job-Attribute-name: All Attributes\n\n");

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
		printf("\n");
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
