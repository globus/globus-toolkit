#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_rsl.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static globus_bool_t globus_l_gram_job_manager_verbose_debugging = 0;

typedef struct
{
    char *				attribute;
    char *				description;
    globus_bool_t			required;
    char *				default_value;
    char *				enumerated_values;
}
globus_l_gram_job_manager_validation_record_t;

static
int
globus_l_gram_job_manager_read_validation_file(
    const char *			validation_filename,
    globus_list_t **			validation_records);

static
int
globus_l_gram_job_manager_attribute_match(
    void *				datum,
    void *				args);

static
int
globus_l_gram_job_manager_check_rsl_attributes(
    globus_rsl_t *			rsl,
    globus_list_t *			validation_records);

static
globus_bool_t
globus_l_gram_job_manager_attribute_exists(
    globus_list_t *			attributes,
    char *				attribute_name);

static
int
globus_l_gram_job_manager_insert_default_rsl(
    globus_rsl_t *			rsl,
    globus_list_t *			validation_records);

int
globus_gram_job_manager_validate_rsl(
    globus_gram_jobmanager_request_t *	request,
    const char *			validation_filename,
    const char *			scheduler_validation_filename)
{
    globus_list_t *			validation_records = GLOBUS_NULL;
    globus_list_t *			tmp;
    globus_l_gram_job_manager_validation_record_t *
					record;
    int					rc;

    /* First validation: RSL is a boolean "&" */
    if(!globus_rsl_is_boolean_and(request->rsl))
    {
	return GLOBUS_FAILURE;
    }

    /* Read in validation files. Do the generic job manager one first,
     * as the scheduler-specific one overrides it.
     */
    rc = globus_l_gram_job_manager_read_validation_file(
	    validation_filename,
	    &validation_records);

    if(scheduler_validation_filename)
    {
	rc = globus_l_gram_job_manager_read_validation_file(
		validation_filename,
		&validation_records);

	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
    }
    if(rc != GLOBUS_SUCCESS)
    {
	goto free_validation_records;
    }

    tmp = validation_records;

    if(globus_l_gram_job_manager_verbose_debugging)
    {
	while(!globus_list_empty(tmp))
	{
	    record = globus_list_first(tmp);
	    tmp = globus_list_rest(tmp);

	    fprintf(
		    stderr,
		    "\n"
		    "attribute = '%s'\n"
		    "description = '%s'\n"
		    "required = '%s'\n"
		    "default_values = '%s'\n"
		    "enumerated_values = '%s'\n",
		    record->attribute,
		    record->description ? record->description : "",
		    record->required ? "yes" : "no",
		    record->default_value ? record->default_value : "",
		    record->enumerated_values ? record->enumerated_values : "");
	}
    }

    /*
     * Make sure all of the attributes match defined RSL validation records.
     */
    rc = globus_l_gram_job_manager_check_rsl_attributes(
	    request->rsl,
	    validation_records);

    if(rc != GLOBUS_SUCCESS)
    {
	goto free_validation_records;
    }
    /*
     * Insert default RSL values where appropriate, make sure everything
     * which is required is defined.
     */
    rc = globus_l_gram_job_manager_insert_default_rsl(
	    request->rsl,
	    validation_records);

free_validation_records:
    /*globus_l_gram_job_manager_free_validation_records(validation_records);*/

    return rc;
}

static
int
globus_l_gram_job_manager_read_validation_file(
    const char *			validation_filename,
    globus_list_t **			validation_records)
{
    FILE *				fp;
    int					length;
    globus_l_gram_job_manager_validation_record_t *
					tmp = NULL;
    char *				token_start;
    char *				token_end;
    char *				attribute;
    char *				value;
    globus_list_t *			node;
    char *				data;
    int					i;
    int					j;

    fp = fopen(validation_filename, "r");

    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    token_start = data = globus_libc_malloc((size_t) length + 1);

    fread(token_start, 1, (size_t) length, fp);
    token_start[(size_t) length] = '\0';

    while(*token_start)
    {
	while(*token_start && isspace(*token_start))
	{
	    token_start++;
	}
	token_end = strchr(token_start, ':');

	if(!token_end)
	{
	    break;
	}
	attribute = globus_libc_malloc(token_end - token_start + 1);
	memcpy(attribute, token_start, token_end - token_start);
	attribute[token_end-token_start] = '\0';
	token_start = token_end + 1; /* skip : */

	while(*token_start && isspace(*token_start))
	{
	    token_start++;
	}
	if(*token_start == '"')
	{
	    token_start++;

	    token_end = token_start;

	    do
	    {
		token_end++;
		token_end = strchr(token_end, '"');
	    }
	    while((*token_end) && *(token_end-1) == '\\');

	    value = globus_libc_malloc(token_end - token_start + 1);
	    for(i = 0, j = 0; token_start + i < token_end; i++)
	    {
		if(token_start[i] == '\\' && token_start[i+1] == '"')
		{
		    value[j++] = token_start[++i];
		}
		else if(!(isspace(token_start[i]) && isspace(token_start[i+1])))
		{
		    value[j++] = token_start[i];
		}
	    }
	    value[j] = '\0';
	    token_end++;

	    while(*token_end && *token_end != '\n')
	    {
		token_end++;
	    }
	    if(*token_end == '\n')
	    {
		token_end++;
	    }
	}
	else
	{
	    token_end = strchr(token_start, '\n');
	    if(token_end != NULL)
	    {
		value = globus_libc_malloc(token_end - token_start + 1);
		memcpy(value, token_start, token_end - token_start);
		value[token_end - token_start] = '\0';
		token_end++;
	    }
	    else
	    {
		value = globus_libc_strdup(token_start);
		token_end = token_start + strlen(token_start);
	    }
	}
	if(tmp == GLOBUS_NULL)
	{
	    tmp = globus_libc_calloc(1, 
		    sizeof(globus_l_gram_job_manager_validation_record_t));
	}
	/* Compare token names against known attributes */
	if(strcasecmp(attribute, "attribute") == 0)
	{
	    tmp->attribute = value;
	}
	else if(strcasecmp(attribute, "description") == 0)
	{
	    tmp->description = value;
	}
	else if(strcasecmp(attribute, "required") == 0)
	{
	    if(strcasecmp(value, "yes") == 0 ||
	       strcasecmp(value, "true") == 0)
	    {
		tmp->required = GLOBUS_TRUE;
	    }
	    else
	    {
		tmp->required = GLOBUS_FALSE;
	    }
	    globus_libc_free(value);
	    value = GLOBUS_NULL;
	}
	else if(strcasecmp(attribute, "default") == 0)
	{
	    tmp->default_value = value;
	}
	else if(strcasecmp(attribute, "values") == 0)
	{
	    tmp->enumerated_values = value;
	}
	else
	{
	    /* unknown attribute.... ignore */
	    globus_libc_free(value);
	    value = GLOBUS_NULL;
	}
	globus_libc_free(attribute);
	attribute = GLOBUS_NULL;

	token_start = token_end;

	/* Eat whitespace on end of record entry */
	while(*token_start && isspace(*token_start))
	{
	    if(*token_start == '\n')
	    {
		break;
	    }
	    else
	    {
		token_start++;
	    }
	}
	/* If record entry is followed by blank line or eof, then
	 * store entry in list
	 */
	if(*token_start == '\0' || *token_start == '\n')
	{
	    node = globus_list_search_pred(
		    *validation_records, 
		    globus_l_gram_job_manager_attribute_match,
		    tmp->attribute);
	    if(node)
	    {
		/*
		 * Validation record already exists, replace it with new
		 * values
		 */
		globus_list_remove(validation_records, node);
	    }

	    /* Insert into validation record list */
	    globus_list_insert(validation_records, tmp);
	    tmp = GLOBUS_NULL;
	}
    }

    globus_libc_free(data);
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_read_validation_file() */

static
int
globus_l_gram_job_manager_attribute_match(
    void *				datum,
    void *				args)
{
    globus_l_gram_job_manager_validation_record_t *
					tmp = datum;

    return (strcmp(tmp->attribute, args) == 0);
}
/* globus_l_gram_job_manager_attribute_match() */

/**
 * Check that RSL attributes are match information in the validation file.
 */
static
int
globus_l_gram_job_manager_check_rsl_attributes(
    globus_rsl_t *			rsl,
    globus_list_t *			validation_records)
{
    globus_list_t *			operands;
    globus_list_t *			node;
    globus_rsl_t *			relation;
    char *				attribute;
    char *				value_str;
    globus_l_gram_job_manager_validation_record_t *
					record;
    globus_rsl_value_t *		value;

    operands = globus_rsl_boolean_get_operand_list(rsl);

    /* Check to make sure that every attribute is recognized by this
     * job manager.
     */
    while(!globus_list_empty(operands))
    {
	relation = globus_list_first(operands);
	operands = globus_list_rest(operands);

	if(!globus_rsl_is_relation_eq(relation))
	{
	    if(globus_l_gram_job_manager_verbose_debugging)
	    {
		fprintf(stderr,
			"RSL contains something besides an \"=\" relation\n");
	    }
	    return GLOBUS_FAILURE;
	}
	attribute = globus_rsl_relation_get_attribute(relation);

	node = globus_list_search_pred(
		validation_records,
		globus_l_gram_job_manager_attribute_match,
		attribute);

	if(!node)
	{
	    if(globus_l_gram_job_manager_verbose_debugging)
	    {
		fprintf(stderr,
			"RSL attribute '%s' is not in the validation file!\n",
			attribute);
	    }
	    return GLOBUS_FAILURE;
	}

	record = globus_list_first(node);

	/* Check enumerated values if applicable */
	if(record->enumerated_values)
	{
	    value = globus_rsl_relation_get_single_value(relation);

	    if(!value)
	    {
		return GLOBUS_FAILURE;
	    }
	    value_str = globus_rsl_value_literal_get_string(value);
	    if(!value_str)
	    {
		return GLOBUS_FAILURE;
	    }
	    if(strstr(record->enumerated_values, value_str) == GLOBUS_NULL)
	    {
		if(globus_l_gram_job_manager_verbose_debugging)
		{
		    fprintf(stderr,
			    "RSL attribute %s's value is not "
			    "in the enumerated set\n",
			    attribute);
		}
		return GLOBUS_FAILURE;
	    }
	}
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_check_rsl_attributes() */

/**
 * Add default values to RSL.
 */
static
int
globus_l_gram_job_manager_insert_default_rsl(
    globus_rsl_t *			rsl,
    globus_list_t *			validation_records)
{
    globus_l_gram_job_manager_validation_record_t *
					record;
    globus_list_t **			attributes;
    globus_rsl_t *			new_relation;
    char *				new_relation_str;

    attributes = globus_rsl_boolean_get_operand_list_ref(rsl);

    while(!globus_list_empty(validation_records))
    {
	record = globus_list_first(validation_records);
	validation_records = globus_list_rest(validation_records);

	if(record->default_value)
	{
	    if(!globus_l_gram_job_manager_attribute_exists(
			*attributes,
			record->attribute))
	    {
		new_relation_str = globus_libc_malloc(
			strlen(record->attribute) +
			strlen(record->default_value) + 
			strlen("%s = %s"));

		sprintf(new_relation_str,
			"%s = %s",
			record->attribute,
			record->default_value);

		if(globus_l_gram_job_manager_verbose_debugging)
		{
		    fprintf(stderr,
			    "Nope, adding default RSL of %s\n",
			    new_relation_str);
		}

		new_relation = globus_rsl_parse(new_relation_str);

		globus_list_insert(attributes, new_relation);

		globus_libc_free(new_relation_str);
	    }
	    else
	    {
		if(globus_l_gram_job_manager_verbose_debugging)
		{
		    fprintf(stderr, "Yes\n");
		}
	    }
	}
	if(record->required)
	{
	    if(globus_l_gram_job_manager_verbose_debugging)
	    {
		fprintf(stderr,
			"Checking whether required attribute %s is in "
			"user RSL spec...",
			record->attribute);
	    }
	    if(!globus_l_gram_job_manager_attribute_exists(
			*attributes,
			record->attribute))
	    {
		if(globus_l_gram_job_manager_verbose_debugging)
		{
		    fprintf(stderr, "No, invalid RSL\n");
		}

		return GLOBUS_FAILURE;
	    }
	    else
	    {
		if(globus_l_gram_job_manager_verbose_debugging)
		{
		    fprintf(stderr, "Yes, valid RSL\n");
		}
	    }
	}
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_insert_default_rsl() */

static
globus_bool_t
globus_l_gram_job_manager_attribute_exists(
    globus_list_t *			attributes,
    char *				attribute_name)
{
    char *				tmp;
    globus_rsl_t *			relation;

    while(!globus_list_empty(attributes))
    {
	relation = globus_list_first(attributes);
	attributes = globus_list_rest(attributes);
	tmp = globus_rsl_relation_get_attribute(relation);

	if(strcmp(tmp, attribute_name) == 0)
	{
	    return GLOBUS_TRUE;
	}
    }
    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_attribute_exists() */
