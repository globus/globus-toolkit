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
 * @file globus_gram_job_manager_rsl.c Job Manager RSL Manipulations
 */
#include "globus_gram_job_manager.h"
#include "globus_rsl_assist.h"

#include <string.h>

enum
{
    GRAM_JOB_MANAGER_COMMIT_TIMEOUT=60
};

/* Module Specific Prototypes */
static
int
globus_l_gram_job_manager_rsl_match(
    void *				datum,
    void *				arg);

#endif

/**
 * Merge two sets of RSL relations.
 *
 * Create a new RSL consisting of the merging of the base_rsl and override_rsl.
 * The result after completion is one RSL containing all of the relations
 * from the base_rsl and the override_rsl with any conflicting definitions
 * resolved by the override_rsl winning. The base_rsl and override_rsl
 * are unmodified in this process.
 */
globus_rsl_t *
globus_gram_job_manager_rsl_merge(
    globus_rsl_t *			base_rsl,
    globus_rsl_t *			override_rsl)
{
    globus_rsl_t *			tmp;
    globus_list_t **			base_relations;
    globus_list_t *			override_relations;
    globus_rsl_t *			result;
    char *				attribute;
    globus_list_t *			node;

    globus_assert(globus_rsl_is_boolean_and(base_rsl));
    globus_assert(globus_rsl_is_boolean_and(override_rsl));

    result = globus_rsl_copy_recursive(base_rsl);

    base_relations = globus_rsl_boolean_get_operand_list_ref(result);
    override_relations = globus_rsl_boolean_get_operand_list(override_rsl);

    while(!globus_list_empty(override_relations))
    {
	tmp = globus_list_first(override_relations);
	override_relations = globus_list_rest(override_relations);
	attribute = globus_rsl_relation_get_attribute(tmp);

	node = globus_list_search_pred(*base_relations,
		                       globus_l_gram_job_manager_rsl_match,
				       attribute);
	if(node)
	{
	    globus_rsl_free_recursive(globus_list_remove(base_relations, node));
	}
	globus_list_insert(base_relations, globus_rsl_copy_recursive(tmp));
    }
    return result;
}
/* globus_l_gram_job_manager_rsl_merge() */

globus_bool_t
globus_gram_job_manager_rsl_need_stage_in(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;
    globus_list_t *			node;
    char *				value;
    globus_url_t			url;
    int					i;
    char *				can_stage[] =
					{ GLOBUS_GRAM_PROTOCOL_STDIN_PARAM,
					  GLOBUS_GRAM_PROTOCOL_EXECUTABLE_PARAM,
					  NULL
					};

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_l_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else if(globus_list_search_pred(
		attributes,
		globus_l_gram_job_manager_rsl_match,
		GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	for(i = 0; can_stage[i] != NULL; i++)
	{
	    node = globus_rsl_param_get_values(
		request->rsl,
		can_stage[i]);

	    if(node)
	    {
		value =
		    globus_rsl_value_literal_get_string(
			    globus_list_first(node));

		if(globus_url_parse(value, &url) == 0)
		{
		    if(url.scheme_type != GLOBUS_URL_SCHEME_FILE)
		    {
			globus_url_destroy(&url);
			return GLOBUS_TRUE;
		    }
		    else
		    {
			globus_url_destroy(&url);
		    }
		}
	    }
	}
    }
    return GLOBUS_FALSE;
}
/* globus_gram_job_manager_rsl_need_stage_in() */

globus_bool_t
globus_gram_job_manager_rsl_need_stage_out(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_l_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_gram_job_manager_rsl_need_stage_out() */

globus_bool_t
globus_gram_job_manager_rsl_need_file_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_l_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_CLEANUP_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_gram_job_manager_rsl_need_file_cleanup() */

globus_bool_t
globus_gram_job_manager_rsl_need_scratchdir(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_l_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_gram_job_manager_rsl_need_scratchdir() */

globus_bool_t
globus_gram_job_manager_rsl_need_restart(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_l_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_RESTART_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_gram_job_manager_rsl_need_restart() */

globus_rsl_t *
globus_gram_job_manager_rsl_extract_relation(
    globus_rsl_t *                      rsl,
    char *                              attribute)
{
    globus_list_t **			operand_ref;
    globus_list_t *			node;

    if(! globus_rsl_is_boolean_and(rsl))
    {
        return GLOBUS_NULL;
    }
    operand_ref = globus_rsl_boolean_get_operand_list_ref(rsl);
    node = globus_list_search_pred(*operand_ref,
				   globus_l_gram_job_manager_rsl_match,
				   attribute);
    if(node)
    {
        globus_rsl_t *                  relation;

        relation = globus_list_remove(operand_ref, node);

        return relation;
    }
    return GLOBUS_NULL;
}
/* globus_gram_job_manager_rsl_extract_relation() */

void
globus_gram_job_manager_rsl_add_relation(
    globus_rsl_t *                      rsl,
    globus_rsl_t *                      relation)
{
    globus_list_t **			operand_ref;

    if(! globus_rsl_is_boolean_and(rsl))
    {
	return;
    }
    operand_ref = globus_rsl_boolean_get_operand_list_ref(rsl);
    globus_list_insert(operand_ref, relation);
}

int
globus_gram_job_manager_rsl_add_substitutions_to_symbol_table(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			tmp_rsl_list;
    globus_rsl_t *			attribute;
    globus_list_t *			substitutions;
    globus_rsl_value_t *		substitution_value;
    globus_list_t *			pair;
    globus_rsl_value_t *		variable;
    globus_rsl_value_t *		value;
    char *				variable_string;
    char *				value_string;
    int					rc;

    if(!globus_rsl_is_boolean_and(request->rsl))
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }

    tmp_rsl_list = globus_rsl_boolean_get_operand_list(request->rsl);
    while(!globus_list_empty(tmp_rsl_list))
    {
	attribute = globus_list_first(tmp_rsl_list);
	tmp_rsl_list = globus_list_rest(tmp_rsl_list);

	if(globus_rsl_is_relation_attribute_equal(
		    attribute,
		    "rslsubstitution"))
	{
	    substitutions =
		globus_rsl_value_sequence_get_value_list(
			globus_rsl_relation_get_value_sequence(
			    attribute));
	}
	else
	{
	    continue;
	}

	while(!globus_list_empty(substitutions))
	{
	    substitution_value = globus_list_first(substitutions);
	    substitutions = globus_list_rest(substitutions);

	    if(!globus_rsl_value_is_sequence(substitution_value))
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    }
	    pair = globus_rsl_value_sequence_get_value_list(substitution_value);

	    if(globus_list_size(pair) != 2)
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    }
	    variable = globus_list_first(pair);
	    value = globus_list_first(globus_list_rest(pair));

	    rc = globus_gram_job_manager_rsl_evaluate_value(
		    request,
		    variable,
		    &variable_string);

	    if(rc != GLOBUS_SUCCESS || variable_string == NULL)
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    }

	    rc = globus_gram_job_manager_rsl_evaluate_value(
		    request,
		    value,
		    &value_string);

	    if(rc != GLOBUS_SUCCESS || value_string == NULL)
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    }

	    globus_symboltable_insert(
		    &request->symbol_table,
		    variable_string,
		    value_string);
	}
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_rsl_add_substitutions_to_symbol_table() */

/**
 * Add an environment variable to the job RSL.
 *
 * This function adds a single environment variable to the job RSL. If
 * there is no environment relation in the RSL, then one is added. Both
 * the variable name and value are copied into the RSL, so the original
 * values passed in may be static strings or pointers to data which is
 * freed or overwritten once this function returns.
 *
 * @param ast_node
 *        A pointer to the RSL tree to update. This should point to the
 *        root of the rsl tree (the boolean &) on the invocation of the
 *        function, but will point to various relations in the RSL as
 *        it calls itself recursively.
 * @param var
 *        A pointer to a string containing the variable to be added to
 *        the RSL. No checking is done to see if this environment variable
 *        is already defined in the RSL. This will be duplicated and inserted
 *        into the RSL.
 * @param value
 *        The value of the environment variable named @a var. This will
 *        be duplicated and inserted into the RSL.
 * 
 * @retval 0
 *         The environment variable was added to the RSL.
 * @retval 1
 *         The @a ast_node points to a relation other than an environment
 *         relation
 * @retval 2
 *         The @a ast_node points to some unexpected part of the RSL.
 *
 * @todo Remove old values of @a var if it is already in the RSL's
 *       environment attribute's value.
 */
int
globus_gram_job_manager_rsl_env_add(
    globus_rsl_t *			ast_node,
    char *				var,
    char *				value)
{
    globus_rsl_t *			tmp_rsl_ptr;
    globus_list_t *			tmp_rsl_list;
    globus_list_t *			new_list;
    char *				tmp_rsl_str;
    int					rc;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

            rc = globus_gram_job_manager_rsl_env_add(
		    tmp_rsl_ptr,
		    var,
		    value);
	    if(rc == 0)
	    {
		return rc;
	    }

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);

        }
	/* Didn't find environment in the RSL: add it! */
	tmp_rsl_str = globus_libc_malloc(
		    strlen("environment = (%s %s)") +
		    strlen(var) +
		    strlen(value));

	sprintf(tmp_rsl_str, "environment = (%s %s)", var, value);
	tmp_rsl_ptr = globus_rsl_parse(tmp_rsl_str);

	globus_libc_free(tmp_rsl_str);

	globus_list_insert(
		globus_rsl_boolean_get_operand_list_ref(ast_node),
		tmp_rsl_ptr);

	return 0;
    }
    else if (globus_rsl_is_relation(ast_node))
    {
        if (!globus_rsl_is_relation_attribute_equal(ast_node, "environment"))
        {
            return(1);
        }

        new_list = NULL;

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(globus_libc_strdup(value)));

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(globus_libc_strdup(var)));

        globus_list_insert(
            globus_rsl_value_sequence_get_list_ref(
                 globus_rsl_relation_get_value_sequence(ast_node)),
                 (void *) globus_rsl_value_make_sequence(new_list));

        return(0);
    }
    else
    {
        return(2);
    }
}
/* globus_gram_job_manager_rsl_env_add() */

/**
 * Fill request structure from RSL tree.
 *
 * In this function, we look through the job request RSL to find attributes
 * which we need to process in the job manager program (not in the scripts).
 */
int
globus_gram_job_manager_rsl_request_fill(
    globus_gram_jobmanager_request_t *	request)
{
    int					x;
    char **				tmp_param;
    globus_bool_t                       gram_myjob_collective = GLOBUS_TRUE;
    char *				ptr;
    int					i;
    int					count;
    int					rc;
    char *				removable_params[] = {
	GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
	GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM,
	GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
	GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM,
	NULL };

    if (request->rsl == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NULL_SPECIFICATION_TREE;
    }

    /* Canonize the RSL attributes.  This will remove underscores and lowercase
     * all character.  For example, givin the RSL relation "(Max_Time=20)" the
     * attribute "Max_Time" will be altered in the rsl_tree to be "maxtime".
     *
     */
    if (globus_rsl_assist_attributes_canonicalize(request->rsl) != GLOBUS_SUCCESS)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NULL_SPECIFICATION_TREE;
    }

    /* Process stdout */
    rc = globus_gram_job_manager_output_set_urls(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
	    globus_rsl_param_get_values(
		request->rsl,
		GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM),
	    globus_rsl_param_get_values(
		request->rsl,
		GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM));

    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    /* Process stderr */
    rc = globus_gram_job_manager_output_set_urls(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
	    globus_rsl_param_get_values(
		request->rsl,
		GLOBUS_GRAM_PROTOCOL_STDERR_PARAM),
	    globus_rsl_param_get_values(
		request->rsl,
		GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM));

    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    /*
     * Remove stdout and stderr from RSL---it's stored in the request
     * structure for easier modification when stdio_update or restart happens,
     * and as we send data to the various stdout destinations.
     */
    for(i = 0; removable_params[i] != NULL; i++)
    {
	globus_gram_job_manager_rsl_remove_attribute(request,
		                                     removable_params[i]);
    }

    /*
     *  GET COUNT PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_COUNT;
    }

    if (tmp_param[0])
    {

        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COUNT;
        }
        else
        {
            count = x;
        }
    }
    else
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COUNT;
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET MYJOB PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_MYJOB_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MYJOB;
    }

    if (tmp_param[0])
    {
        if(strcmp(tmp_param[0], "collective") != 0)
        {
            gram_myjob_collective = GLOBUS_FALSE;
        }
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET DRY_RUN PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_DRY_RUN_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_DRYRUN;
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
	{
            request->dry_run = GLOBUS_TRUE;
	}
        else
	{
            request->dry_run = GLOBUS_FALSE;
	}

    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET SAVE_STATE PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_SAVE_STATE_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SAVE_STATE;
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
            request->save_state = GLOBUS_TRUE;
        else
            request->save_state = GLOBUS_FALSE;

    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET TWO_PHASE_COMMIT PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_TWO_PHASE_COMMIT;
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
	{
            request->two_phase_commit = GRAM_JOB_MANAGER_COMMIT_TIMEOUT;
	}
        else
	{
	    x = (int) strtol(tmp_param[0], &ptr, 10);

	    if (strlen(ptr) > 0 || x < 0)
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_TWO_PHASE_COMMIT;
	    }
	    else
	    {
		request->two_phase_commit = x;
	    }
	}
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    globus_gram_job_manager_rsl_remove_attribute(
	    request,
	    GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM);

    /**********************************
     *  GET REMOTE IO URL PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_REMOTE_IO_URL_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
    }

    if (tmp_param[0])
    {
        /* In a STDIO_UPDATE signal, this can be replaced */
        if (request->remote_io_url)
        {
            globus_libc_free(request->remote_io_url);
        }
        request->remote_io_url = globus_libc_strdup(tmp_param[0]);
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET PROXY_TIMEOUT PARAM
     */
    if (globus_rsl_param_get(request->rsl,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_PROXY_TIMEOUT_PARAM,
		             &tmp_param) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_PROXY_TIMEOUT;
    }

    if (tmp_param[0])
    {
        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_PROXY_TIMEOUT;
        }
        else
        {
            request->proxy_timeout = x;
        }
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /* Check for files to stage in */
    rc = globus_gram_job_manager_staging_create_list(request);
    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    return(GLOBUS_SUCCESS);

error_exit:
    return rc;
}
/* globus_gram_job_manager_rsl_request_fill() */

/**
 * Remove an RSL attribute from and RSL tree.
 *
 * @param request
 *        The request containing the RSL tree to modify
 * @param attribute
 *        The name of the attribute to remove from the RSL. The
 *        attribute and it's values will be freed.
 *
 * @retval GLOBUS_SUCCESS
 *         The RSL attribute is no longer present in the request.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
 *         The RSL is not a boolean tree containing attributes.
 */
int
globus_gram_job_manager_rsl_remove_attribute(
    globus_gram_jobmanager_request_t *	request,
    char *				attribute)
{
    globus_list_t **			operand_ref;
    globus_list_t *			node;

    if(! globus_rsl_is_boolean_and(request->rsl))
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }
    operand_ref = globus_rsl_boolean_get_operand_list_ref(request->rsl);
    node = globus_list_search_pred(*operand_ref,
				   globus_l_gram_job_manager_rsl_match,
				   attribute);
    if(node)
    {
	globus_rsl_free_recursive(globus_list_remove(operand_ref, node));
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_rsl_remove_attribute() */

/**
 * Evaluate RSL substitutions for a single RSL attribute
 *
 * Evaluates the value of the named RSL attribute. If it is present, and
 * the evaluation succeeds, then the @a value parameter is modified to
 * contain a copy of the newly-evaluated value of the attribute. 
 *
 * @param request
 *        The request containing the RSL tree to evaluate.
 * @param attribute
 *        The name of the attribute to evaluate.
 * @param value
 *        A pointer to a char * which will be filled with a copy
 *        of the evaluated value of the RSL attribute. If the attribute
 *        is not found, or an error occurs, this will be set to NULL.
 *
 * @retval GLOBUS_SUCCESS
 *         The RSL attribute is present and has evaluated successfully.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
 *         The RSL is not a boolean tree containing attributes.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_EVALUATION_FAILED
 *         The RSL attribute is present but some RSL substitution
 *         could not be evaluated for that attribute.
 */
int
globus_gram_job_manager_rsl_eval_one_attribute(
    globus_gram_jobmanager_request_t *	request,
    char *                              attribute,
    char **                             value)
{
    globus_list_t *                     operands;
    globus_rsl_t *                      attribute_rsl = GLOBUS_NULL;
    globus_rsl_t *			rsl_tree;
    int					rc;

    *value = GLOBUS_NULL;

    if(globus_rsl_is_boolean_and(request->rsl))
    {
        operands = globus_rsl_boolean_get_operand_list(request->rsl);

        while(!globus_list_empty(operands))
        {
            rsl_tree = globus_list_first(operands);

            if(globus_rsl_is_relation_eq(rsl_tree))
            {
                if(globus_rsl_is_relation_attribute_equal(
                            rsl_tree,
                            attribute))
                {
                    attribute_rsl = rsl_tree;
                    break;
                }
            }
            operands = globus_list_rest(operands);
        }
        if(attribute_rsl)
        {
            rc = globus_rsl_eval(attribute_rsl, &request->symbol_table);

	    if(rc != GLOBUS_SUCCESS)
	    {
		return GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    }
            *value = globus_libc_strdup(
		         globus_rsl_value_literal_get_string(
                             globus_rsl_relation_get_single_value(
                                attribute_rsl)));

            return GLOBUS_SUCCESS;
        }
        else
        {
            return GLOBUS_SUCCESS;
        }
    }
    else
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }
}
/* globus_gram_job_manager_eval_one_attribute() */

int
globus_gram_job_manager_rsl_parse_value(
    globus_gram_jobmanager_request_t *	request,
    char *				value_string,
    globus_rsl_value_t **		rsl_value)
{
    char *				rsl_spec = NULL;
    char *				format = "x = %s\n";
    globus_rsl_t *			rsl;
    globus_rsl_value_t *		values;
    int                                 rc = GLOBUS_SUCCESS;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Parsing value string %s to rsl_value_t *\n",
	    value_string);

    rsl_spec = globus_libc_malloc(strlen(format) + strlen(value_string) + 1);

    if (rsl_spec == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }
    sprintf(rsl_spec, format, value_string);
    rsl = globus_rsl_parse(rsl_spec);
    if (rsl == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;

        goto free_rsl_spec_out;
    }

    values = globus_list_first(
	    globus_rsl_value_sequence_get_value_list(
		globus_rsl_relation_get_value_sequence(rsl)));
    if (values == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;

        goto free_rsl_out;
    }
    *rsl_value = globus_rsl_value_copy_recursive(values);
    if (*rsl_value == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_rsl_out;
    }

free_rsl_out:
    globus_rsl_free_recursive(rsl);

free_rsl_spec_out:
    globus_libc_free(rsl_spec);

out:
    return rc;
}
/* globus_gram_job_manager_rsl_parse_value() */

int
globus_gram_job_manager_rsl_evaluate_value(
    globus_gram_jobmanager_request_t *	request,
    globus_rsl_value_t *		value,
    char **				value_string)
{
    globus_rsl_value_t *		copy;
    int					rc = GLOBUS_SUCCESS;

    *value_string = NULL;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Evaluating RSL Value");

    copy = globus_rsl_value_copy_recursive(value);
    if (copy == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }

    if(globus_rsl_value_is_literal(copy))
    {
	*value_string =
	    globus_libc_strdup(globus_rsl_value_literal_get_string(copy));

        if (*value_string == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto free_copy_out;
        }
    }
    else
    {
	rc = globus_rsl_value_eval(
		copy,
		&request->symbol_table,
		value_string,
		0);
    }

free_copy_out:
    globus_rsl_value_free_recursive(copy);

out:
    globus_gram_job_manager_request_log(
	    request,
	    "JM: Evaluated RSL Value to %s",
	    *value_string ? *value_string : "NULL");

    return rc;
}
/* globus_gram_job_manager_rsl_evaluate_value() */

int
globus_gram_job_manager_rsl_eval_string(
    globus_gram_jobmanager_request_t *	request,
    char *				string,
    char **				value_string)
{
    globus_rsl_value_t *		value;
    int					rc;

    *value_string = NULL;

    rc = globus_gram_job_manager_rsl_parse_value(
	    request,
	    string,
	    &value);

    if(rc != GLOBUS_SUCCESS)
    {
	goto parse_failed;
    }

    rc = globus_gram_job_manager_rsl_evaluate_value(
	    request,
	    value,
	    value_string);

    if(rc != GLOBUS_SUCCESS || (*value_string) == NULL)
    {
	goto eval_failed;
    }

eval_failed:
    globus_rsl_value_free_recursive(value);
parse_failed:

    return rc;
}
/* globus_gram_job_manager_rsl_eval_string() */

static
int
globus_l_gram_job_manager_rsl_match(
    void *				datum,
    void *				arg)
{
    globus_rsl_t *			relation = datum;
    char *				attribute = arg;
    char *				test;

    if(!globus_rsl_is_relation(relation))
    {
        return GLOBUS_FALSE;
    }

    test = globus_rsl_relation_get_attribute(relation);

    return (strcmp(test, attribute)==0);
}
/* globus_l_gram_job_manager_rsl_match() */

