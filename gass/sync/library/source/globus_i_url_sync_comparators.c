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
 * @file globus_i_url_sync_comparators.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_handle.h"
#include "globus_i_url_sync_log.h"
#include "globus_ftp_client.h"
#include "globus_common.h"
#include "version.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/* Types */

/** Monitor structured user locally to synchronize the asynch FTP calls. */
typedef struct
{
    globus_mutex_t                          mutex;
    globus_cond_t                           cond;
    globus_bool_t                           done;
} globus_l_url_sync_monitor_t;

/** Callback arg structure used in the chained comparison. */
typedef struct
{
    globus_list_t *				list;
    globus_url_sync_compare_func_cb_t		cb_func;
    void *					cb_arg;
}
globus_l_url_sync_chain_func_cb_arg_t;

/* Function declarations */

static
globus_result_t
globus_l_url_sync_ftpclient_mlst(
    globus_url_sync_endpoint_t *            endpoint);

static
void
globus_l_url_sync_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error);

static
globus_result_t
globus_l_url_sync_exists_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *				error);

static
globus_result_t
globus_l_url_sync_size_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *		       		error);

static
globus_result_t
globus_l_url_sync_modify_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *				error);

/* Functions */

/**
 * Existence comparison function, including filetype checking.
 *
 */
static
globus_result_t
globus_l_url_sync_exists_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *				error)
{
    globus_result_t	res = GLOBUS_SUCCESS;

    GlobusFuncName(globus_l_url_sync_exists_func);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");
    
    *result = 0;

    /* Stat the source */
	if (source->stats.type == globus_url_sync_endpoint_type_unknown)
		res = globus_l_url_sync_ftpclient_mlst(source);
	
    if (res != GLOBUS_SUCCESS)
    {
        globus_object_t * err = globus_error_get(res);
	int response_code = globus_error_ftp_error_get_code(err);
	globus_i_url_sync_log_debug("response = %d, result = %d, %s\n", 
		    response_code, res, globus_error_print_chain(err));

	/* *** use the real return code(s) which are not currently known *** */
	switch (res)
	  {
	  case 18:
            /* gridftp authentication error */
	    error = GLOBUS_I_URL_SYNC_ERROR_REMOTE("authentication required");
	    break;
	  case 11:
	  case 12:
	    error = GLOBUS_I_URL_SYNC_ERROR_REMOTE("authentication expired");
	    break;
	  default:
	    error = GLOBUS_I_URL_SYNC_ERROR_NOTFOUND();
	  } 
    }
    else 
    {
        /* Report an error if source file is not found */
        if (!source->stats.exists) 
	{
	    error = GLOBUS_I_URL_SYNC_ERROR_NOTFOUND();
	} 
	else 
        {
	    int dir_ending = 
	      (destination->url[strlen(destination->url)-1] == '/')? GLOBUS_TRUE: GLOBUS_FALSE;

	    /* If source is directory, make sure URL ends with "/". */
	    if (source->stats.type == globus_url_sync_endpoint_type_dir)
	    {
	        if (source->url[strlen(source->url)-1] != '/')
		    strcat(source->url, "/");
	    }
	    
	    /* Stat the destination */
	    if (destination->stats.type == globus_url_sync_endpoint_type_unknown)
	        globus_l_url_sync_ftpclient_mlst(destination);
       
	    /* Compare existence */
	    *result = source->stats.exists - destination->stats.exists;
       
	    if (destination->stats.exists)
	    {
	        if (source->stats.type != destination->stats.type)
		  error = GLOBUS_I_URL_SYNC_ERROR_FILETYPE();
		else 
		{
		    if (source->stats.type == globus_url_sync_endpoint_type_dir)
		    {
		        if (!dir_ending) 
			    strcat(destination->url, "/");
		    } else {
		        if (dir_ending) {
			    error = GLOBUS_I_URL_SYNC_ERROR_FILETYPE();
			}
		    }
		}
	    }
	    else
	    {
	        if (source->stats.type == globus_url_sync_endpoint_type_dir)
		{
		    if (!dir_ending)
		        strcat(destination->url, "/");
		}
		else 
		{
		    if (dir_ending)
			    error = GLOBUS_I_URL_SYNC_ERROR_FILETYPE();
		}
	    }
	}
    }
					
    /* Not handling the ftpclient_mlst() results because... the ftp client
     * documentation seems to indicate that if a file does not exist, the
     * mlst operation may return an error. So an error is not really an error
     * in some cases... Ideally this should be better handled or confirmed in
     * the docs. */

    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
    return GLOBUS_SUCCESS;
}
/* globus_l_url_sync_exists_func */

/**
 * Size comparison function.
 */
static
globus_result_t
globus_l_url_sync_size_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *				error)
{
    GlobusFuncName(globus_l_url_sync_size_func);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");
	
    *result = source->stats.size - destination->stats.size;
	
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
    return GLOBUS_SUCCESS;
}
/* globus_l_url_sync_size_func */

/**
 * Modify comparison function.
 */
static
globus_result_t
globus_l_url_sync_modify_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int *					result,
    globus_object_t *				error)
{
    globus_url_sync_modification_params_t *params = 
      (globus_url_sync_modification_params_t *)comparator_arg;

    GlobusFuncName(globus_l_url_sync_modify_func);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");
	
    *result = (int) difftime(
		mktime(&(source->stats.modify_tm)),
		mktime(&(destination->stats.modify_tm)));

    if (params != GLOBUS_NULL)
    {
        switch (params->type)
        {
            case globus_url_sync_modification_time_newer:
                if (*result < 0) {
                    *result = 0;
                }
                break;
            case globus_url_sync_modification_time_older:
                if (*result > 0) {
                    *result = 0;
                }
                break;
            default:
                /* No action required, for globus_url_sync_modification_time_equal. */
                ;
        }
    }

    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
    return GLOBUS_SUCCESS;
}
/* globus_l_url_sync_modify_func */

/**
 * Chained comparison function. Sets up the callback argument then immediately
 * hands execution to its own callback which does the rest of the work.
 */
globus_result_t
globus_l_url_sync_chain_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    globus_url_sync_compare_func_cb_t		 callback_func,
    void *                                      callback_arg)
{
    globus_url_sync_comparator_t *		next_comparator;
    int						result = 0;
    globus_object_t *                           error = GLOBUS_NULL;
    globus_list_t *				list = comparator_arg;

    GlobusFuncName(globus_l_url_sync_chain_func);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(callback_func, "callback");

    while (1) {
        if (globus_list_empty(list) || result!=0 || error)
	{
	    /* Call the user callback function when the evaluations in this chain
	     * reach a conclussion:
	     *  a. either there are no more comparisons left to perform,
	     *  b. or a comparison indicated source/dest are out of synch,
	     *  c. or an error has occurred.
	     *
	     * Call the user callback, then free the temporary callback arg
	     * structure.
	     */
	    callback_func(callback_arg, source, destination, result, error);
	    break;
	}
	else
	{
	    /* Initiate next comparison in the list. */
	    next_comparator =
	      (globus_url_sync_comparator_t *)globus_list_first(list);
	    list = globus_list_rest(list);
			
	    /* Call next compare func */
	    next_comparator->compare_func(next_comparator->comparator_arg,
					  source,
					  destination,
					  &result,
					  error);
	}	
    }
    
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(callback_func, "callback");
    return GLOBUS_SUCCESS;
}
/* globus_l_url_sync_chain_func */


/**
 * A helper function for simplifying the MSLT operations.
 */
static
globus_result_t
globus_l_url_sync_ftpclient_mlst(
    globus_url_sync_endpoint_t *            endpoint)
{
    globus_result_t                         result;
    globus_l_url_sync_monitor_t             monitor;
    globus_byte_t *                         buffer;
    globus_size_t                           buffer_length;
    globus_ftp_client_operationattr_t       dummy;
    char			            name[GLOBUS_I_URL_SYNC_FILENAME_BUFLEN];
    GlobusFuncName(globus_l_url_sync_ftp_mlst);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(endpoint->ftp_handle, endpoint->url);

    /* Initialize monitor */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

    /* Initialize buffer */
    buffer = GLOBUS_NULL;
    buffer_length = 0;

    /* Create a dummy op attr to workaround gridftp bug in older clients */
    globus_ftp_client_operationattr_init(&dummy);

    /* MSLT */
    result = globus_ftp_client_mlst(
            endpoint->ftp_handle,
            endpoint->url,
            &dummy, /* operation attribute optional */
            &endpoint->mlst_buffer,
            &endpoint->mlst_buffer_length,
            globus_l_url_sync_ftpclient_complete_cb,
            &monitor);

    if (result != GLOBUS_SUCCESS)
        goto cleanexit;

    /* Wait for completion */
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    /* Parse MSLT buffer */
    if (endpoint->mlst_buffer_length)
    {
        globus_url_sync_l_parse_mlst_buffer(endpoint, endpoint->mlst_buffer, name);
    }
    
  cleanexit:
    globus_cond_destroy(&monitor.cond);
    globus_mutex_destroy(&monitor.mutex);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(endpoint->ftp_handle, endpoint->url);
    return result;
}
/* globus_l_url_sync_ftpclient_mlst */

/*
 * The operation complete callback for the ftp client operation.
 */
static
void
globus_l_url_sync_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_monitor_t *           monitor;
    GlobusFuncName(globus_l_url_sync_ftpclient_complete_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");

    monitor = (globus_l_url_sync_monitor_t *) user_arg;

    if(error)
    {
        globus_i_url_sync_log_error(error);
    }

    /* Signal monitor */
    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
}
/* globus_l_url_sync_ftpclient_complete_cb */

/* Chained comparator functions */
void
globus_url_sync_chained_comparator_init(
    globus_url_sync_comparator_t *					chain)
{
    chain->comparator_arg  =  GLOBUS_NULL;
    chain->compare_func    =  (globus_url_sync_compare_func_t)GLOBUS_NULL;
    /* unused, because chain is started with "globus_l_url_sync_chain_func",
       which takes the user callback as a parameter. */
}

void
globus_url_sync_chained_comparator_destroy(
    globus_url_sync_comparator_t *					chain)
{
    globus_assert(chain);

    if (chain->comparator_arg)
        globus_list_free(chain->comparator_arg);
}

void
globus_url_sync_chained_comparator_add(
    globus_url_sync_comparator_t *					chain,
    globus_url_sync_comparator_t *					next)
{
    globus_assert(chain);
    chain->comparator_arg = globus_list_cons(
		next, (globus_list_t *) chain->comparator_arg);
}


/* Variables */

globus_url_sync_comparator_t    globus_url_sync_comparator_exists =
{
    GLOBUS_NULL,
    globus_l_url_sync_exists_func
};

globus_url_sync_comparator_t    globus_url_sync_comparator_size =
{
    GLOBUS_NULL,
    globus_l_url_sync_size_func
};

globus_url_sync_comparator_t    globus_url_sync_comparator_modify =
{
	GLOBUS_NULL,
	globus_l_url_sync_modify_func
};

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

