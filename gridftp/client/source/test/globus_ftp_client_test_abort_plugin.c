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

#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#include "globus_ftp_client_test_abort_plugin.h"

static int dummy_counter;

typedef struct
{
    globus_ftp_client_test_abort_plugin_when_t		when;
    globus_ftp_client_test_abort_plugin_when_t		next;
    int *					counter;
}
globus_l_ftp_test_abort_plugin_specific_t;

#define GLOBUS_L_FTP_CLIENT_TEST_ABORT_PLUGIN_NAME \
    "globus_ftp_client_test_abort_plugin"
#define GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(d, func) \
    result = globus_ftp_client_plugin_set_##func##_func(d, globus_l_ftp_client_test_abort_plugin_##func); \
    if(result != GLOBUS_SUCCESS) goto result_exit;
#define GLOBUS_L_FTP_CLIENT_ABORT_PLUGIN_RETURN(plugin) \
    if(plugin == GLOBUS_NULL) \
    {\
	return globus_error_put(globus_error_construct_string(\
		GLOBUS_FTP_CLIENT_MODULE,\
		GLOBUS_NULL,\
		"[%s] NULL plugin at %s\n",\
		GLOBUS_FTP_CLIENT_MODULE->module_name,\
		myname));\
    }


static globus_bool_t globus_l_ftp_client_test_abort_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_test_abort_plugin_deactivate(void);

globus_module_descriptor_t globus_i_ftp_client_test_abort_plugin_module =
{
    "globus_ftp_client_test_abort_plugin",
    globus_l_ftp_client_test_abort_plugin_activate,
    globus_l_ftp_client_test_abort_plugin_deactivate,
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
globus_bool_t
globus_l_ftp_client_test_abort_plugin_activate(void)
{
    return globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
}

/**
 * Module deactivation
 */
static
globus_bool_t
globus_l_ftp_client_test_abort_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
}

static
void
globus_l_ftp_client_test_abort_plugin_authenticate(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_control_auth_info_t *		auth_info)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;

    if(d->when == FTP_ABORT_AT_AUTH)
    {
	printf("[abort plugin]: Aborting during authentication\n");
	globus_ftp_client_plugin_abort(handle);
	(*d->counter)++;
    }
    d->next = FTP_ABORT_AT_AUTH_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_connect(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;

    if(d->when == FTP_ABORT_AT_CONNECT)
    {
	printf("[abort plugin]: Aborting during connect\n");
	globus_ftp_client_plugin_abort(handle);
	(*d->counter)++;
    }
    d->next = FTP_ABORT_AT_CONNECT_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_list(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_verbose_list(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_machine_list(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}
     
static
void
globus_l_ftp_client_test_abort_plugin_delete(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_mkdir(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_rmdir(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_move(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					source_url,
    const char *					dest_url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_get(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_put(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_command(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const char *					command_name)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;

    if(strncmp(command_name, "SITE HELP", strlen("SITE HELP")) == 0)
    {
	if(d->when == FTP_ABORT_AT_SITE_HELP)
	{
	    printf("[abort plugin]: Aborting during SITE HELP\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_SITE_HELP_RESPONSE;
    }
    else if(strncmp(command_name, "FEAT", strlen("FEAT")) == 0)
    {
	if(d->when == FTP_ABORT_AT_FEAT)
	{
	    printf("[abort plugin]: Aborting during FEAT\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_FEAT_RESPONSE;
    }
    else if(strncmp(command_name, "TYPE", strlen("TYPE")) == 0)
    {
	if(d->when == FTP_ABORT_AT_TYPE)
	{
	    printf("[abort plugin]: Aborting during TYPE\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_TYPE_RESPONSE;
    }
    else if(strncmp(command_name, "MODE", strlen("MODE")) == 0)
    {
	if(d->when == FTP_ABORT_AT_MODE)
	{
	    printf("[abort plugin]: Aborting during MODE\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_MODE_RESPONSE;
    }
    else if(strncmp(command_name, "OPTS RETR", strlen("OPTS RETR")) == 0)
    {
	if(d->when == FTP_ABORT_AT_OPTS_RETR)
	{
	    printf("[abort plugin]: Aborting during OPTS RETR\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_OPTS_RETR_RESPONSE;
    }
    else if(strncmp(command_name, "PASV", strlen("PASV")) == 0)
    {
	if(d->when == FTP_ABORT_AT_PASV)
	{
	    printf("[abort plugin]: Aborting during PASV\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_PASV_RESPONSE;
    }
    else if(strncmp(command_name, "PORT", strlen("PORT")) == 0)
    {
	if(d->when == FTP_ABORT_AT_PORT)
	{
	    printf("[abort plugin]: Aborting during PORT\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_PORT_RESPONSE;
    }
    else if(strncmp(command_name, "REST", strlen("REST")) == 0)
    {
	if(d->when == FTP_ABORT_AT_REST)
	{
	    printf("[abort plugin]: Aborting during REST\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_REST_RESPONSE;
    }
    else if(strncmp(command_name, "RETR", strlen("RETR")) == 0)
    {
	if(d->when == FTP_ABORT_AT_RETR)
	{
	    printf("[abort plugin]: Aborting during RETR\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_RETR_RESPONSE;
    }
    else if(strncmp(command_name, "STOR", strlen("STOR")) == 0)
    {
	if(d->when == FTP_ABORT_AT_STOR)
	{
	    printf("[abort plugin]: Aborting during STOR\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_STOR_RESPONSE;
    }
    else if(strncmp(command_name, "LIST", strlen("LIST")) == 0)
    {
	if(d->when == FTP_ABORT_AT_LIST)
	{
	    printf("[restart plugin]: About to restart during LIST\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_LIST_RESPONSE;
    }
    else if(strncmp(command_name, "NLST", strlen("NLST")) == 0)
    {
	if(d->when == FTP_ABORT_AT_NLST)
	{
	    printf("[restart plugin]: About to restart during NLST\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_NLST_RESPONSE;
    }
    else if(strncmp(command_name, "MLSD", strlen("MLSD")) == 0)
    {
	if(d->when == FTP_ABORT_AT_MLSD)
	{
	    printf("[restart plugin]: About to restart during MLSD\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_MLSD_RESPONSE;
    }
    else if(strncmp(command_name, "MKD", strlen("MKD")) == 0)
    {
	if(d->when == FTP_ABORT_AT_MKD)
	{
	    printf("[restart plugin]: About to restart during MKD\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_MKD_RESPONSE;
    }
    else if(strncmp(command_name, "RMD", strlen("RMD")) == 0)
    {
	if(d->when == FTP_ABORT_AT_RMD)
	{
	    printf("[restart plugin]: About to restart during RMD\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_RMD_RESPONSE;
    }
    else if(strncmp(command_name, "DELE", strlen("DELE")) == 0)
    {
	if(d->when == FTP_ABORT_AT_DELE)
	{
	    printf("[restart plugin]: About to restart during DELE\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_DELE_RESPONSE;
    }
    else if(strncmp(command_name, "RNFR", strlen("RNFR")) == 0)
    {
	if(d->when == FTP_ABORT_AT_RNFR)
	{
	    printf("[restart plugin]: About to restart during RNFR\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_RNFR_RESPONSE;
    }
    else if(strncmp(command_name, "RNTO", strlen("RNTO")) == 0)
    {
	if(d->when == FTP_ABORT_AT_RNTO)
	{
	    printf("[restart plugin]: About to restart during RNTO\n");
	    globus_ftp_client_plugin_abort(handle);
	    (*d->counter)++;
	}
	d->next = FTP_ABORT_AT_RNTO_RESPONSE;
    }

    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_response(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    globus_object_t *					err,
    const globus_ftp_control_response_t *		response)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;
    if(d->next == d->when)
    {
	printf("[abort plugin]: Aborting during response (when=%d)\n",
	       (int) d->when);
	globus_ftp_client_abort(handle);
	(*d->counter)++;
    }
    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_read(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;
    if(d->when == FTP_ABORT_AT_READ)
    {
	printf("[abort plugin]: Aborting during read\n");
	globus_ftp_client_abort(handle);
	(*d->counter)++;
    }
    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_data(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    globus_object_t *					error,
    const globus_byte_t *				buffer,
    globus_size_t					length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;
    if(d->when == FTP_ABORT_AT_DATA)
    {
	printf("[abort plugin]: Aborting during data callback\n");
	globus_ftp_client_abort(handle);
	(*d->counter)++;
    }
    return;
}

static
void
globus_l_ftp_client_test_abort_plugin_write(
    globus_ftp_client_plugin_t *			plugin,
    void *						plugin_specific,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    d = plugin_specific;
    if(d->when == FTP_ABORT_AT_WRITE)
    {
	printf("[abort plugin]: Aborting during write\n");
	globus_ftp_client_abort(handle);
	(*d->counter)++;
    }
    return;
}

static
globus_ftp_client_plugin_t *
globus_l_ftp_client_test_abort_plugin_copy(
    globus_ftp_client_plugin_t *			self,
    void *						plugin_specific)
{
    globus_ftp_client_plugin_t *			newguy;
    globus_l_ftp_test_abort_plugin_specific_t *		d;
    globus_result_t					result;

    d = (globus_l_ftp_test_abort_plugin_specific_t *) plugin_specific;

    newguy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    if(newguy == GLOBUS_NULL)
    {
	goto error_exit;
    }
    result = globus_ftp_client_test_abort_plugin_init(newguy);
    if(result != GLOBUS_SUCCESS)
    {
	goto free_exit;
    }
    result = globus_ftp_client_test_abort_plugin_set_abort_point(newguy,
	    d->when);
    if(result != GLOBUS_SUCCESS)
    {
	goto destroy_exit;
    }
    result = globus_ftp_client_test_abort_plugin_set_abort_counter(newguy,
	    d->counter);
    if(result != GLOBUS_SUCCESS)
    {
	goto destroy_exit;
    }
    return newguy;

destroy_exit:
    globus_ftp_client_test_abort_plugin_destroy(newguy);
free_exit:
    globus_libc_free(newguy);
error_exit:

    return GLOBUS_NULL;
}

static
void
globus_l_ftp_client_test_abort_plugin_destroy(
    globus_ftp_client_plugin_t *			self,
    void *						plugin_specific)
{
    globus_ftp_client_test_abort_plugin_destroy(self);
    globus_libc_free(self);
}

static
void
globus_l_ftp_client_test_abort_plugin_third_party_transfer(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				source_url,
    const globus_ftp_client_operationattr_t *	source_attr,
    const char *				dest_url,
    const globus_ftp_client_operationattr_t *	dest_attr,
    globus_bool_t				restart)
{
}

static
void
globus_l_ftp_client_test_abort_plugin_abort(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle)
{
    printf("[abort plugin]: We've been aborted\n");
}

static
void
globus_l_ftp_client_test_abort_plugin_fault(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    globus_object_t *				error)
{
    printf("[abort plugin]: Fault detected\n");
}

globus_result_t
globus_ftp_client_test_abort_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_object_t *					err;
    globus_result_t					result;
    static char * myname = "globus_ftp_client_test_abort_plugin_init";
    globus_l_ftp_test_abort_plugin_specific_t *		d;

    if(plugin == GLOBUS_NULL)
    {
	return globus_error_put(globus_error_construct_string(
		GLOBUS_FTP_CLIENT_MODULE,
		GLOBUS_NULL,
		"[%s] NULL plugin at %s\n",
		GLOBUS_FTP_CLIENT_MODULE->module_name,
		myname));
    }

    d = globus_libc_malloc(sizeof(globus_l_ftp_test_abort_plugin_specific_t));
    if(d == GLOBUS_NULL)
    {
	return globus_error_put(globus_error_construct_string(
		    GLOBUS_FTP_CLIENT_MODULE,
		    GLOBUS_NULL,
		    "[%s] Could not allocate internal data structure at %s\n",
		    GLOBUS_FTP_CLIENT_MODULE->module_name,
		    myname));
    }
    d->when = FTP_ABORT_NEVER;
    d->counter = &dummy_counter;

    result = globus_ftp_client_plugin_init(plugin,
	                          GLOBUS_L_FTP_CLIENT_TEST_ABORT_PLUGIN_NAME,
				  GLOBUS_FTP_CLIENT_CMD_MASK_ALL,
				  d);

    if(result != GLOBUS_SUCCESS)
    {
	globus_free(d);
	return result;
    }

    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, copy);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, destroy);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, list);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, verbose_list);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, machine_list);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, delete);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, mkdir);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, rmdir);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, move);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, get);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, put);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, third_party_transfer);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, abort);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, connect);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, authenticate);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, read);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, write);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, data);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, command);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, response);
    GLOBUS_FTP_CLIENT_ABORT_PLUGIN_SET_FUNC(plugin, fault);

    return GLOBUS_SUCCESS;

result_exit:
    err = globus_error_get(result);
    globus_ftp_client_plugin_destroy(plugin);

    return globus_error_put(err);
}

globus_result_t
globus_ftp_client_test_abort_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;
    globus_result_t					result;
    static char * myname = "globus_ftp_client_test_abort_plugin_destroy";

    GLOBUS_L_FTP_CLIENT_ABORT_PLUGIN_RETURN(plugin);

    result = globus_ftp_client_plugin_get_plugin_specific(plugin,
                                                          (void **) &d);
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    globus_libc_free(d);

    return globus_ftp_client_plugin_destroy(plugin);
}

globus_result_t
globus_ftp_client_test_abort_plugin_set_abort_point(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_test_abort_plugin_when_t			when)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;
    globus_result_t					result;
    static char * myname = "globus_ftp_client_test_abort_plugin_set_abort_point";

    GLOBUS_L_FTP_CLIENT_ABORT_PLUGIN_RETURN(plugin);

    result = globus_ftp_client_plugin_get_plugin_specific(plugin,
                                                          (void **) &d);

    if(result == GLOBUS_SUCCESS)
    {
        d->when = when;

	return GLOBUS_SUCCESS;
    }
    else
    {
	return result;
    }
}

globus_result_t
globus_ftp_client_test_abort_plugin_set_abort_counter(
    globus_ftp_client_plugin_t *                        plugin,
    int *                                               counter)
{
    globus_l_ftp_test_abort_plugin_specific_t *		d;
    globus_result_t					result;
    static char * myname = "globus_ftp_client_test_abort_plugin_set_abort_point";

    GLOBUS_L_FTP_CLIENT_ABORT_PLUGIN_RETURN(plugin);

    result = globus_ftp_client_plugin_get_plugin_specific(plugin,
                                                          (void **) &d);
    if(result == GLOBUS_SUCCESS)
    {
        d->counter = counter;

	return GLOBUS_SUCCESS;
    }
    else
    {
	return result;
    }
}
