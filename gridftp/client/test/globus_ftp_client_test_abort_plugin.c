#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#include "globus_ftp_client_test_abort_plugin.h"

static int dummy_counter;

typedef struct
{
    globus_ftp_abort_plugin_when_t		when;
    globus_ftp_abort_plugin_when_t		next;
    int *					counter;
}
globus_l_ftp_abort_plugin_specific_t;
static globus_bool_t globus_l_ftp_client_abort_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_abort_plugin_deactivate(void);

globus_module_descriptor_t		globus_i_ftp_client_abort_plugin_module =
{
    "globus_ftp_client_abort_plugin",
    globus_l_ftp_client_abort_plugin_activate,
    globus_l_ftp_client_abort_plugin_deactivate,
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
globus_bool_t
globus_l_ftp_client_abort_plugin_activate(void)
{
    return globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
}

/**
 * Module deactivation
 */
static
globus_bool_t
globus_l_ftp_client_abort_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
}

static
void
globus_l_ftp_client_abort_plugin_authenticate(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const globus_ftp_control_auth_info_t *		auth_info)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(d->when == FTP_ABORT_AT_AUTH)
    {
	printf("[abort plugin]: Aborting during authentication\n");
	globus_ftp_client_plugin_abort(handle);
	d->counter++;
    }
    d->next = FTP_ABORT_AT_AUTH_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_abort_plugin_connect(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(d->when == FTP_ABORT_AT_CONNECT)
    {
	printf("[abort plugin]: Aborting during connect\n");
	globus_ftp_client_plugin_abort(handle);
	d->counter++;
    }
    d->next = FTP_ABORT_AT_CONNECT_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_abort_plugin_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_verbose_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_delete(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_mkdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_rmdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_move(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					source_url,
    const char *					dest_url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_get(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_abort_plugin_put(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{

}

static
void
globus_l_ftp_client_abort_plugin_command(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const char *					command_name)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(strcmp(command_name, "SITE HELP") == 0)
    {
	if(d->when == FTP_ABORT_AT_SITE_HELP)
	{
	    printf("[abort plugin]: Aborting during SITE HELP\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_SITE_HELP_RESPONSE;
    }
    else if(strcmp(command_name, "FEAT") == 0)
    {
	if(d->when == FTP_ABORT_AT_FEAT)
	{
	    printf("[abort plugin]: Aborting during FEAT\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_FEAT_RESPONSE;
    }
    else if(strcmp(command_name, "TYPE") == 0)
    {
	if(d->when == FTP_ABORT_AT_TYPE)
	{
	    printf("[abort plugin]: Aborting during TYPE\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_TYPE_RESPONSE;
    }
    else if(strcmp(command_name, "MODE") == 0)
    {
	if(d->when == FTP_ABORT_AT_MODE)
	{
	    printf("[abort plugin]: Aborting during MODE\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_MODE_RESPONSE;
    }
    else if(strcmp(command_name, "OPTS RETR") == 0)
    {
	if(d->when == FTP_ABORT_AT_OPTS_RETR)
	{
	    printf("[abort plugin]: Aborting during OPTS RETR\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_OPTS_RETR_RESPONSE;
    }
    else if(strcmp(command_name, "PASV") == 0)
    {
	if(d->when == FTP_ABORT_AT_PASV)
	{
	    printf("[abort plugin]: Aborting during PASV\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_PASV_RESPONSE;
    }
    else if(strcmp(command_name, "PORT") == 0)
    {
	if(d->when == FTP_ABORT_AT_PORT)
	{
	    printf("[abort plugin]: Aborting during PORT\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_PORT_RESPONSE;
    }
    else if(strcmp(command_name, "REST") == 0)
    {
	if(d->when == FTP_ABORT_AT_REST)
	{
	    printf("[abort plugin]: Aborting during REST\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_REST_RESPONSE;
    }
    else if(strcmp(command_name, "RETR") == 0)
    {
	if(d->when == FTP_ABORT_AT_RETR)
	{
	    printf("[abort plugin]: Aborting during RETR\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_RETR_RESPONSE;
    }
    else if(strcmp(command_name, "STOR") == 0)
    {
	if(d->when == FTP_ABORT_AT_STOR)
	{
	    printf("[abort plugin]: Aborting during STOR\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_STOR_RESPONSE;
    }
    else if(strcmp(command_name, "LIST") == 0)
    {
	if(d->when == FTP_ABORT_AT_LIST)
	{
	    printf("[restart plugin]: About to restart during LIST\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_LIST_RESPONSE;
    }
    else if(strcmp(command_name, "NLST") == 0)
    {
	if(d->when == FTP_ABORT_AT_NLST)
	{
	    printf("[restart plugin]: About to restart during NLST\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_NLST_RESPONSE;
    }
    else if(strcmp(command_name, "MKD") == 0)
    {
	if(d->when == FTP_ABORT_AT_MKD)
	{
	    printf("[restart plugin]: About to restart during MKD\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_MKD_RESPONSE;
    }
    else if(strcmp(command_name, "RMD") == 0)
    {
	if(d->when == FTP_ABORT_AT_RMD)
	{
	    printf("[restart plugin]: About to restart during RMD\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_RMD_RESPONSE;
    }
    else if(strcmp(command_name, "DELE") == 0)
    {
	if(d->when == FTP_ABORT_AT_DELE)
	{
	    printf("[restart plugin]: About to restart during DELE\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_DELE_RESPONSE;
    }
    else if(strcmp(command_name, "RNFR") == 0)
    {
	if(d->when == FTP_ABORT_AT_RNFR)
	{
	    printf("[restart plugin]: About to restart during RNFR\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_RNFR_RESPONSE;
    }
    else if(strcmp(command_name, "RNTO") == 0)
    {
	if(d->when == FTP_ABORT_AT_RNTO)
	{
	    printf("[restart plugin]: About to restart during RNTO\n");
	    globus_ftp_client_plugin_abort(handle);
	    d->counter++;
	}
	d->next = FTP_ABORT_AT_RNTO_RESPONSE;
    }

    return;
}

static
void
globus_l_ftp_client_abort_plugin_response(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    globus_object_t *					err,
    const globus_ftp_control_response_t *		response)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->next == d->when)
    {
	printf("[abort plugin]: Aborting during response (when=%d)\n",
	       (int) d->when);
	globus_ftp_client_abort(handle);
	d->counter++;
    }
    return;
}

static
void
globus_l_ftp_client_abort_plugin_read(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_ABORT_AT_READ)
    {
	printf("[abort plugin]: Aborting during read\n");
	globus_ftp_client_abort(handle);
	d->counter++;
    }
    return;
}

static
void
globus_l_ftp_client_abort_plugin_data(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    globus_object_t *					error,
    const globus_byte_t *				buffer,
    globus_size_t					length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_ABORT_AT_DATA)
    {
	printf("[abort plugin]: Aborting during data callback\n");
	globus_ftp_client_abort(handle);
	d->counter++;
    }
    return;
}

static
void
globus_l_ftp_client_abort_plugin_write(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_ABORT_AT_WRITE)
    {
	printf("[abort plugin]: Aborting during write\n");
	globus_ftp_client_abort(handle);
	d->counter++;
    }
    return;
}

static
globus_ftp_client_plugin_t *
globus_l_ftp_client_abort_plugin_copy(
    globus_ftp_client_plugin_t *			self)
{
    globus_ftp_client_plugin_t *			newguy;

    newguy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    memcpy(newguy, self, sizeof(globus_ftp_client_plugin_t));
    newguy->plugin_specific = 
	globus_libc_malloc(sizeof(globus_l_ftp_abort_plugin_specific_t));
    memcpy(newguy->plugin_specific, 
	   self->plugin_specific, 
	   sizeof(globus_l_ftp_abort_plugin_specific_t));
    return newguy;
}

static
void
globus_l_ftp_client_abort_plugin_destroy(
    globus_ftp_client_plugin_t *			self)
{
    globus_libc_free(self->plugin_specific);
    globus_libc_free(self);
}

static
void 
globus_l_ftp_client_abort_plugin_transfer(
    globus_ftp_client_plugin_t *		plugin,
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
globus_l_ftp_client_abort_plugin_abort(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle)
{
    printf("[abort plugin]: We've been aborted\n");
}

static
void 
globus_l_ftp_client_abort_plugin_fault(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const globus_url_t *			url,
    globus_object_t *				error)
{
    printf("[abort plugin]: Fault detected\n");
}

globus_result_t
globus_ftp_client_abort_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    memset(plugin, '\0', sizeof(globus_ftp_client_plugin_t));
    plugin->plugin_name		= "globus_ftp_client_abort_plugin";
    plugin->copy		= globus_l_ftp_client_abort_plugin_copy;
    plugin->destroy		= globus_l_ftp_client_abort_plugin_destroy;
    plugin->list_func		= globus_l_ftp_client_abort_plugin_list;
    plugin->vlist_func		= globus_l_ftp_client_abort_plugin_verbose_list;
    plugin->delete_func		= globus_l_ftp_client_abort_plugin_delete;
    plugin->mkdir_func		= globus_l_ftp_client_abort_plugin_mkdir;
    plugin->rmdir_func		= globus_l_ftp_client_abort_plugin_rmdir;
    plugin->move_func		= globus_l_ftp_client_abort_plugin_move;
    plugin->get_func		= globus_l_ftp_client_abort_plugin_get;
    plugin->put_func		= globus_l_ftp_client_abort_plugin_put;
    plugin->transfer_func	= globus_l_ftp_client_abort_plugin_transfer;
    plugin->abort_func		= globus_l_ftp_client_abort_plugin_abort;
    plugin->connect_func	= globus_l_ftp_client_abort_plugin_connect;
    plugin->auth_func		= globus_l_ftp_client_abort_plugin_authenticate;
    plugin->read_func		= globus_l_ftp_client_abort_plugin_read;
    plugin->write_func		= globus_l_ftp_client_abort_plugin_write;
    plugin->data_func		= globus_l_ftp_client_abort_plugin_data;
    plugin->command_func	= globus_l_ftp_client_abort_plugin_command;
    plugin->response_func	=
	globus_l_ftp_client_abort_plugin_response;
    plugin->fault_func		= globus_l_ftp_client_abort_plugin_fault;
    plugin->command_mask	= GLOBUS_FTP_CLIENT_CMD_MASK_ALL;
    plugin->plugin_specific	= 
	globus_libc_malloc(sizeof(globus_l_ftp_abort_plugin_specific_t));

    d = plugin->plugin_specific;

    d->when = FTP_ABORT_NEVER;
    d->counter = &dummy_counter;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_abort_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_libc_free(plugin->plugin_specific);
    plugin->plugin_specific = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_abort_plugin_set_abort_point(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_abort_plugin_when_t			when)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    d->when = when;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_abort_plugin_set_abort_counter(
    globus_ftp_client_plugin_t *                        plugin,
    int *                                               counter)
{
    globus_l_ftp_abort_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    d->counter = counter;
    return GLOBUS_SUCCESS;
}
