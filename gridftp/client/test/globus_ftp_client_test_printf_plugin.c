#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#include "globus_ftp_client_test_printf_plugin.h"

/**
 * @example printf_plugin.c Plugin API demo
 *
 * This example demonstrates the use of the FTP Client Plugin API to
 * implement a plugin which prints out FTP protocol messages and data
 * buffer status as FTP operations occur. It doesn't provide any restart
 * or reliability capability, but shows the minimum code needed to implement
 * a plugin.
 */

static globus_bool_t globus_l_ftp_client_printf_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_printf_plugin_deactivate(void);

static globus_ftp_client_plugin_t globus_l_ftp_client_static_plugin;
globus_module_descriptor_t		globus_i_ftp_client_printf_plugin_module =
{
    "globus_ftp_client_printf_plugin",
    globus_l_ftp_client_printf_plugin_activate,
    globus_l_ftp_client_printf_plugin_deactivate,
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
int
globus_l_ftp_client_printf_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_printf_plugin_init(&globus_l_ftp_client_static_plugin);
    return rc;
}

/**
 * Module deactivation
 */
static
int
globus_l_ftp_client_printf_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
}

static
void
globus_l_ftp_client_printf_plugin_authenticate(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const globus_ftp_control_auth_info_t *		auth_info)
{
    printf("[printf plugin]: Authenticating connection for [handle=%p]\n", handle);
}

static
void
globus_l_ftp_client_printf_plugin_data(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				error,
    const globus_byte_t *			buffer,
    globus_size_t				length,
    globus_off_t				offset,
    globus_bool_t				eof)
{
    printf("[printf plugin]: Received data [%"GLOBUS_OFF_T_FORMAT"-%"GLOBUS_OFF_T_FORMAT"] for [handle=%p]\n",
	   offset, offset+length, handle);
}


static
void
globus_l_ftp_client_printf_plugin_connect(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url)
{
    printf("[printf plugin]: Making a new connection for [handle=%p]\n", handle);
}

static
void
globus_l_ftp_client_printf_plugin_get(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting get" : "Getting",
	   url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_delete(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting delete" : "Deleting",
	   url,
	   handle);
}


static
void
globus_l_ftp_client_printf_plugin_mkdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting mkdir" : "Making directory",
	   url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_rmdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting rmdir" : "Removing directory",
	   url,
	   handle);
}


static
void
globus_l_ftp_client_printf_plugin_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting listing of" : "Listing",
	   url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_verbose_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting verbose listing of" : "Listing",
	   url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_move(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					source_url,
    const char *					dest_url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s to %s (handle=%p)\n",
	   restart ? "Restarting move of" : "Moving",
	   source_url,
	   dest_url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_put(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    printf("[printf plugin]: %s %s (handle=%p)\n",
	   restart ? "Restarting put" : "Putting",
	   url,
	   handle);
}

static
void
globus_l_ftp_client_printf_plugin_command(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const char *					command_name)
{
    printf("[printf plugin]: %s://%s -> %s\n",
	   url->scheme,
	   url->host,
	   command_name);
}

static
void
globus_l_ftp_client_printf_plugin_response(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    globus_object_t *					err,
    const globus_ftp_control_response_t *		response)
{
    if(response && response->response_buffer)
    {
	printf("[printf plugin]: %s://%s <- %s\n",
	       url->scheme,
	       url->host,
	       response->response_buffer);
    }
    else
    {
        if(err)
	{
	    char * tmpstr = globus_object_printable_to_string(err);
	    printf("[printf plugin]: null response, error: %s\n",
	           tmpstr);
	    globus_libc_free(tmpstr);
	}
	else
	{
	    printf("[printf plugin]: null response without an error\n");
	}
    }
}

static
globus_ftp_client_plugin_t *
globus_l_ftp_client_printf_plugin_copy(
    globus_ftp_client_plugin_t *			self)
{
    printf("[printf plugin]: Referencing plugin %p\n", self);

    return &globus_l_ftp_client_static_plugin;
}

static
void
globus_l_ftp_client_printf_plugin_destroy(
    globus_ftp_client_plugin_t *			self)
{
    printf("[printf plugin]: Dereferencing plugin\n");
}

static
void 
globus_l_ftp_client_printf_plugin_transfer(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const char *				source_url,
    const globus_ftp_client_operationattr_t *	source_attr,
    const char *				dest_url,
    const globus_ftp_client_operationattr_t *	dest_attr,
    globus_bool_t				restart)
{
    printf("[printf plugin]: %stransfer for %s->%s\n", restart?"Restarting ":"",source_url, dest_url);
}

static
void 
globus_l_ftp_client_printf_plugin_abort(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle)
{
    printf("[printf plugin]: Abort\n");
}

static
void 
globus_l_ftp_client_printf_plugin_fault(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const globus_url_t *			url,
    globus_object_t *				error)
{
    char * tmpstr = error ? globus_object_printable_to_string(error)
	: "unknown error";

    printf("[printf plugin]: Fault occurred (%s)\n",
	   tmpstr);
}

globus_result_t
globus_ftp_client_printf_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    memset(plugin, '\0', sizeof(globus_ftp_client_plugin_t));

    plugin->plugin_name		= "globus_ftp_client_printf_plugin";
    plugin->copy		= globus_l_ftp_client_printf_plugin_copy;
    plugin->destroy		= globus_l_ftp_client_printf_plugin_destroy;
    plugin->list_func		= globus_l_ftp_client_printf_plugin_list;
    plugin->vlist_func		= globus_l_ftp_client_printf_plugin_verbose_list;
    plugin->mkdir_func		= globus_l_ftp_client_printf_plugin_mkdir;
    plugin->rmdir_func		= globus_l_ftp_client_printf_plugin_rmdir;
    plugin->delete_func		= globus_l_ftp_client_printf_plugin_delete;
    plugin->move_func		= globus_l_ftp_client_printf_plugin_move;
    plugin->get_func		= globus_l_ftp_client_printf_plugin_get;
    plugin->put_func		= globus_l_ftp_client_printf_plugin_put;
    plugin->transfer_func	= globus_l_ftp_client_printf_plugin_transfer;
    plugin->abort_func		= globus_l_ftp_client_printf_plugin_abort;
    plugin->connect_func	= globus_l_ftp_client_printf_plugin_connect;
    plugin->auth_func		= globus_l_ftp_client_printf_plugin_authenticate;
    plugin->read_func		= 0;
    plugin->write_func		= 0;
    plugin->data_func		= globus_l_ftp_client_printf_plugin_data;
    plugin->command_func	= globus_l_ftp_client_printf_plugin_command;
    plugin->response_func	=
	globus_l_ftp_client_printf_plugin_response;
    plugin->fault_func		= globus_l_ftp_client_printf_plugin_fault;
    plugin->command_mask	=
	GLOBUS_FTP_CLIENT_CMD_MASK_ALL &
	~(GLOBUS_FTP_CLIENT_CMD_MASK_INFORMATION);
    plugin->plugin_specific	= 0;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_printf_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    return GLOBUS_SUCCESS;
}

