#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#include "globus_ftp_client_test_restart_plugin.h"

typedef enum
{
    GLOBUS_FTP_CLIENT_IDLE,
    GLOBUS_FTP_CLIENT_DELETE,
    GLOBUS_FTP_CLIENT_MKDIR,
    GLOBUS_FTP_CLIENT_RMDIR,
    GLOBUS_FTP_CLIENT_MOVE,
    GLOBUS_FTP_CLIENT_LIST,
    GLOBUS_FTP_CLIENT_NLST,
    GLOBUS_FTP_CLIENT_GET,
    GLOBUS_FTP_CLIENT_PUT,
    GLOBUS_FTP_CLIENT_TRANSFER
}
plugin_operation_t;

typedef struct
{
    globus_ftp_restart_plugin_when_t		when;
    globus_ftp_restart_plugin_when_t		next;
    char *					source_url;
    globus_ftp_client_operationattr_t		source_attr;
    char *					dest_url;
    globus_ftp_client_operationattr_t		dest_attr;
    plugin_operation_t				op;
    globus_reltime_t				timeout;
}
globus_l_ftp_restart_plugin_specific_t;
static globus_bool_t globus_l_ftp_client_restart_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_restart_plugin_deactivate(void);
static
void
globus_l_ftp_client_restart_plugin_do_restart(
    globus_ftp_client_handle_t *			handle,
    globus_l_ftp_restart_plugin_specific_t *		 d);

globus_module_descriptor_t		globus_i_ftp_client_restart_plugin_module =
{
    "globus_ftp_client_restart_plugin",
    globus_l_ftp_client_restart_plugin_activate,
    globus_l_ftp_client_restart_plugin_deactivate,
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
globus_bool_t
globus_l_ftp_client_restart_plugin_activate(void)
{
    return globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
}

/**
 * Module deactivation
 */
static
globus_bool_t
globus_l_ftp_client_restart_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
}

static
void
globus_l_ftp_client_restart_plugin_authenticate(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const globus_ftp_control_auth_info_t *		auth_info)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(d->when == FTP_RESTART_AT_AUTH)
    {
	printf("[restart plugin]: About to restart during authentication\n");
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    d->next = FTP_RESTART_AT_AUTH_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_restart_plugin_connect(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(d->when == FTP_RESTART_AT_CONNECT)
    {
	printf("[restart plugin]: About to restart during connect\n");
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    d->next = FTP_RESTART_AT_CONNECT_RESPONSE;
    return;
}

static
void
globus_l_ftp_client_restart_plugin_get(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_GET;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_delete(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_DELETE;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}


static
void
globus_l_ftp_client_restart_plugin_mkdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_MKDIR;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_rmdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_RMDIR;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_NLST;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_verbose_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;
    
    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_LIST;
	d->source_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_move(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					source_url,
    const char *					dest_url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_MOVE;
	d->source_url = globus_libc_strdup(source_url);
	d->dest_url = globus_libc_strdup(dest_url);
	
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}


static
void
globus_l_ftp_client_restart_plugin_put(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_PUT;
	d->dest_url = globus_libc_strdup(url);
	
	globus_ftp_client_operationattr_copy(&d->dest_attr,
					     attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}

static
void
globus_l_ftp_client_restart_plugin_command(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const char *					command_name)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    if(strcmp(command_name, "SITE HELP") == 0)
    {
	if(d->when == FTP_RESTART_AT_SITE_HELP)
	{
	    printf("[restart plugin]: About to restart during SITE HELP\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_SITE_HELP_RESPONSE;
    }
    else if(strcmp(command_name, "FEAT") == 0)
    {
	if(d->when == FTP_RESTART_AT_FEAT)
	{
	    printf("[restart plugin]: About to restart during FEAT\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle,d);
	}
	d->next = FTP_RESTART_AT_FEAT_RESPONSE;
    }
    else if(strcmp(command_name, "TYPE") == 0)
    {
	if(d->when == FTP_RESTART_AT_TYPE)
	{
	    printf("[restart plugin]: About to restart during TYPE\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_TYPE_RESPONSE;
    }
    else if(strcmp(command_name, "MODE") == 0)
    {
	if(d->when == FTP_RESTART_AT_MODE)
	{
	    printf("[restart plugin]: About to restart during MODE\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_MODE_RESPONSE;
    }
    else if(strcmp(command_name, "OPTS RETR") == 0)
    {
	if(d->when == FTP_RESTART_AT_OPTS_RETR)
	{
	    printf("[restart plugin]: About to restart during OPTS RETR\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_OPTS_RETR_RESPONSE;
    }
    else if(strcmp(command_name, "PASV") == 0)
    {
	if(d->when == FTP_RESTART_AT_PASV)
	{
	    printf("[restart plugin]: About to restart during PASV\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_PASV_RESPONSE;
    }
    else if(strcmp(command_name, "PORT") == 0)
    {
	if(d->when == FTP_RESTART_AT_PORT)
	{
	    printf("[restart plugin]: About to restart during PORT\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_PORT_RESPONSE;
    }
    else if(strcmp(command_name, "REST") == 0)
    {
	if(d->when == FTP_RESTART_AT_REST)
	{
	    printf("[restart plugin]: About to restart during REST\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_REST_RESPONSE;
    }
    else if(strcmp(command_name, "RETR") == 0)
    {
	if(d->when == FTP_RESTART_AT_RETR)
	{
	    printf("[restart plugin]: About to restart during RETR\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_RETR_RESPONSE;
    }
    else if(strcmp(command_name, "STOR") == 0)
    {
	if(d->when == FTP_RESTART_AT_STOR)
	{
	    printf("[restart plugin]: About to restart during STOR\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_STOR_RESPONSE;
    }
    else if(strcmp(command_name, "LIST") == 0)
    {
	if(d->when == FTP_RESTART_AT_LIST)
	{
	    printf("[restart plugin]: About to restart during LIST\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_LIST_RESPONSE;
    }
    else if(strcmp(command_name, "NLST") == 0)
    {
	if(d->when == FTP_RESTART_AT_NLST)
	{
	    printf("[restart plugin]: About to restart during NLST\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_NLST_RESPONSE;
    }
    else if(strcmp(command_name, "MKD") == 0)
    {
	if(d->when == FTP_RESTART_AT_MKD)
	{
	    printf("[restart plugin]: About to restart during MKD\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_MKD_RESPONSE;
    }
    else if(strcmp(command_name, "RMD") == 0)
    {
	if(d->when == FTP_RESTART_AT_RMD)
	{
	    printf("[restart plugin]: About to restart during RMD\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_RMD_RESPONSE;
    }
    else if(strcmp(command_name, "DELE") == 0)
    {
	if(d->when == FTP_RESTART_AT_DELE)
	{
	    printf("[restart plugin]: About to restart during DELE\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_DELE_RESPONSE;
    }
    else if(strcmp(command_name, "RNFR") == 0)
    {
	if(d->when == FTP_RESTART_AT_RNFR)
	{
	    printf("[restart plugin]: About to restart during RNFR\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_RNFR_RESPONSE;
    }
    else if(strcmp(command_name, "RNTO") == 0)
    {
	if(d->when == FTP_RESTART_AT_RNTO)
	{
	    printf("[restart plugin]: About to restart during RNTO\n");
	    globus_l_ftp_client_restart_plugin_do_restart(handle, d);
	}
	d->next = FTP_RESTART_AT_RNTO_RESPONSE;
    }
    return;
}

static
void
globus_l_ftp_client_restart_plugin_response(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    globus_object_t *					err,
    const globus_ftp_control_response_t *		response)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->next == d->when)
    {
	printf("[restart plugin]: About to restart during response (when=%d)\n",
	       (int) d->when);
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    return;
}

static
void
globus_l_ftp_client_restart_plugin_read(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_RESTART_AT_READ)
    {
	printf("[restart plugin]: About to restart during read\n");
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    return;
}

static
void
globus_l_ftp_client_restart_plugin_data(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    globus_object_t *					error,
    const globus_byte_t *				buffer,
    globus_size_t					length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_RESTART_AT_DATA)
    {
	printf("[restart plugin]: About to restart during data callback\n");
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    return;
}

static
void
globus_l_ftp_client_restart_plugin_write(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_byte_t *				buffer,
    globus_size_t					buffer_length,
    globus_off_t					offset,
    globus_bool_t					eof)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(d->when == FTP_RESTART_AT_WRITE)
    {
	printf("[restart plugin]: About to restart during write\n");
	globus_l_ftp_client_restart_plugin_do_restart(handle, d);
    }
    return;
}

static
globus_ftp_client_plugin_t *
globus_l_ftp_client_restart_plugin_copy(
    globus_ftp_client_plugin_t *			self)
{
    globus_ftp_client_plugin_t *			newguy;

    newguy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    memcpy(newguy, self, sizeof(globus_ftp_client_plugin_t));
    newguy->plugin_specific = 
	globus_libc_calloc(1,sizeof(globus_l_ftp_restart_plugin_specific_t));
    memcpy(newguy->plugin_specific, 
	   self->plugin_specific, 
	   sizeof(globus_l_ftp_restart_plugin_specific_t));
    return newguy;
}

static
void
globus_l_ftp_client_restart_plugin_destroy(
    globus_ftp_client_plugin_t *			self)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = self->plugin_specific;

    globus_ftp_client_operationattr_destroy(&d->source_attr);
    globus_ftp_client_operationattr_destroy(&d->dest_attr);
    if(d->source_url)
    {
	globus_libc_free(d->source_url);
    }
    if(d->dest_url)
    {
	globus_libc_free(d->dest_url);
    }
    globus_libc_free(self->plugin_specific);
    globus_libc_free(self);
}

static
void 
globus_l_ftp_client_restart_plugin_transfer(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const char *				source_url,
    const globus_ftp_client_operationattr_t *	source_attr,
    const char *				dest_url,
    const globus_ftp_client_operationattr_t *	dest_attr,
    globus_bool_t				restart)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;
    if(!restart)
    {
	d = plugin->plugin_specific;
	d->op = GLOBUS_FTP_CLIENT_TRANSFER;
	d->source_url = globus_libc_strdup(source_url);
	globus_ftp_client_operationattr_copy(&d->source_attr,
					     source_attr);
	d->dest_url = globus_libc_strdup(dest_url);
	globus_ftp_client_operationattr_copy(&d->dest_attr,
					     dest_attr);
    }
    else
    {
	printf("[restart plugin]: We've been restarted\n");
    }
}


static
void 
globus_l_ftp_client_restart_plugin_fault(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const globus_url_t *			url,
    globus_object_t *				error)
{
    printf("[restart plugin]: Fault detected\n");
}

static
void 
globus_l_ftp_client_restart_plugin_complete(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle)
{
    globus_l_ftp_restart_plugin_specific_t *	d;

    printf("[restart plugin]: operation completed\n");

    d = plugin->plugin_specific;

    if(d->source_url)
    {
	globus_libc_free(d->source_url);
        globus_ftp_client_operationattr_destroy(&d->source_attr);
    }
    if(d->dest_url)
    {
	globus_libc_free(d->dest_url);
        globus_ftp_client_operationattr_destroy(&d->dest_attr);
    }
 }


globus_result_t
globus_ftp_client_restart_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_l_ftp_restart_plugin_specific_t *		d;
    memset(plugin, '\0', sizeof(globus_ftp_client_plugin_t));


    plugin->plugin_name		= "globus_ftp_client_restart_plugin";
    plugin->copy		= globus_l_ftp_client_restart_plugin_copy;
    plugin->abort_func		= 0;
    plugin->destroy		= globus_l_ftp_client_restart_plugin_destroy;
    plugin->list_func		= globus_l_ftp_client_restart_plugin_list;
    plugin->vlist_func		= globus_l_ftp_client_restart_plugin_verbose_list;
    plugin->delete_func		= globus_l_ftp_client_restart_plugin_delete;
    plugin->mkdir_func		= globus_l_ftp_client_restart_plugin_mkdir;
    plugin->rmdir_func		= globus_l_ftp_client_restart_plugin_rmdir;
    plugin->move_func		= globus_l_ftp_client_restart_plugin_move;
    plugin->get_func		= globus_l_ftp_client_restart_plugin_get;
    plugin->put_func		= globus_l_ftp_client_restart_plugin_put;
    plugin->transfer_func	= globus_l_ftp_client_restart_plugin_transfer;
    plugin->connect_func	= globus_l_ftp_client_restart_plugin_connect;
    plugin->auth_func		= globus_l_ftp_client_restart_plugin_authenticate;
    plugin->read_func		= globus_l_ftp_client_restart_plugin_read;
    plugin->write_func		= globus_l_ftp_client_restart_plugin_write;
    plugin->data_func		= globus_l_ftp_client_restart_plugin_data;
    plugin->command_func	= globus_l_ftp_client_restart_plugin_command;
    plugin->response_func	=
	globus_l_ftp_client_restart_plugin_response;
    plugin->fault_func		= globus_l_ftp_client_restart_plugin_fault;
    plugin->complete_func	= globus_l_ftp_client_restart_plugin_complete;
    plugin->command_mask	= GLOBUS_FTP_CLIENT_CMD_MASK_ALL;
    plugin->plugin_specific	= 
	globus_libc_calloc(1,sizeof(globus_l_ftp_restart_plugin_specific_t));

    d = plugin->plugin_specific;

    d->when = FTP_RESTART_NEVER;
    GlobusTimeReltimeSet(d->timeout,0,0);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_restart_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_libc_free(plugin->plugin_specific);
    plugin->plugin_specific = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_restart_plugin_set_restart_point(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_restart_plugin_when_t			when,
    globus_reltime_t *					timeout)
{
    globus_l_ftp_restart_plugin_specific_t *		d;

    d = plugin->plugin_specific;

    d->when = when;
    GlobusTimeReltimeCopy(d->timeout, *timeout);

    return GLOBUS_SUCCESS;
}

static
void
globus_l_ftp_client_restart_plugin_do_restart(
    globus_ftp_client_handle_t *			handle,
    globus_l_ftp_restart_plugin_specific_t *		d)
{
    globus_abstime_t					delay;

    GlobusTimeAbstimeGetCurrent(delay);
    GlobusTimeAbstimeInc(delay, d->timeout);

    d->when = FTP_RESTART_NEVER;

    globus_assert(d->op == GLOBUS_FTP_CLIENT_LIST   ||
		  d->op == GLOBUS_FTP_CLIENT_NLST   ||
		  d->op == GLOBUS_FTP_CLIENT_MOVE   ||
		  d->op == GLOBUS_FTP_CLIENT_DELETE ||
		  d->op == GLOBUS_FTP_CLIENT_MKDIR  ||
		  d->op == GLOBUS_FTP_CLIENT_RMDIR  ||
		  d->op == GLOBUS_FTP_CLIENT_GET    ||
		  d->op == GLOBUS_FTP_CLIENT_PUT    ||
		  d->op == GLOBUS_FTP_CLIENT_TRANSFER);

    if(d->op == GLOBUS_FTP_CLIENT_LIST)
    {
	globus_ftp_client_plugin_restart_verbose_list(handle,
						      d->source_url,
						      &d->source_attr,
						      &delay);
    }
    else if(d->op == GLOBUS_FTP_CLIENT_NLST)
    {
	globus_ftp_client_plugin_restart_list(handle,
					      d->source_url,
					      &d->source_attr,
					      &delay);
    }
    else if(d->op == GLOBUS_FTP_CLIENT_DELETE)
    {
	globus_ftp_client_plugin_restart_delete(handle,
						d->source_url,
						&d->source_attr,
						&delay);
	
    }
    else if(d->op == GLOBUS_FTP_CLIENT_MKDIR)
    {
	globus_ftp_client_plugin_restart_mkdir(handle,
					       d->source_url,
					       &d->source_attr,
					       &delay);
	
    }
    else if(d->op == GLOBUS_FTP_CLIENT_RMDIR)
    {
	globus_ftp_client_plugin_restart_rmdir(handle,
					       d->source_url,
					       &d->source_attr,
					       &delay);
	
    }
    else if(d->op == GLOBUS_FTP_CLIENT_MOVE)
    {
	globus_ftp_client_plugin_restart_move(handle,
					      d->source_url,
					      d->dest_url,
					      &d->source_attr,
					      &delay);
    }
    else if(d->op == GLOBUS_FTP_CLIENT_GET)
    {
	globus_ftp_client_plugin_restart_get(handle,
					     d->source_url,
					     &d->source_attr,
					     GLOBUS_NULL,
					     &delay);
    }
    else if(d->op == GLOBUS_FTP_CLIENT_PUT)
    {
	globus_ftp_client_plugin_restart_put(handle,
					     d->dest_url,
					     &d->dest_attr,
					     GLOBUS_NULL,
					     &delay);
    }
    else if(d->op == GLOBUS_FTP_CLIENT_TRANSFER)
    {
	/* Enable auto-discovery of restart point */
	globus_ftp_client_plugin_restart_transfer(handle,
						  d->source_url,
						  &d->source_attr,
						  d->dest_url,
						  &d->dest_attr,
						  GLOBUS_NULL,
						  &delay);
    }
}









