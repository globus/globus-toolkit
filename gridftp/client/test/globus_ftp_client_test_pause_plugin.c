#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#include "globus_ftp_client_test_pause_plugin.h"

static globus_bool_t globus_l_ftp_client_pause_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_pause_plugin_deactivate(void);

static globus_ftp_client_plugin_t globus_l_ftp_client_static_plugin;
globus_module_descriptor_t		globus_i_ftp_client_pause_plugin_module =
{
    "globus_ftp_client_pause_plugin",
    globus_l_ftp_client_pause_plugin_activate,
    globus_l_ftp_client_pause_plugin_deactivate,
    GLOBUS_NULL
};

static
int
globus_l_ftp_client_pause_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_pause_plugin_init(&globus_l_ftp_client_static_plugin);
    return rc;
}

static
int
globus_l_ftp_client_pause_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
}


static
void
globus_l_ftp_client_pause_plugin_connect(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url)
{
    plugin->plugin_specific = (void *) 1;
}

static
void
globus_l_ftp_client_pause_plugin_get(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_pause_plugin_delete(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}


static
void
globus_l_ftp_client_pause_plugin_mkdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_pause_plugin_rmdir(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}


static
void
globus_l_ftp_client_pause_plugin_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_pause_plugin_verbose_list(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_pause_plugin_move(
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
globus_l_ftp_client_pause_plugin_put(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const char *					url,
    const globus_ftp_client_operationattr_t *		attr,
    globus_bool_t					restart)
{
}

static
void
globus_l_ftp_client_pause_plugin_command(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    const char *					command_name)
{
}

static
void
globus_l_ftp_client_pause_plugin_response(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_handle_t *			handle,
    const globus_url_t *				url,
    globus_object_t *					err,
    const globus_ftp_control_response_t *		response)
{
    if(plugin->plugin_specific != GLOBUS_NULL)
    {
        plugin->plugin_specific = GLOBUS_NULL;
        printf("Connection established. Press any key to continue.\n");
        getchar();
    }
}

static
globus_ftp_client_plugin_t *
globus_l_ftp_client_pause_plugin_copy(
    globus_ftp_client_plugin_t *			self)
{
    globus_ftp_client_plugin_t * copy;
    copy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    memcpy(copy, self, sizeof(globus_ftp_client_plugin_t));
    return copy;
}

static
void
globus_l_ftp_client_pause_plugin_destroy(
    globus_ftp_client_plugin_t *			self)
{
    globus_libc_free(self);
}

static
void 
globus_l_ftp_client_pause_plugin_transfer(
    globus_ftp_client_plugin_t *		plugin,
    globus_ftp_client_handle_t *		handle,
    const char *				source_url,
    const globus_ftp_client_operationattr_t *	source_attr,
    const char *				dest_url,
    const globus_ftp_client_operationattr_t *	dest_attr,
    globus_bool_t				restart)
{
}

globus_result_t
globus_ftp_client_pause_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    memset(plugin, '\0', sizeof(globus_ftp_client_plugin_t));

    plugin->plugin_name		= "globus_ftp_client_pause_plugin";
    plugin->copy		= globus_l_ftp_client_pause_plugin_copy;
    plugin->destroy		= globus_l_ftp_client_pause_plugin_destroy;
    plugin->list_func		= globus_l_ftp_client_pause_plugin_list;
    plugin->vlist_func		= globus_l_ftp_client_pause_plugin_verbose_list;
    plugin->mkdir_func		= globus_l_ftp_client_pause_plugin_mkdir;
    plugin->rmdir_func		= globus_l_ftp_client_pause_plugin_rmdir;
    plugin->delete_func		= globus_l_ftp_client_pause_plugin_delete;
    plugin->move_func		= globus_l_ftp_client_pause_plugin_move;
    plugin->get_func		= globus_l_ftp_client_pause_plugin_get;
    plugin->put_func		= globus_l_ftp_client_pause_plugin_put;
    plugin->transfer_func	= globus_l_ftp_client_pause_plugin_transfer;
    plugin->abort_func		= GLOBUS_NULL;
    plugin->connect_func	= globus_l_ftp_client_pause_plugin_connect;
    plugin->auth_func		= GLOBUS_NULL;
    plugin->read_func		= GLOBUS_NULL;
    plugin->write_func		= GLOBUS_NULL;
    plugin->data_func		= GLOBUS_NULL;
    plugin->command_func	= GLOBUS_NULL;
    plugin->response_func	= globus_l_ftp_client_pause_plugin_response;
    plugin->fault_func		= GLOBUS_NULL;
    plugin->command_mask	= GLOBUS_FTP_CLIENT_CMD_MASK_ALL;
    plugin->plugin_specific	= GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_client_pause_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    return GLOBUS_SUCCESS;
}

