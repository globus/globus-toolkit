#include "globus_ftp_client_time_plugin.h"
#include "globus_url_copy.h"

#include <stdio.h>
#include <string.h>

static int l_time_plugin_activate(void);
static int l_time_plugin_deactivate(void);

#define L_TIME_PLUGIN_NAME "client_time_plugin"

typedef struct l_time_plugin_s
{
    char *                              src_url;
    char *                              dst_url;
    char *                              text;
    char *                              fname;
    FILE *                              stream;
    globus_abstime_t                    connect_time;
    globus_abstime_t                    login_time;
    globus_abstime_t                    transfer_start_time;
} l_time_plugin_t;

globus_result_t
l_time_plugin_init(
    globus_ftp_client_plugin_t *        plugin,
    char *                              in_args);

static
globus_result_t
l_time_setup_plugin(
    globus_ftp_client_plugin_t *		plugin,
    l_time_plugin_t *                   d);


static globus_guc_client_plugin_funcs_t  l_my_guc_plugin =
{
    l_time_plugin_init
};


static
globus_ftp_client_plugin_t *
l_time_copy(
    globus_ftp_client_plugin_t *        plugin_template,
    void *                              plugin_specific)
{
    globus_ftp_client_plugin_t *        newguy;
    l_time_plugin_t *                   s;
    l_time_plugin_t *                   d;
    globus_result_t                     result;

    s = (l_time_plugin_t *) plugin_specific;

    newguy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    if(newguy == GLOBUS_NULL)
    {
        goto error_exit;
    }
    d = globus_calloc(sizeof(l_time_plugin_t), 1);
    d->fname = strdup(s->fname);
    d->text = strdup(s->text);

    result = l_time_setup_plugin(newguy, d);
    if(result != GLOBUS_SUCCESS)
    {
        goto free_exit;
    }
    return newguy;

free_exit:
    globus_libc_free(newguy);
error_exit:
    return NULL;
}

static
void
l_time_destroy(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific)
{
    l_time_plugin_t *                   s;

    s = (l_time_plugin_t *) plugin_specific;

    globus_free(s->text);
    globus_free(s->fname);
    if(s->stream != stdout)
    {
        fclose(s->stream);
    }
    globus_free(s);
    globus_ftp_client_plugin_destroy(plugin);
}

static
void
l_time_connect(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                        url)
{
    l_time_plugin_t *	d;

    d = (l_time_plugin_t *) plugin_specific;

    GlobusTimeAbstimeGetCurrent(d->connect_time);
}

static
void
l_time_authenticate(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                        url,
    const globus_ftp_control_auth_info_t *  auth_info)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;
}

static
void
l_time_get(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    const globus_ftp_client_operationattr_t *	attr,
    globus_bool_t 				restart)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;

    d->src_url = strdup(url);
    d->dst_url = strdup("(local)");

    GlobusTimeAbstimeGetCurrent(d->transfer_start_time);
}

static
void
l_time_put(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    const globus_ftp_client_operationattr_t *	attr,
    globus_bool_t 				restart)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;

    d->src_url = strdup("(local)");
    d->dst_url = strdup(url);

    GlobusTimeAbstimeGetCurrent(d->transfer_start_time);
}

static
void
l_time_third_party_transfer(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				source_url,
    const globus_ftp_client_operationattr_t *	source_attr,
    const char *				dest_url,
    const globus_ftp_client_operationattr_t *	dest_attr,
    globus_bool_t 				restart)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;

    d->src_url = strdup(source_url);
    d->dst_url = strdup(dest_url);

    GlobusTimeAbstimeGetCurrent(d->transfer_start_time);
}

static
void
l_time_response(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    globus_object_t *				error,
    const globus_ftp_control_response_t *	ftp_response)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;
    char * error_str;

    if(!error)
    {
        switch(ftp_response->code)
        {
            case 230:
                GlobusTimeAbstimeGetCurrent(d->login_time);
                break;

            default:
                break;
        }
    }
    else
    {
        error_str = globus_object_printable_to_string(error);

        fprintf(d->stream, "%s%serror reading response from %s: %s\n",
            d->text ? d->text : "",
            d->text ? ": " : "",
            url,
            error_str);

        globus_libc_free(error_str);
    }
}

static
void
l_time_fault(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    globus_object_t *				error)
{
    l_time_plugin_t *                   d;
    char * error_str;

    d = (l_time_plugin_t *) plugin_specific;

    if(!d->stream)
    {
        return;
    }

    if(!error)
    {
        fprintf(d->stream, "%s%sfault on connection to %s\n",
            d->text ? d->text : "",
            d->text ? ": " : "",
            url);
    }
    else
    {
        error_str = globus_object_printable_to_string(error);

        fprintf(d->stream, "%s%sfault on connection to %s: %s\n",
            d->text ? d->text : "",
            d->text ? ": " : "",
            url,
            error_str);

        globus_libc_free(error_str);
    }
}

static
void
l_time_complete(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle)
{
    float                               login_sec;
    float                               transfer_sec;
    long                                login_usec;
    long                                transfer_usec;
    globus_reltime_t                    diff;
    globus_abstime_t                    now;
    l_time_plugin_t *                   d;

    d = (l_time_plugin_t *) plugin_specific;

    GlobusTimeAbstimeGetCurrent(now);
    login_sec = d->login_time.tv_sec - d->connect_time.tv_sec;
    transfer_sec = now.tv_sec - d->login_time.tv_sec;

    GlobusTimeAbstimeDiff(diff, d->login_time, d->connect_time);
    GlobusTimeReltimeToUSec(login_usec, diff);

    GlobusTimeAbstimeDiff(diff, now, d->login_time);
    GlobusTimeReltimeToUSec(transfer_usec, diff);

    transfer_sec = (float)transfer_usec / 1000000.0;
    login_sec = (float)login_usec / 1000000.0;


    fprintf(d->stream, "%ld %s%f %f %s %s\n", 
        now.tv_sec, d->text,
        login_sec, transfer_sec, d->src_url, d->dst_url);

    if(d->dst_url != NULL) free(d->dst_url);
    if(d->src_url != NULL) free(d->src_url);
}

globus_result_t
l_time_plugin_init(
    globus_ftp_client_plugin_t *		plugin,
    char *                              in_args)
{
    char *                              args;
    char *                              current_arg;
    char *                              key;
    int                                 key_len;
    char *                              tmp_s;
    char *                              fname = NULL;
    char *                              text = NULL;
    char *                              next_arg = NULL;
    l_time_plugin_t *                   d;
    GlobusFuncName(l_time_plugin_init);

    if(in_args != NULL)
    {
        args = strdup(in_args);

        current_arg = args;
        while(current_arg != NULL && *current_arg != '\0')
        {
            tmp_s = strchr(current_arg, '#');
            if(tmp_s != NULL)
            {
                *tmp_s = '\0';
                next_arg = tmp_s + 1;
            }
            else
            {
                next_arg = NULL;
            }
            /* check for parametes we car about */
            key = "filename=";
            key_len = strlen(key);
            if(strncmp(key, current_arg, key_len) == 0)
            {
                fname = current_arg + key_len;
            }

            key = "text=";
            key_len = strlen(key);
            if(strncmp(key, current_arg, key_len) == 0)
            {
                text = current_arg + key_len;
            }

            current_arg = next_arg;
        }
    }


    d = globus_libc_malloc(sizeof(l_time_plugin_t));

    if(fname == NULL)
    {
        fname = "-";
    }
    if(text == NULL)
    {
        text = "";
    }

    d->fname = strdup(fname);
    d->text = strdup(text);

    return l_time_setup_plugin(plugin, d);
}

static
globus_result_t
l_time_setup_plugin(
    globus_ftp_client_plugin_t *		plugin,
    l_time_plugin_t *                   d)
{

    if(strcmp(d->fname, "-") == 0)
    {
        d->stream = stdout;
    }
    else
    {
        d->stream = fopen(d->fname, "a");
        if(d->stream == NULL)
        {
            d->stream = stdout;
        }
    }

    globus_ftp_client_plugin_init(plugin,
		L_TIME_PLUGIN_NAME,
		GLOBUS_FTP_CLIENT_CMD_MASK_ALL,
        d);

    globus_ftp_client_plugin_set_copy_func(plugin, l_time_copy);
    globus_ftp_client_plugin_set_destroy_func(plugin, l_time_destroy);
    globus_ftp_client_plugin_set_connect_func(plugin, l_time_connect);
    globus_ftp_client_plugin_set_get_func(plugin, l_time_get);
    globus_ftp_client_plugin_set_put_func(plugin, l_time_put);
    globus_ftp_client_plugin_set_third_party_transfer_func(
        plugin, l_time_third_party_transfer);
    globus_ftp_client_plugin_set_authenticate_func(plugin, l_time_authenticate);
    globus_ftp_client_plugin_set_response_func(plugin, l_time_response);
    globus_ftp_client_plugin_set_fault_func(plugin, l_time_fault);
    globus_ftp_client_plugin_set_complete_func(plugin, l_time_complete);

    return GLOBUS_SUCCESS;
}

GlobusExtensionDefineModule(guc_time) =
{
    "guc_time",
    l_time_plugin_activate,
    l_time_plugin_deactivate,
    NULL,
    NULL,
    NULL
};

static
int
l_time_plugin_activate(void)
{
    int                                 rc;

    rc = globus_extension_registry_add(
        &globus_guc_client_plugin_registry,
        L_TIME_PLUGIN_NAME "_funcs",
        GlobusExtensionMyModule(guc_time),
        &l_my_guc_plugin);

    return rc;
}

static
int
l_time_plugin_deactivate(void)
{
    return 0;
}

