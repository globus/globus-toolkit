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
 * @file globus_ftp_client_throughput_nl_plugin.c GridFTP Netlogger Throughput Plugin
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 * $Author$
 */

#include "globus_ftp_client_throughput_nl_plugin.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static globus_bool_t globus_l_ftp_client_throughput_nl_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_throughput_nl_plugin_deactivate(void);

globus_module_descriptor_t globus_i_ftp_client_throughput_nl_plugin_module =
{
    "globus_ftp_client_throughput_nl_plugin",
    globus_l_ftp_client_throughput_nl_plugin_activate,
    globus_l_ftp_client_throughput_nl_plugin_deactivate,
    GLOBUS_NULL
};

static
int
globus_l_ftp_client_throughput_nl_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_THROUGHPUT_PLUGIN_MODULE);
    return rc;
}

static
int
globus_l_ftp_client_throughput_nl_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_THROUGHPUT_PLUGIN_MODULE);
}

typedef struct throughput_nl_plugin_info_s
{
    globus_ftp_client_throughput_plugin_begin_cb_t      begin_cb;
    globus_ftp_client_throughput_plugin_stripe_cb_t     per_stripe_cb;
    globus_ftp_client_throughput_plugin_total_cb_t      total_cb;
    globus_ftp_client_throughput_plugin_complete_cb_t   complete_cb;
    void *                                              user_specific;

    char *                                          opaque_string;
    char *                                          source_url;
    char *                                          dest_url;
    NLhandle *                                      nl_handle;
    globus_bool_t                                   destroy_handle;
} throughput_nl_plugin_info_t;

static
void throughput_plugin_begin_cb(
    void *                                          user_arg,
    globus_ftp_client_handle_t *                    handle,
    const char *                                    source_url,
    const char *                                    dest_url)
{
    throughput_nl_plugin_info_t *                   info;

    info = (throughput_nl_plugin_info_t *) user_arg;

    if(info->source_url)
    {
        globus_libc_free(info->source_url);
        info->source_url = GLOBUS_NULL;
    }

    if(info->dest_url)
    {
        globus_libc_free(info->dest_url);
        info->dest_url = GLOBUS_NULL;
    }

    if(source_url)
    {
        info->source_url = globus_libc_strdup(source_url);
    }

    if(dest_url)
    {
        info->dest_url = globus_libc_strdup(dest_url);
    }

    NetLoggerWrite(info->nl_handle, "TransferBegin",
        info->opaque_string,
        "URL.SOURCE=%s URL.DEST=%s",
        (info->source_url) ? info->source_url : "",
        (info->dest_url) ? info->dest_url : "");

    if(info->begin_cb)
    {
        info->begin_cb(
            info->user_specific,
            handle,
            source_url,
            dest_url);
    }
}

static
void throughput_plugin_stripe_cb(
    void *                                          user_arg,
    globus_ftp_client_handle_t *                    handle,
    int                                             stripe_ndx,
    globus_off_t                                    bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput)
{
    throughput_nl_plugin_info_t *                   info;

    info = (throughput_nl_plugin_info_t *) user_arg;

    NetLoggerWrite(info->nl_handle, "TransferPerfStripe",
        info->opaque_string,
        "URL.SOURCE=%s URL.DEST=%s "
        "INDEX=%d BYTES=%" GLOBUS_OFF_T_FORMAT " BW.CURRENT=%.3f BW.AVG=%.3f",
        (info->source_url) ? info->source_url : "",
        (info->dest_url) ? info->dest_url : "",
        stripe_ndx,
        bytes,
        instantaneous_throughput,
        avg_throughput);

    if(info->per_stripe_cb)
    {
        info->per_stripe_cb(
            info->user_specific,
            handle,
            stripe_ndx,
            bytes,
            instantaneous_throughput,
            avg_throughput);
    }
}

static
void throughput_plugin_total_cb(
    void *                                          user_arg,
    globus_ftp_client_handle_t *                    handle,
    globus_off_t                                    bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput)
{
    throughput_nl_plugin_info_t *                   info;

    info = (throughput_nl_plugin_info_t *) user_arg;

    NetLoggerWrite(info->nl_handle, "TransferPerfTotal",
        info->opaque_string,
        "URL.SOURCE=%s URL.DEST=%s "
        "BYTES=%" GLOBUS_OFF_T_FORMAT " BW.CURRENT=%.3f BW.AVG=%.3f",
        (info->source_url) ? info->source_url : "",
        (info->dest_url) ? info->dest_url : "",
        bytes,
        instantaneous_throughput,
        avg_throughput);

    if(info->total_cb)
    {
        info->total_cb(
            info->user_specific,
            handle,
            bytes,
            instantaneous_throughput,
            avg_throughput);
    }
}

static
void throughput_plugin_complete_cb(
    void *                                          user_arg,
    globus_ftp_client_handle_t *                    handle,
    globus_bool_t                                   success)
{
    throughput_nl_plugin_info_t *                   info;

    info = (throughput_nl_plugin_info_t *) user_arg;

    if(info->source_url)
    {
        globus_libc_free(info->source_url);
        info->source_url = GLOBUS_NULL;
    }

    if(info->dest_url)
    {
        globus_libc_free(info->dest_url);
        info->dest_url = GLOBUS_NULL;
    }

    NetLoggerWrite(info->nl_handle, "TransferEnd",
        info->opaque_string,
        "SUCCESS=%d",
        (success) ? 1 : 0);

    if(info->complete_cb)
    {
        info->complete_cb(
            info->user_specific,
            handle,
            success);
    }
}

static
void *
throughput_plugin_user_copy_cb(
    void *                                          user_specific)
{
    throughput_nl_plugin_info_t *                   old_info;
    throughput_nl_plugin_info_t *                   new_info;

    old_info = (throughput_nl_plugin_info_t *) user_specific;

    new_info = (throughput_nl_plugin_info_t *)
        globus_malloc(sizeof(throughput_nl_plugin_info_t));

    if(new_info == GLOBUS_NULL)
    {
        return GLOBUS_NULL;
    }

    new_info->opaque_string     = old_info->opaque_string;
    new_info->nl_handle         = old_info->nl_handle;

    new_info->source_url        = GLOBUS_NULL;
    new_info->dest_url          = GLOBUS_NULL;

    return new_info;
}

static
void
throughput_plugin_user_destroy_cb(
    void *                                          user_specific)
{
    throughput_nl_plugin_info_t *                   info;

    info = (throughput_nl_plugin_info_t *) user_specific;

    globus_free(info);
}

#endif  /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Initialize netlogger wrapped throughput plugin
 * @ingroup globus_ftp_client_throughput_nl_plugin
 *
 * This will initialize a netlogger wrapped throughput plugin.  Note
 * that the nl_url may be NULL.
 * Regardless of what nl_host is set to, if the env variable NL_DEST_ENV
 * is set, logging will always occur to that location.
 *
 * @param plugin
 *        a plugin to be initialized
 *
 * @param nl_url
 *        the url to log to (May be NULL)
 *        Valid urls are:
 *          file://tmp/netlog.log
 *          x-netlog://host[:port]
 *          x-syslog://localhost
 *
 * @param prog_name
 *        This is used as the prog name in the NetLoggerOpen call
 *
 * @param opaque_string
 *        this is an opaque string that will be inserted into all logged
 *        statements. (may be NULL)
 *
 * @return
 *        - Error on NULL plugin or failure to init throughput plugin
 *        - Error on NetLogger open
 *        - GLOBUS_SUCCESS
 */

globus_result_t
globus_ftp_client_throughput_nl_plugin_init(
    globus_ftp_client_plugin_t *			plugin,
    const char *                                        nl_url,
    const char *                                        prog_name,
    const char *                                        opaque_string)
{
    globus_result_t                                     result;
    NLhandle *                                          nl_handle;
    throughput_nl_plugin_info_t *                       info;
    GlobusFuncName(globus_ftp_client_throughput_nl_plugin_init);

    if(nl_url)
    {
        nl_handle = NetLoggerOpen((char *)prog_name, (char *)nl_url, 0);
    }
    else
    {
        nl_handle = NetLoggerOpen((char *)prog_name, NULL, NL_ENV);
    }

    if(nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                                GLOBUS_FTP_CLIENT_MODULE,
                                GLOBUS_NULL,
                                "[%s] Could not open NetLogger handle %s\n",
                                 GLOBUS_FTP_CLIENT_MODULE->module_name,
                                 _globus_func_name));
    }

    result = globus_ftp_client_throughput_nl_plugin_init_with_handle(
        plugin,
        nl_handle,
        opaque_string);

    if(result == GLOBUS_SUCCESS)
    {
        globus_ftp_client_throughput_plugin_get_user_specific(
            plugin,
            (void **) &info);
        info->destroy_handle = GLOBUS_TRUE;
    }
    else
    {
        NetLoggerClose(nl_handle);
    }

    return result;
}

/**
 * Initialize netlogger wrapped throughput plugin
 * @ingroup globus_ftp_client_throughput_nl_plugin
 *
 * This will initialize a netlogger wrapped throughput plugin.  Instead
 * of passing a NetLogger url as in the plain init func, you can pass in
 * a previously 'Open'ed NLhandle.  This handle will not be destroyed by
 * this plugin.
 *
 * @param plugin
 *        a plugin to be initialized
 *
 * @param nl_handle
 *        a previously opened NetLogger handle
 *
 * @param opaque_string
 *        this is an opaque string that will be inserted into all logged
 *        statements. (may be NULL)
 *
 * @return
 *        - Error on NULL plugin or failure to init throughput plugin
 *        - Error on NetLogger open
 *        - GLOBUS_SUCCESS
 */

globus_result_t
globus_ftp_client_throughput_nl_plugin_init_with_handle(
    globus_ftp_client_plugin_t *			plugin,
    NLhandle *                                          nl_handle,
    const char *                                        opaque_string)
{
    throughput_nl_plugin_info_t *                       info;
    globus_result_t                                     result;
    GlobusFuncName(globus_ftp_client_throughput_nl_plugin_init_with_handle);

    if(plugin == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL plugin at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                _globus_func_name));
    }

    if(nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL netlogger handle at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                _globus_func_name));
    }

    info = (throughput_nl_plugin_info_t *)
        globus_malloc(sizeof(throughput_nl_plugin_info_t));

    if(info == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                                GLOBUS_FTP_CLIENT_MODULE,
                                GLOBUS_NULL,
                                "[%s] Out of memory at %s\n",
                                 GLOBUS_FTP_CLIENT_MODULE->module_name,
                                 _globus_func_name));
    }

    result = globus_ftp_client_throughput_plugin_init(
        plugin,
        throughput_plugin_begin_cb,
        throughput_plugin_stripe_cb,
        throughput_plugin_total_cb,
        throughput_plugin_complete_cb,
        info);

    if(result != GLOBUS_SUCCESS)
    {
        globus_free(info);
        return result;
    }

    globus_ftp_client_throughput_plugin_set_copy_destroy(
        plugin,
        throughput_plugin_user_copy_cb,
        throughput_plugin_user_destroy_cb);

    if(opaque_string)
    {
        info->opaque_string = globus_libc_strdup(opaque_string);
    }
    else
    {
        info->opaque_string = GLOBUS_NULL;
    }
    info->source_url    = GLOBUS_NULL;
    info->dest_url      = GLOBUS_NULL;
    info->nl_handle     = nl_handle;
    info->destroy_handle = GLOBUS_FALSE;

    info->begin_cb      = GLOBUS_NULL;
    info->per_stripe_cb = GLOBUS_NULL;
    info->total_cb      = GLOBUS_NULL;
    info->complete_cb   = GLOBUS_NULL;
    info->user_specific = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

/**
 * Destroy netlogger wrapped throughput plugin
 * @ingroup globus_ftp_client_throughput_nl_plugin
 *
 * Frees up memory associated with plugin
 *
 * @param plugin
 *        plugin previously initialized with init (above)
 *
 * @return
 *        - GLOBUS_SUCCESS
 *        - Error on NULL plugin
 */

globus_result_t
globus_ftp_client_throughput_nl_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    globus_result_t                                     result;
    throughput_nl_plugin_info_t *                       info;

    GlobusFuncName(globus_ftp_client_throughput_nl_plugin_destroy);

    if(plugin == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL plugin at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                _globus_func_name));
    }

    result = globus_ftp_client_throughput_plugin_get_user_specific(
              plugin,
              (void **) &info);

    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    if(info->opaque_string)
    {
        globus_libc_free(info->opaque_string);
    }

    if(info->destroy_handle)
    {
        NetLoggerClose(info->nl_handle);
    }

    globus_free(info);

    return globus_ftp_client_throughput_plugin_destroy(plugin);
}


/**
 * Receive throughput callbacks
 * @ingroup globus_ftp_client_throughput_nl_plugin
 *
 * You can still get the automatic netlogging of throughput along with
 * receiving the same throughput callbacks that the throughput plugin
 * provides by using this function to set these callbacks.  Note that
 * the callbacks are defined the same as in the throughput plugin
 *
 * @param begin_cb
 *        the callback to be called upon the start of a transfer
 *
 * @param per_stripe_cb
 *        the callback to be called every time updated throughput info is
 *        available for a given stripe
 *
 * @param total_cb
 *        the callback to be called every time updated throughput info is
 *        available for any stripe
 *
 * @param complete_cb
 *        the callback to be called to indicate transfer completion
 *
 * @param user_specific
 *        a pointer to some user specific data that will be provided to
 *        all callbacks
 *
 * @return
 *        - Error on NULL or invalid plugin
 *        - GLOBUS_SUCCESS
 *
 * @see globus_ftp_client_throughput_plugin
 */

globus_result_t
globus_ftp_client_throughput_nl_plugin_set_callbacks(
    globus_ftp_client_plugin_t *                        plugin,
    globus_ftp_client_throughput_plugin_begin_cb_t      begin_cb,
    globus_ftp_client_throughput_plugin_stripe_cb_t     per_stripe_cb,
    globus_ftp_client_throughput_plugin_total_cb_t      total_cb,
    globus_ftp_client_throughput_plugin_complete_cb_t   complete_cb,
    void *                                              user_specific)
{
    globus_result_t                                     result;
    throughput_nl_plugin_info_t *                       info;
    GlobusFuncName(globus_ftp_client_throughput_nl_plugin_set_callbacks);

    if(plugin == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL plugin at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                _globus_func_name));
    }

    result = globus_ftp_client_throughput_plugin_get_user_specific(
              plugin,
              (void **) &info);

    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    info->begin_cb      = begin_cb;
    info->per_stripe_cb = per_stripe_cb;
    info->total_cb      = total_cb;
    info->complete_cb   = complete_cb;
    info->user_specific = user_specific;

    return GLOBUS_SUCCESS;
}
