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

#include "gfs_advertiser.h"

#define RESOURCE_NAME "frontendInfo"

#define GFSADError(error_msg, _type)                                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _gfs_ad_gfork_func_name,                                           \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GFSGForkFuncName(func) static const char * _gfs_ad_gfork_func_name __attribute__((__unused__)) = #func
#else
#define GFSGForkFuncName(func) static const char * _gfs_ad_gfork_func_name = #func
#endif


static globus_mutex_t                   g_mutex;
static globus_cond_t                    g_cond;
static globus_bool_t                    g_done = GLOBUS_FALSE;
static FILE *                           g_log_fptr;
static int                              g_log_level = 16;
static gfork_child_handle_t             g_handle;
static int                              g_connection_count = 0;
static int                              g_port = 0;
static char *                           g_epr_filename = "/tmp/epr_file";

static
globus_result_t
gfsad_l_master_opts_unknown(
    globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv);

static
globus_result_t
gfsad_l_master_options(
    int                                 argc,
    char **                             argv);

static
void
gfsad_l_log(
    globus_result_t                     result,
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(g_log_fptr == NULL)
    {
        return;
    }
    va_start(ap, fmt);

    fprintf(g_log_fptr, "[gridftp advertiser plugin] : ");
    if(result != GLOBUS_SUCCESS)
    {
        char * err_str = globus_error_print_friendly(
            globus_error_peek(result));

        fprintf(g_log_fptr, "ERROR : %s : ", err_str);
        globus_free(err_str);
    }
    vfprintf(g_log_fptr, fmt, ap);
    va_end(ap);
    fflush(g_log_fptr);
}

static
globus_result_t
gfsad_l_write_epr(
    wsa_EndpointReferenceType *         epr,
    const char *                        epr_filename)
{
    globus_result_t                     result;

    result = globus_wsrf_core_export_endpoint_reference(
        epr,
        epr_filename,
        &wsa_EndpointReference_qname);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return GLOBUS_SUCCESS;

error:
    printf("error writting\n");
    return result;
}


static
void
gfsad_l_open_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid)
{
    gfsad_l_log(
        GLOBUS_SUCCESS, 2, "Open called for pid %d\n", from_pid);

    globus_mutex_lock(&g_mutex);
    {
        g_connection_count++;
    }
    globus_mutex_unlock(&g_mutex);
}

static
void
gfsad_l_closed_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid)
{
    globus_mutex_lock(&g_mutex);
    {
        g_connection_count--;
    }
    globus_mutex_unlock(&g_mutex);
}

static
void
gfsad_l_incoming_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
}

static
void
gfsad_l_engine_stop_callback(
    globus_result_t                     result,
    globus_service_engine_t             engine,
    void *                              args)
{
}

void
gridftpA_l_fe_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property)
{
    gridftp_advertise_frontendInfoType * fe;
    int                                 tmp_i;
    time_t                              now = time(NULL);
    xsd_dateTime *                      now_tm;

    now_tm = gmtime(&now);

    gridftp_advertise_frontendInfoType_init(&fe);

    fe->contactString = globus_libc_strdup("contactString");
    fe->banner = globus_libc_strdup("banner");
    fe->maxConnections = 0;

    globus_mutex_lock(&g_mutex);
    {
        tmp_i = g_connection_count;
    }
    globus_mutex_unlock(&g_mutex);

    fe->openConnections = (xsd_int) tmp_i;
    wsrl_CurrentTimeType_init_contents(&fe->CurrentTime);
    xsd_dateTime_copy_contents(&fe->CurrentTime.base_value, now_tm);


    *property = fe;
}

/* maynot externally set this */
globus_bool_t
gridftpA_l_fe_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property)
{
    return GLOBUS_FALSE;
}


static globus_result_t
gfsad_l_create_resource(
    globus_service_engine_t             engine)
{
    wsa_EndpointReferenceType           epr;
    globus_result_t                     result;
    xsd_any *                           reference_properties;
    char *                              name = RESOURCE_NAME;
    globus_resource_t                   resource = NULL;
    GlobusGFSName(gridftp_admin_l_create_resource);

    result = globus_resource_find(
        name,
        &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_wsrf_core_create_endpoint_reference(
        engine,
        GRIDFTPADVERTISESERVICE_BASE_PATH,
        NULL,
        &epr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_resource;
    }

    result = globus_resource_create_property_callback(
        resource,
        &gridftp_advertise_frontendInfo_qname,
        &gridftp_advertise_frontendInfoType_info,
        gridftpA_l_fe_get_cb,
        gridftpA_l_fe_set_cb,
        "gridftp_advertise_frontendInfoType");
    if (result != GLOBUS_SUCCESS)
    {
        goto error_epr;
    }

    result = gfsad_l_write_epr(&epr, g_epr_filename);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_epr;
    }

error_epr:
    wsa_EndpointReferenceType_destroy_contents(&epr);
error_resource:
    globus_resource_finish(resource);
error:

    return result;
}

static globus_result_t
gfsad_init()
{
    globus_result_t                     result;
    char *                              pc = NULL;
    globus_bool_t                       secure = GLOBUS_TRUE;
    globus_service_engine_t             engine;
    char *                              real_pc;
    int                                 rc;

    result = globus_module_activate(GLOBUS_SERVICE_ENGINE_MODULE);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_service_engine_init(
        &engine,
        NULL,
        pc,
        NULL,
        secure);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
    result = globus_service_engine_get_contact(engine, &real_pc);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_engine_destroy;
    }

    result = globus_service_engine_register_start(
        engine,
        gfsad_l_engine_stop_callback,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }
    rc = globus_extension_activate(
            GLOBUS_SERVICE_ENGINE_MODULE_PATH_PREFIX "/"
            GRIDFTPADVERTISESERVICE_BASE_PATH);
    if(rc != 0)
    {
        goto error_pc_free;
    }

    result = gfsad_l_create_resource(engine);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }

    /* print out real */
    gfsad_l_log(
        GLOBUS_SUCCESS, 1, "GridFTP Server Advertising at: %s\n", real_pc);

    return GLOBUS_SUCCESS;

error_pc_free:
    free(real_pc);
error_engine_destroy:
    globus_service_engine_destroy(engine);
error_deactivate:
    globus_module_deactivate(GLOBUS_SERVICE_ENGINE_MODULE);
error:
    gfsad_l_log(result, 1, "Error starting WSRF service");

    return result;

}

static void
timer_cb(void * arg)
{
    globus_mutex_lock(&g_mutex);
    {
        g_connection_count++;
    }
    globus_mutex_unlock(&g_mutex);
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_result_t                     result;
    int                                 rc;

    rc = globus_module_activate(GLOBUS_GFORK_CHILD_MODULE);
    if(rc != 0)
    {
        goto error_activate;
    }
    rc = globus_module_activate(GLOBUS_WSRF_RESOURCE_MODULE);
    rc = globus_module_activate(GLOBUS_OPERATION_PROVIDER_MODULE);

    result = gfsad_l_master_options(argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_opts;
    }

    globus_mutex_init(&g_mutex, NULL);
    globus_cond_init(&g_cond, NULL);
    g_done = GLOBUS_FALSE;

    /*
    {
        globus_reltime_t                    period;

        GlobusTimeReltimeSet(period, 5, 0);
        globus_callback_register_periodic(
            NULL,
            &period,
            &period,
            timer_cb,
            NULL);
    }
    */

    globus_mutex_lock(&g_mutex);
    {
        result = gfsad_init();
        if(result != GLOBUS_SUCCESS)
        {
            goto error_start;
        }

        result = globus_gfork_child_master_start(
            &g_handle,
            NULL,
            gfsad_l_open_cb,
            gfsad_l_closed_cb,
            gfsad_l_incoming_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_start;
        }

        while(!g_done)
        {
            globus_cond_wait(&g_cond, &g_mutex);
        }
    }
    globus_mutex_unlock(&g_mutex);

    return 0;

error_start:
    globus_mutex_unlock(&g_mutex);
error_opts:
error_activate:
    gfsad_l_log(result, 0, "\n");

    return 1;
}

static
globus_result_t
gfsad_l_opts_eprfilename(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    GFSGForkFuncName(gfsad_l_opts_eprfilename);

    g_epr_filename = opt[0];
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}


static
globus_result_t
gfsad_l_opts_logfile(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    FILE *                              fptr;
    GFSGForkFuncName(gfsad_l_opts_logfile);

    if(strncmp("-", opt[0], 1) == 0)
    {
        fptr = stdout;
    }
    else
    {
        fptr = fopen(opt[0], "a");
        if(fptr == NULL)
        {
            *out_parms_used = 0;
            return GFSADError("Bad logfile", 0);
        }
    }

    g_log_fptr = fptr;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfsad_l_opts_log_level(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 l;
    GFSGForkFuncName(gfsad_l_opts_log_level);

    sc = sscanf(opt[0], "%d", &l);
    if(sc != 1)
    {
        *out_parms_used = 0;
        return GFSADError("non integer value passed as a log level", 0);
    }

    g_log_level = l;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}


static
globus_result_t
gfsad_l_opts_port(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 p;
    GFSGForkFuncName(gfsad_l_opts_port);

    sc = sscanf(opt[0], "%d", &p);
    if(sc != 1)
    {
        *out_parms_used = 0;
        return GFSADError("non integer value passed as a port", 0);
    }

    g_port = p;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}



static
globus_result_t
gfsad_l_opts_help(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_options_help(opts_handle);

    printf("This program should be executed from gfork only.  It is "
        "not intended to be a stand alone program.\n");
    exit(0);
    return GLOBUS_SUCCESS;
}

static globus_options_entry_t                   gfsad_l_opts_table[] =
{
    {"eprfile", "e", NULL, NULL,
        "set the location of the epr file",
        1, gfsad_l_opts_eprfilename},
    {"logfile", "l", NULL, NULL,
        "set the logfile",
        1, gfsad_l_opts_logfile},
    {"loglevel", "d", NULL, NULL,
        "set the log level",
        1, gfsad_l_opts_log_level},
    {"port", "p", NULL, NULL,
        "set the port that where wsrf communication can occur",
        1, gfsad_l_opts_port},
    {"help", "h", NULL, NULL,
        "print the help message",
        0, gfsad_l_opts_help},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

static
globus_result_t
gfsad_l_master_opts_unknown(
    globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "gfs_lgfork_master_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}



static
globus_result_t
gfsad_l_master_options(
    int                                 argc,
    char **                             argv)
{
    globus_options_handle_t             opt_h;
    globus_result_t                     result;
    char *                              env_s;
    
    GFSGForkFuncName(gfs_gfork_master_options);

    globus_options_init(
        &opt_h, gfsad_l_master_opts_unknown, NULL);
    globus_options_add_table(opt_h, gfsad_l_opts_table, NULL);
    result = globus_options_command_line_process(opt_h, argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    env_s = globus_libc_getenv(GFORK_CHILD_INSTANCE_ENV);
    if(env_s == NULL)
    {
        result = GFSADError(
            "GFork environment: GFORK_CHILD_INSTANCE_ENV not proeprly set."
            "  Was this program sarted from gfork?",
            0);
        goto error;
    }


    return GLOBUS_SUCCESS;
error:
    return result;
}

