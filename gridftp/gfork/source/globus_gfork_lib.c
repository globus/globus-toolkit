#include "globus_i_gfork.h"
#include "version.h"

#define GFORK_CHILD_READ_ENV "GFORK_CHILD_READ_ENV"
#define GFORK_CHILD_WRITE_ENV "GFORK_CHILD_WRITE_ENV"

globus_xio_stack_t                      gfork_i_tcp_stack;
globus_xio_attr_t                       gfork_i_tcp_attr;
globus_xio_driver_t                     gfork_i_tcp_driver;
globus_xio_stack_t                      gfork_i_file_stack;
globus_xio_attr_t                       gfork_i_file_attr;
globus_xio_driver_t                     gfork_i_file_driver;
globus_extension_registry_t             gfork_i_plugin_registry;

static globus_bool_t                    gfork_l_globals_set = GLOBUS_FALSE;
static int                              gfork_l_read_fd = -1;
static int                              gfork_l_write_fd = -1;
static globus_xio_handle_t              gfork_l_read_handle = NULL;
static globus_xio_handle_t              gfork_l_write_handle = NULL;

GlobusDebugDefine(GLOBUS_GFORK);

globus_result_t
globus_gfork_get_fd(
    globus_gfork_handle_t               handle,
    int *                               read_fd,
    int *                               write_fd)
{
    if(read_fd != NULL)
    {
        *read_fd = handle->read_fd;
    }
    if(write_fd != NULL)
    {
        *write_fd = handle->write_fd;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gfork_get_xio(
    globus_gfork_handle_t               handle,
    globus_xio_handle_t *               read_xio_handle,
    globus_xio_handle_t *               write_xio_handle)
{
    if(read_xio_handle != NULL)
    {
        *read_xio_handle = handle->read_xio_handle;
    }
    if(write_xio_handle != NULL)
    {
        *write_xio_handle = handle->write_xio_handle;
    }

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_get_env_fd(
    char *                              env,
    int *                               out_fd)
{
    globus_result_t                     res;
    char *                              tmp_str;
    int                                 sc;
    int                                 fd;
    GForkFuncName(gfork_l_get_env_fd);

    tmp_str = globus_libc_getenv(env);
    if(tmp_str == NULL)
    {
        res = GForkErrorStr("Env not set");
        goto error_env;
    }
    sc = sscanf(tmp_str, "%d", &fd);
    if(sc != 1)
    {
        res = GForkErrorStr("Env not and integer");
        goto error_scan;
    }

    *out_fd = fd;

    return GLOBUS_SUCCESS;

error_scan:
error_env:

    return res; 
}

globus_result_t
globus_gfork_child_get_fd(
    int *                               read_fd,
    int *                               write_fd)
{
    globus_result_t                     result;
    GForkFuncName(globus_gfork_child_get_fd);

    if(read_fd != NULL)
    {
        if(gfork_l_read_fd == -1)
        {
            result = GForkErrorStr("No read handle set");
            goto error;
        }
        *read_fd = gfork_l_read_fd;
    }
    if(write_fd != NULL)
    {
        if(gfork_l_write_fd == -1)
        {
            result = GForkErrorStr("No write handle set");
            goto error;
        }
        *write_fd = gfork_l_write_fd;
    }

    return GLOBUS_SUCCESS;

error:

    return result;
}

globus_result_t
gfork_i_make_xio_handle(
    globus_xio_handle_t *               xio_handle,
    int                                 fd)
{
    globus_result_t                     res;
    globus_xio_attr_t                   attr;
    globus_xio_handle_t                 handle;

    res = globus_xio_attr_copy(&attr, gfork_i_file_attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_copy;
    }
    res = globus_xio_attr_cntl(attr, gfork_i_file_driver,
        GLOBUS_XIO_FILE_SET_HANDLE, fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }

    res = globus_xio_handle_create(&handle, gfork_i_file_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_create;
    }

    /* the way the stack is set up xio should not poll. */
    res = globus_xio_open(
        handle,
        NULL,
        attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    globus_xio_attr_destroy(attr);
    *xio_handle = handle;

    return GLOBUS_SUCCESS;
error_open:
error_create:
error_attr:
    globus_xio_attr_destroy(attr);
error_copy:
    return res;
}

globus_result_t
globus_gfork_child_get_xio(
    globus_xio_handle_t *               read_xio_handle,
    globus_xio_handle_t *               write_xio_handle)
{
    globus_result_t                     result;
    GForkFuncName(globus_gfork_child_get_xio);

    if(read_xio_handle != NULL)
    {
        if(gfork_l_read_fd == -1 || gfork_l_read_handle == NULL)
        {
            result = GForkErrorStr("No read handle set");
            goto error;
        }
        *read_xio_handle = gfork_l_read_handle;
    }
    if(write_xio_handle != NULL)
    {
        if(gfork_l_write_fd == -1 || gfork_l_write_handle == NULL)
        {
            result = GForkErrorStr("No write handle set");
            goto error;
        }
        *write_xio_handle = gfork_l_write_handle;
    }

    return GLOBUS_SUCCESS;

error:

    return result;
}

static
int
gfork_l_activate()
{
    int                                 rc;
    globus_result_t                     res;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != 0)
    {
        goto error_activate;
    }

    if(!gfork_l_globals_set)
    {
        GlobusDebugInit(GLOBUS_GFORK,
            ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);


        gfork_i_state_init();

        res = globus_xio_stack_init(&gfork_i_tcp_stack, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_tcp_stack;
        }
        res = globus_xio_driver_load("tcp", &gfork_i_tcp_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_tcp_driver;
        }
        res = globus_xio_stack_push_driver(
            gfork_i_tcp_stack, gfork_i_tcp_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_tcp_push;
        }
        globus_xio_attr_init(&gfork_i_tcp_attr);
        res = globus_xio_attr_cntl(
            gfork_i_tcp_attr,
            gfork_i_tcp_driver,
            GLOBUS_XIO_TCP_SET_REUSEADDR,
            GLOBUS_TRUE);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_tcp_attr;
        }
        /* set whatever other default attrs */

        res = globus_xio_stack_init(&gfork_i_file_stack, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_stack;
        }
        res = globus_xio_driver_load("file", &gfork_i_file_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_driver;
        }
        res = globus_xio_stack_push_driver(
            gfork_i_file_stack, gfork_i_file_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_push;
        }
        globus_xio_attr_init(&gfork_i_file_attr);

    }
    gfork_l_globals_set = GLOBUS_TRUE;

    return 0;
error_file_push:
    globus_xio_driver_unload(gfork_i_file_driver);
error_file_driver:
    globus_xio_stack_destroy(gfork_i_file_stack);
error_file_stack:
error_tcp_attr:
    globus_xio_attr_destroy(gfork_i_tcp_attr);
error_tcp_push:
    globus_xio_driver_unload(gfork_i_tcp_driver);
error_tcp_driver:
    globus_xio_stack_destroy(gfork_i_tcp_stack);
error_tcp_stack:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
error_activate:
    return 1;
}

static int
gfork_l_parent_activate()
{
    int                                 rc;

    rc = gfork_l_activate();
    if(rc != 0)
    {
        goto error_activate;
    }

    return 0;

error_activate:
    return 1;
}


static int
gfork_l_child_activate()
{
    globus_result_t                     res;
    int                                 rc;

    rc = gfork_l_activate();
    if(rc != 0)
    {
        goto error_activate;
    }

    res = gfork_l_get_env_fd(GFORK_CHILD_READ_ENV, &gfork_l_read_fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_handles;
    }
    res = gfork_i_make_xio_handle(&gfork_l_read_handle, gfork_l_read_fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_handles;
    }
    res = gfork_l_get_env_fd(GFORK_CHILD_WRITE_ENV, &gfork_l_write_fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_handles;
    }
    res = gfork_i_make_xio_handle(&gfork_l_write_handle, gfork_l_write_fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_handles;
    }

    return 0;

error_handles:
error_activate:
    return 1;
}

static int
gfork_l_deactivate()
{
    if(gfork_l_read_fd != -1)
    {
        close(gfork_l_read_fd);
        if(gfork_l_read_handle != NULL)
        {
            globus_xio_close(gfork_l_read_handle, NULL);
        }
    }
    if(gfork_l_write_fd != -1)
    {
        close(gfork_l_write_fd);
        if(gfork_l_write_handle != NULL)
        {
            globus_xio_close(gfork_l_write_handle, NULL);
        }
    }

    gfork_l_read_fd = -1;
    gfork_l_write_fd = -1;
    gfork_l_read_handle = NULL;
    gfork_l_write_handle = NULL;

    globus_xio_stack_destroy(gfork_i_tcp_stack);
    globus_xio_driver_unload(gfork_i_tcp_driver);
    globus_xio_attr_destroy(gfork_i_tcp_attr);

    gfork_l_globals_set = GLOBUS_FALSE;

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}

globus_module_descriptor_t              globus_i_gfork_parent_module =
{
    "globus_gfork",
    gfork_l_parent_activate,
    gfork_l_deactivate,
    NULL,
    NULL,
    &local_version
};

globus_module_descriptor_t              globus_i_gfork_child_module =
{
    "globus_gfork",
    gfork_l_child_activate,
    gfork_l_deactivate,
    NULL,
    NULL,
    &local_version
};

