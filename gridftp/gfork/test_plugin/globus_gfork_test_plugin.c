#include "globus_common.h"
#include "globus_gfork.h"

#define GFORK_NAME "globus_gfork_test_plugin"

#define B_SIZE 32


typedef struct gfork_test_plugin_handle_s
{
    globus_xio_handle_t                 read_handle;
    globus_xio_handle_t                 write_handle;
    globus_byte_t                       buffer[B_SIZE];
    int                                 ref;
} gfork_test_plugin_handle_t;

static
void
test_res(
    int                                 line,
    globus_result_t                     res)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    printf("Error on line %d\n:%s:", line, globus_error_print_friendly(globus_error_get(res)));
    globus_assert(0);
}


static
void
gfork_test_startup_func(
    void **                             user_arg)
{
    printf("%d) Startup\n", getpid());
}

static void
gfork_test_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfork_test_plugin_handle_t *        handle;
    char *                              msg;

    handle = (gfork_test_plugin_handle_t *) user_arg;

    msg = (char *) handle->buffer;
    printf("parent) %s\n", msg);

    result = globus_xio_write(
        handle->write_handle,
        buffer,
        B_SIZE,
        B_SIZE,
        &nbytes,
        NULL);
    test_res(__LINE__, result);

    handle->ref--;
    if(handle->ref == 0)
    {
        free(handle);
    }
}

static
void
gfork_test_open_func(
    void *                              user_arg,
    globus_gfork_handle_t               gfork_handle,
    void **                             connection_user_arg)
{
    globus_result_t                     result;
    gfork_test_plugin_handle_t *        handle;

    printf("%d) Open\n", getpid());

    handle = (gfork_test_plugin_handle_t *) globus_calloc(1,
        sizeof(gfork_test_plugin_handle_t));

    result = globus_gfork_get_xio(
        gfork_handle, &handle->read_handle, &handle->write_handle);
    globus_assert(result == GLOBUS_SUCCESS);
    globus_assert(handle->read_handle != NULL);
    globus_assert(handle->write_handle != NULL);

    handle->ref = 2;
    result = globus_xio_register_read(
        handle->read_handle,
        handle->buffer,
        B_SIZE,
        B_SIZE,
        NULL,
        gfork_test_read_cb,
        handle);
    test_res(__LINE__, result);

    *connection_user_arg = handle;
}

static
void
gfork_test_closed_func(
    void *                              user_arg,
    globus_gfork_handle_t               gfork_handle,
    void *                              connection_user_arg)
{
    gfork_test_plugin_handle_t *        handle;

    handle = (gfork_test_plugin_handle_t *) connection_user_arg;
    printf("%d) Close\n", getpid());

    handle->ref--;
    if(handle->ref == 0)
    {
        free(connection_user_arg);
    }
}

static
void
gfork_test_shutdown_func(
    void *                              user_arg)
{
    printf("%d) Shutdown\n", getpid());
}


globus_gfork_module_t                   test_gfork = 
{
    gfork_test_startup_func,
    gfork_test_open_func,
    gfork_test_closed_func,
    gfork_test_shutdown_func
};

static
int
gfork_test_l_activate();

static
int
gfork_test_l_deactivate();

GlobusExtensionDefineModule(GFORK_NAME) =
{
    GFORK_NAME,
    gfork_test_l_activate,
    gfork_test_l_deactivate,
    NULL,
    NULL,
    NULL
};

static
int
gfork_test_l_activate()
{
    int                                 rc;

    rc = globus_extension_registry_add(
        &gfork_i_plugin_registry,
        GFORK_NAME,
        GlobusExtensionMyModule(GFORK_NAME),
        &test_gfork);

    return rc;
}

static
int
gfork_test_l_deactivate()
{
    globus_extension_registry_remove(&gfork_i_plugin_registry, GFORK_NAME);

    return 0;
}





