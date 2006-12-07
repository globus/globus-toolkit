#include "globus_gfork.h"
#include "errno.h"
#include <sys/types.h>
#include <sys/wait.h>

#define MESSAGE "HELLO GFORK"
#define B_SIZE  32

static globus_mutex_t                   g_mutex;
static globus_cond_t                    g_cond;
static globus_bool_t                    g_done;
static globus_xio_handle_t              g_write_h;
static globus_xio_handle_t              g_read_h;
static globus_byte_t                    g_buffer[B_SIZE];

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

    fprintf(stderr, "%d) Error on line %d\n:%s:", getpid(), line, globus_error_print_friendly(globus_error_get(res)));

    fflush(stderr);
    sleep(1);
    globus_assert(0);
}

static void
gfork_test_ap_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    printf("Child) \n");
        exit(0);
}

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 rc;
    globus_result_t                     result;
    globus_size_t                       nbytes;

    rc = globus_module_activate(GLOBUS_GFORK_CHILD_MODULE);
    globus_assert(rc == 0);

    globus_mutex_init(&g_mutex, NULL);
    globus_cond_init(&g_cond, NULL);
    g_done = GLOBUS_FALSE;

    result = globus_gfork_child_get_xio(&g_read_h, &g_write_h);
    test_res(__LINE__, result);

    memcpy(g_buffer, MESSAGE, strlen(MESSAGE));

    globus_mutex_lock(&g_mutex);
    {    
        result = globus_xio_write(
            g_write_h,
            g_buffer,
            B_SIZE,
            B_SIZE,
            &nbytes,
            NULL);
        test_res(__LINE__, result);

        result = globus_xio_register_read(
            g_read_h,
            g_buffer,
            B_SIZE,
            B_SIZE,
            NULL,
            gfork_test_ap_read_cb,
            NULL);
        test_res(__LINE__, result);
    
        while(!g_done)
        {
            globus_cond_wait(&g_cond, &g_mutex);
        }
    }
    globus_mutex_unlock(&g_mutex);

    return 0;
}
