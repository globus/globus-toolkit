#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;

void
print_help()
{
    fprintf(stderr, "test <options> \n");
    fprintf(stderr, "--------------------------------------\n");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "    F <failure point> : set failure point\n");
    fprintf(stderr, "    i                 : set inline finish\n");
    fprintf(stderr, "    d                 : delay before finish\n");
    fprintf(stderr, "    s                 : buffer chunk size\n");

    exit(1);
}

void
close_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    test_info_t *                               info;

    info = (test_info_t *) user_arg;

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

void
read_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    test_info_t *                               info;
    globus_result_t                             res;

    info = (test_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        if(len < nbytes)
        {
            failed_exit("read wait for has failed");
        }
        else if(nbytes > len)
        {
            failed_exit("too many bytes were read.");
        }

        info->nread += nbytes;

        if(info->nread >= info->total_read_bytes && !info->read_done)
        {
            info->closed++;
            info->read_done = GLOBUS_TRUE;
            if(info->closed == 2 || info->write_count == 0)
            {
                res = globus_xio_register_close(
                        handle,
                        NULL,
                        close_cb,
                        user_arg);
                test_res(res, __LINE__);
            }
        }
        else if(!info->closed)
        {
            res = globus_xio_register_read(
                    handle,
                    info->buffer,
                    info->buffer_length,
                    info->buffer_length,
                    NULL,
                    read_cb,
                    user_arg);
            test_res(res, __LINE__);
        }
    }
    globus_mutex_unlock(&info->mutex);
}

void
write_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    test_info_t *                               info;
    globus_result_t                             res;

    info = (test_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        if(len < nbytes)
        {
            failed_exit("write wait for has failed");
        }
        else if(nbytes > len)
        {
            failed_exit("too many bytes were written.");
        }

        info->nwritten += nbytes;

        if(info->nwritten >= info->total_write_bytes && !info->write_done)
        {
            info->closed++;
            info->write_done = GLOBUS_TRUE;
            if(info->closed == 2 || info->read_count == 0)
            {
                res = globus_xio_register_close(
                        handle,
                        NULL,
                        close_cb,
                        user_arg);
                test_res(res, __LINE__);
            }
        }
        else if(!info->closed)
        {
            res = globus_xio_register_write(
                    handle,
                    info->buffer,
                    info->buffer_length,
                    info->buffer_length,
                    NULL,
                    write_cb,
                    user_arg);
            test_res(res, __LINE__);
        }
    }
    globus_mutex_unlock(&info->mutex);
}

void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    int                                         ctr;
    test_info_t *                               info;

    info = (test_info_t *) user_arg;

    for(ctr = 0; ctr < info->write_count; ctr++)
    {
        res = globus_xio_register_write(
                handle,
                info->buffer,
                info->buffer_length,
                info->buffer_length,
                NULL,
                write_cb,
                user_arg);
        test_res(res, __LINE__);
    }

    for(ctr = 0; ctr < info->read_count; ctr++)
    {
        res = globus_xio_register_read(
                handle,
                info->buffer,
                info->buffer_length,
                info->buffer_length,
                NULL,
                read_cb,
                user_arg);
        test_res(res, __LINE__);
    }

}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_driver_t                     driver;
    globus_xio_target_t                     target;
    globus_xio_attr_t                       attr;
    globus_result_t                         res;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);


    driver = globus_xio_driver_test_transport_get_driver();

    res = globus_xio_attr_init(&attr);
    test_res(res, __LINE__);

    parse_parameters(argc, argv, driver, attr);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(res, __LINE__);

    res = globus_xio_stack_push_driver(stack, driver);
    test_res(res, __LINE__);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(res, __LINE__);

    res = globus_xio_register_open(
            &handle,
            attr,
            target,
            open_cb,
            (void *)&globus_l_test_info);
    test_res(res, __LINE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
