#include "globus_xio.h"
#include "globus_common.h"
#include "globus_xio_test_transport.h"

static int                                  globus_l_argc;
static char **                              globus_l_argv;
static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;

void
print_help()
{
    fprintf(stderr, "%s <options> \n", globus_l_argv[0]);
    fprintf(stderr, "--------------------------------------\n");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "    F <failure point> : set failure point\n");
    fprintf(stderr, "    i                 : set inline finish\n");
    fprintf(stderr, "    d                 : delay before finish\n");
    fprintf(stderr, "    s                 : buffer chunk size\n");

    exit(1);
}

void
test_res(
    globus_result_t                         res,
    int                                     line)
{
    if(res != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "error at line %d.\n", line);
        globus_assert(res == GLOBUS_SUCCESS);
    }
}

void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{

}


void
close_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}


static void
parse_parameters(
    int                                     argc,
    char **                                 argv,
    globus_xio_driver_t                     driver,
    globus_xio_attr_t                       attr)
{
    int                                     failure = 0;
    globus_bool_t                           inline_finish = GLOBUS_FALSE;
    globus_result_t                         res;
    int                                     chunk_size = -1;
    int                                     delay = 1000;
    int                                     eof_bytes = -1;
    char                                    c;

    globus_l_argc = argc;
    globus_l_argv = argv;

    /* parse the parameters */
    while((c = getopt(argc, argv, "iF:d:s:")) != -1)
    {
        switch(c)
        {
            case 'F':
                failure = atoi(optarg);
                break;

            case 'i':
                inline_finish = GLOBUS_TRUE;
                break;

            case 'd':
                delay = atoi(optarg);
                break;

            case 's':
                chunk_size = atoi(optarg);
                break;

            default:
                print_help();
                break;
        }
    }
    
    /* set up the attr */
    res = globus_xio_attr_cntl(
            attr, 
            driver, 
            GLOBUS_XIO_TEST_SET_INLINE,
            inline_finish);
    test_res(res, __LINE__);

    res = globus_xio_attr_cntl(
            attr, 
            driver, 
            GLOBUS_XIO_TEST_SET_FAILURES,
            failure);
    test_res(res, __LINE__);

    res = globus_xio_attr_cntl(
            attr, 
            driver, 
            GLOBUS_XIO_TEST_SET_USECS,
            delay);
    test_res(res, __LINE__);

    res = globus_xio_attr_cntl(
            attr, 
            driver, 
            GLOBUS_XIO_TEST_CHUNK_SIZE,
            chunk_size);
    test_res(res, __LINE__);

    res = globus_xio_attr_cntl(
            attr, 
            driver, 
            GLOBUS_XIO_TEST_READ_EOF_BYTES,
            eof_bytes);
    test_res(res, __LINE__);
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
    globus_abstime_t                        end_time;

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
            NULL);
    test_res(res, __LINE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }

        /* once done block a bit anyway, to test close barrier */
        GlobusTimeAbstimeSet(end_time, 5, 0);
        globus_cond_timedwait(&globus_l_cond, &globus_l_mutex, &end_time);
    }
    globus_mutex_unlock(&globus_l_mutex);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    return 0;
}
