#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;
static globus_bool_t                        globus_l_accepted = GLOBUS_FALSE;
static int                                  globus_l_cb_cnt = 0;

static void
close_cb(
    globus_xio_server_t                     server,
    void *                                  user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_l_cb_cnt++;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
accept_close_cb(
    globus_xio_server_t                         server,
    globus_xio_target_t                         target,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_cb_cnt++;
        globus_l_closed = GLOBUS_FALSE;
        res = globus_xio_server_register_close(
                server,
                close_cb,
                NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);

}

static void
accept_cb(
    globus_xio_server_t                         server,
    globus_xio_target_t                         target,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_xio_target_t *                       t;

    t = (globus_xio_target_t *) user_arg;

    if(globus_l_closed)
    {
        failed_exit("the accept callback came after the server_close callback");
    }

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_cb_cnt++;
        *t = target;
        globus_l_accepted = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

int
server2_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_target_t                     target;
    globus_result_t                         res;
    globus_xio_server_t                     server;
    globus_xio_attr_t                       attr;

    globus_l_cb_cnt = 0;
    globus_l_closed = GLOBUS_FALSE;
    globus_l_accepted = GLOBUS_FALSE;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    globus_mutex_init(&globus_l_mutex, NULL);    
    globus_cond_init(&globus_l_cond, NULL);    

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    parse_parameters(argc, argv, stack, attr);

    /*
     *  create the server
     */
    res = globus_xio_server_create(&server, attr, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    /* blocking */
    res = globus_xio_server_accept(&target, server, NULL);

    globus_mutex_lock(&globus_l_mutex);
    {
        /* non blocking */
        res = globus_xio_server_register_accept(
                server,
                NULL,
                accept_cb,
                &target);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__);
        /* should fail */
        res = globus_xio_server_register_accept(
                server,
                NULL,
                accept_cb,
                &target);
        if(res == GLOBUS_SUCCESS)
        {
            failed_exit("2nd register accept should have failed");
        }

        while(!globus_l_accepted)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }

        globus_l_accepted = GLOBUS_FALSE;

        /* non with close */
        globus_l_cb_cnt = 0;
        res = globus_xio_server_register_accept(
                server,
                NULL,
                accept_cb,
                &target);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__);
        res = globus_xio_server_register_close(
                server,
                close_cb,
                NULL);

        while(globus_l_cb_cnt < 2)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }

        /* close called from within the accept_cb */
        res = globus_xio_server_create(&server, attr, stack);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
        globus_l_cb_cnt = 0;
        res = globus_xio_server_register_accept(
                server,
                NULL,
                accept_close_cb,
                &target);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__);
        while(globus_l_cb_cnt < 2)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    
        

    globus_xio_attr_destroy(attr);
    globus_xio_stack_destroy(stack);

    if(globus_l_test_info.server)
    {
        res = globus_xio_server_close(server);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    }

    test_common_end();

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
