#include "globus_common.h"
#include "globus_net_manager.h"
#include "globus_net_manager_python.h"
#include "globus_test_tap.h"

static
int
test_pre_listen_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_listen;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            attr_array,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_listen_no_result() */

static
int
test_pre_listen_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_listen;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_listen_exception() */

static
int
test_pre_listen_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_listen;expected_result=res = [(\"tcp\", \"port\", \"4545\")];");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out != NULL);
    for (int i = 0; attr_array_out[i].scope != NULL; i++)
    {
        TEST_ASSERT(strcmp(attr_array_out[i].scope, "tcp") == 0);
        TEST_ASSERT(strcmp(attr_array_out[i].name, "port") == 0);
        TEST_ASSERT(strcmp(attr_array_out[i].value, "4545") == 0);
    }
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_pre_listen_new_attr() */

static
int
test_post_listen_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    char                               *local_contact_out = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_listen;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    TEST_ASSERT(local_contact_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_listen_no_result() */

static
int
test_post_listen_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *local_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_listen;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    TEST_ASSERT(local_contact_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_listen_exception() */

static
int
test_post_listen_new_contact(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *local_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_listen;expected_result=res = (\"new_contact:4242\", None);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(local_contact_out != NULL);
    TEST_ASSERT(strcmp(local_contact_out, "new_contact:4242") == 0);
    free(local_contact_out);
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_post_listen_new_contact() */

static
int
test_post_listen_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *local_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_listen;expected_result=res = (None, [(\"tcp\", \"port\", \"4546\")]);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(local_contact_out == NULL);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(attr_array_out[0].value != NULL);

    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4546") == 0);

    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_post_listen_new_attr() */

static
int
test_post_listen_new_attr_and_contact(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *local_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_listen;expected_result=res = (\"new_contact:4242\", [(\"tcp\", \"port\", \"4546\")]);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_listen(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(local_contact_out != NULL);
    TEST_ASSERT(strcmp(local_contact_out, "new_contact:4242") == 0);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(attr_array_out[0].value != NULL);

    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4546") == 0);

    free(local_contact_out);
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_post_listen_new_attr_and_contact() */

static
int
test_pre_accept_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_accept;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_accept_no_result() */

static
int
test_pre_accept_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_accept;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_accept_exception() */

static
int
test_pre_accept_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_accept;expected_result=res = [(\"tcp\", \"port\", \"4545\")];");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out != NULL);
    for (int i = 0; attr_array_out[i].scope != NULL; i++)
    {
        TEST_ASSERT(strcmp(attr_array_out[i].scope, "tcp") == 0);
        TEST_ASSERT(strcmp(attr_array_out[i].name, "port") == 0);
        TEST_ASSERT(strcmp(attr_array_out[i].value, "4545") == 0);
    }
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_pre_accept_new_attr() */


static
int
test_post_accept_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_accept;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_accept_no_result() */

static
int
test_post_accept_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_accept;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_accept_exception() */

static
int
test_post_accept_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_accept;expected_result=res = [(\"tcp\", \"port\", \"4545\")];");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_accept(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4545") == 0);
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_post_accept_new_attr() */

static
int
test_pre_connect_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    char                               *remote_contact_out = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_connect;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    TEST_ASSERT(remote_contact_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_connect_no_result() */

static
int
test_pre_connect_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *remote_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_connect;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            attr_array,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    TEST_ASSERT(remote_contact_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_connect_exception() */

static
int
test_pre_connect_new_contact(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *remote_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_connect;expected_result=res = (\"new_contact:4242\", None);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(remote_contact_out != NULL);
    TEST_ASSERT(strcmp(remote_contact_out, "new_contact:4242") == 0);
    free(remote_contact_out);
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_pre_connect_new_contact() */

static
int
test_pre_connect_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *remote_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_connect;expected_result=res = (None, [(\"tcp\", \"port\", \"4546\")]);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(remote_contact_out == NULL);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(attr_array_out[0].value != NULL);

    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4546") == 0);

    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_pre_connect_new_attr() */

static
int
test_pre_connect_new_attr_and_contact(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *remote_contact_out = NULL;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_connect;expected_result=res = (\"new_contact:4242\", [(\"tcp\", \"port\", \"4546\")]);");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            attr_array,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(remote_contact_out != NULL);
    TEST_ASSERT(strcmp(remote_contact_out, "new_contact:4242") == 0);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(attr_array_out[0].value != NULL);

    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4546") == 0);

    free(remote_contact_out);
    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}

/* test_pre_connect_new_attr_and_contact() */

static
int
test_post_connect_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_connect;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result)
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_connect_no_result() */

static
int
test_post_connect_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_connect;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out == NULL);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_connect_exception() */

static
int
test_post_connect_new_attr(void)
{
    globus_net_manager_attr_t          *attr_array = NULL,
                                       *attr_array_out = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_connect;expected_result=res = [(\"tcp\", \"port\", \"4546\")];");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_connect(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4545",
            "remotehost:4545",
            attr_array,
            &attr_array_out);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(attr_array_out[0].value != NULL);

    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "4546") == 0);

    globus_net_manager_attr_array_delete(attr_array);
    globus_net_manager_attr_array_delete(attr_array_out);
    return 0;
}
/* test_post_connect_new_attr() */

static
int
test_pre_close_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_close;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_close(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array);
    TEST_ASSERT_RESULT_SUCCESS(result)
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_close_no_result() */

static
int
test_pre_close_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=pre_close;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->pre_close(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_pre_close_exception() */

static
int
test_post_close_no_result(void)
{
    globus_net_manager_attr_t          *attr_array = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_close;expected_result=res=None;");
    TEST_ASSERT_RESULT_SUCCESS(result);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_close(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array);
    TEST_ASSERT_RESULT_SUCCESS(result)
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_close_no_result() */

static
int
test_post_close_exception(void)
{
    globus_net_manager_attr_t          *attr_array = NULL;
    globus_net_manager_t               *net_manager = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_net_manager_attr_array_from_string(
            &attr_array,
            "python",
            "pymod=test_module;test_func=post_close;expected_result=raise Exception();");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array != NULL);

    net_manager = globus_net_manager_python_module.get_pointer_func();
    TEST_ASSERT(net_manager != NULL);

    result = net_manager->post_close(
            net_manager,
            attr_array,
            "42",
            "tcp",
            "localhost:4242",
            "remotehost:4242",
            attr_array);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    globus_net_manager_attr_array_delete(attr_array);
    return 0;
}
/* test_post_close_exception() */

struct tests
{
    char * test_name;
    int (*test_func)(void);
};

#define TEST_INITIALIZER(name) { #name, name }

int
main(int argc, char *argv[])
{
    struct tests tests[] = {
        TEST_INITIALIZER(test_pre_listen_no_result),
        TEST_INITIALIZER(test_pre_listen_exception),
        TEST_INITIALIZER(test_pre_listen_new_attr),
        TEST_INITIALIZER(test_post_listen_no_result),
        TEST_INITIALIZER(test_post_listen_exception),
        TEST_INITIALIZER(test_post_listen_new_contact),
        TEST_INITIALIZER(test_post_listen_new_attr),
        TEST_INITIALIZER(test_post_listen_new_attr_and_contact),
        TEST_INITIALIZER(test_pre_accept_no_result),
        TEST_INITIALIZER(test_pre_accept_exception),
        TEST_INITIALIZER(test_pre_accept_new_attr),
        TEST_INITIALIZER(test_post_accept_no_result),
        TEST_INITIALIZER(test_post_accept_exception),
        TEST_INITIALIZER(test_post_accept_new_attr),
        TEST_INITIALIZER(test_pre_connect_no_result),
        TEST_INITIALIZER(test_pre_connect_exception),
        TEST_INITIALIZER(test_pre_connect_new_contact),
        TEST_INITIALIZER(test_pre_connect_new_attr),
        TEST_INITIALIZER(test_pre_connect_new_attr_and_contact),
        TEST_INITIALIZER(test_post_connect_no_result),
        TEST_INITIALIZER(test_post_connect_exception),
        TEST_INITIALIZER(test_post_connect_new_attr),
        TEST_INITIALIZER(test_pre_close_no_result),
        TEST_INITIALIZER(test_pre_close_exception),
        TEST_INITIALIZER(test_post_close_no_result),
        TEST_INITIALIZER(test_post_close_exception),
        {NULL, NULL}
    };
    int i;
    int rc;

    rc = globus_module_activate(&globus_net_manager_python_module);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Unable to load module\n");
        exit(EXIT_FAILURE);
    }
    printf("1..%d\n", (int) (sizeof(tests)/sizeof(tests[0]))-1);
    for (i = 0; tests[i].test_name; i++)
    {
        ok(tests[i].test_func() == 0, tests[i].test_name);
    }
    return TEST_EXIT_CODE;
}
