#include "globus_net_manager_context.h"
#include "globus_test_tap.h"

static
int
context_init_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_attr_t           attr[] = {
        {"scope,", "name", "value"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };

    result = globus_net_manager_context_init(NULL, NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_init(NULL, attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    return 0;
}
/* context_init_null_test() */

static
int
context_destroy_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    globus_net_manager_context_destroy(NULL);

    return 0;
}
/* context_destroy_null_test() */

static
int
context_init_destroy_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_init_destroy_test() */

static
int
context_init_multiple_modules_destroy_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context init multiple modules destroy test */

static
int
context_pre_listen_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_listen(
            NULL,
            task_id,
            transport,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_listen(
            context,
            NULL,
            transport,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_listen(
            context,
            task_id,
            NULL,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_listen(
            context,
            task_id,
            transport,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_listen(
            context,
            task_id,
            transport,
            attr,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_listen_null_test() */

static
int
context_pre_listen_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_listen(
            context,
            task_id,
            transport,
            attr,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "pre_listen") == 0);

    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_listen_test() */

static
int
context_post_listen_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    char                               *local_contact_out = NULL;
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_listen(
            NULL,
            task_id,
            transport,
            local_contact,
            attr,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            NULL,
            transport,
            local_contact,
            attr,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            NULL,
            local_contact,
            attr,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            transport,
            NULL,
            attr,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            transport,
            local_contact,
            NULL,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            transport,
            local_contact,
            attr,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            transport,
            local_contact,
            attr,
            &local_contact_out,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_listen_null_test() */

static
int
context_post_listen_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    char                               *local_contact_out = NULL;
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_listen(
            context,
            task_id,
            transport,
            local_contact,
            attr,
            &local_contact_out,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "post_listen") == 0);

    free(local_contact_out);
    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_listen_test() */

static
int
context_pre_accept_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_accept(
            NULL,
            task_id,
            transport,
            local_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_accept(
            context,
            NULL,
            transport,
            local_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_accept(
            context,
            task_id,
            NULL,
            local_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_accept(
            context,
            task_id,
            transport,
            NULL,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_accept(
            context,
            task_id,
            transport,
            local_contact,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_accept(
            context,
            task_id,
            transport,
            local_contact,
            attr,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_accept_null_test() */

static
int
context_pre_accept_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_accept(
            context,
            task_id,
            transport,
            local_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "pre_accept") == 0);

    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_accept_test() */

static
int
context_post_accept_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_accept(
            NULL,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            NULL,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            NULL,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            transport,
            NULL,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            transport,
            local_contact,
            NULL,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_accept_null_test() */

static
int
context_post_accept_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_accept(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "post_accept") == 0);

    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_accept_test() */

static
int
context_pre_connect_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *remote_contact = "remotehost:42";
    char                               *remote_contact_out = NULL;
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_connect(
            NULL,
            task_id,
            transport,
            remote_contact,
            attr,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            NULL,
            transport,
            remote_contact,
            attr,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            NULL,
            remote_contact,
            attr,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            transport,
            remote_contact,
            NULL,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            transport,
            remote_contact,
            NULL,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            transport,
            remote_contact,
            attr,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            transport,
            remote_contact,
            attr,
            &remote_contact_out,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_connect_null_test() */

static
int
context_pre_connect_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    char                               *remote_contact_out = NULL;
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_connect(
            context,
            task_id,
            transport,
            remote_contact,
            attr,
            &remote_contact_out,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "pre_connect") == 0);

    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_connect_test() */

static
int
context_post_connect_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_connect(
            NULL,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_connect(
            context,
            NULL,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_connect(
            context,
            task_id,
            NULL,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_connect(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_connect(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            NULL,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_connect(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_connect_null_test() */

static
int
context_post_connect_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_connect(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr,
            &attr_array_out);
    TEST_ASSERT_RESULT_SUCCESS(result);

    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope,
            "return_function_called_module") == 0);
    TEST_ASSERT(attr_array_out[0].name != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].name,
            "function") == 0);
    TEST_ASSERT(attr_array_out[0].value != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].value,
            "post_connect") == 0);

    globus_net_manager_attr_array_delete(attr_array_out);
    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_connect_test() */

static
int
context_pre_close_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_close(
            NULL,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_close(
            context,
            NULL,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_close(
            context,
            task_id,
            NULL,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_close(
            context,
            task_id,
            transport,
            NULL,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_close(
            context,
            task_id,
            transport,
            local_contact,
            NULL,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_pre_close(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_close_null_test() */

static
int
context_pre_close_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t          *attr_array_out = NULL;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_close(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_pre_close_test() */

static
int
context_post_close_null_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_logging_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_close(
            NULL,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_close(
            context,
            NULL,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_close(
            context,
            task_id,
            NULL,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_close(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    result = globus_net_manager_context_post_close(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            NULL);
    TEST_ASSERT(result != GLOBUS_SUCCESS);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_close_null_test() */

static
int
context_post_close_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "globus_net_manager_python_module"},
        {"python,", "pymod", "return_function_called_module"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    const char                         *local_contact = "localhost:42";
    const char                         *remote_contact = "remotehost:42";

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_post_close(
            context,
            task_id,
            transport,
            local_contact,
            remote_contact,
            attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_post_close_test() */

int
context_chain_plus_minus_listen_test(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_context_t        context = NULL;
    const char                         *task_id = "42";
    const char                         *transport = "tcp";
    globus_net_manager_attr_t           attr[] = {
        {"net_manager,", "manager", "python"},
        {"python,", "pymod", "port_plus_one"},
        {"net_manager,", "manager", "python"},
        {"python,", "pymod", "port_minus_one"},
        {"tcp", "port", "42"},
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t          *attr_array_out;

    result = globus_net_manager_context_init(&context, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_net_manager_context_pre_listen(
            context,
            task_id,
            transport,
            attr,
            &attr_array_out);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    TEST_ASSERT(attr_array_out != NULL);
    TEST_ASSERT(attr_array_out[0].scope != NULL);
    TEST_ASSERT(strcmp(attr_array_out[0].scope, "tcp") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].name, "port") == 0);
    TEST_ASSERT(strcmp(attr_array_out[0].value, "42") == 0);

    globus_net_manager_context_destroy(context);

    return 0;
}
/* context_chain_plus_minus_listen_test() */

struct tests
{
    char * test_name;
    int (*test_func)(void);
};

#define TEST_INITIALIZER(name) { #name, name }
#ifdef ENABLE_PYTHON
#define SKIP_PYTHON_TESTS 0
#else
#define SKIP_PYTHON_TESTS 0
#endif

int
main(int argc, char *argv[])
{
    struct tests tests[] = {
        TEST_INITIALIZER(context_init_null_test),
        TEST_INITIALIZER(context_destroy_null_test),
        TEST_INITIALIZER(context_init_destroy_test),
        TEST_INITIALIZER(context_init_multiple_modules_destroy_test),
        TEST_INITIALIZER(context_pre_listen_null_test),
        TEST_INITIALIZER(context_pre_listen_test),
        TEST_INITIALIZER(context_post_listen_null_test),
        TEST_INITIALIZER(context_post_listen_test),
        TEST_INITIALIZER(context_pre_accept_null_test),
        TEST_INITIALIZER(context_pre_accept_test),
        TEST_INITIALIZER(context_post_accept_null_test),
        TEST_INITIALIZER(context_post_accept_test),
        TEST_INITIALIZER(context_pre_connect_null_test),
        TEST_INITIALIZER(context_pre_connect_test),
        TEST_INITIALIZER(context_post_connect_null_test),
        TEST_INITIALIZER(context_post_connect_test),
        TEST_INITIALIZER(context_pre_close_null_test),
        TEST_INITIALIZER(context_pre_close_test),
        TEST_INITIALIZER(context_post_close_null_test),
        TEST_INITIALIZER(context_post_close_test),
        TEST_INITIALIZER(context_chain_plus_minus_listen_test),
        {NULL, NULL}
    };
    int i;

    printf("1..%d\n", (int) (sizeof(tests)/sizeof(tests[0]))-1);
    for (i = 0; tests[i].test_name; i++)
    {
        skip(SKIP_PYTHON_TESTS, ok(tests[i].test_func() == 0,
                "%s", tests[i].test_name));
    }
    return TEST_EXIT_CODE;
}
