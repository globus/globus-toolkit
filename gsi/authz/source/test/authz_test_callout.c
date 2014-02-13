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

#include "globus_common.h"
#include "globus_gsi_authz.h"
#include <stdlib.h>


static gss_ctx_id_t current_context = GSS_C_NO_CONTEXT;

/*
 * ap is:
 *		void * authz_system_state;
 */
globus_result_t
authz_test_system_init_callout(
                               va_list ap)
{
    void                               **authz_system_state;

    globus_result_t                     result = GLOBUS_SUCCESS;

    authz_system_state = va_arg(ap, void **);

    return result;
}


globus_result_t
authz_test_system_destroy_callout(
                                  va_list ap)
{
    void                               *authz_system_state;

    globus_result_t                     result = GLOBUS_SUCCESS;

    authz_system_state = va_arg(ap, void *);

    return result;
}


globus_result_t
authz_test_handle_init_callout(
                               va_list ap)
{
    char                               *service_name;
    gss_ctx_id_t                        context;
    globus_gsi_authz_cb_t               callback;
    void                               *callback_arg;
    void                               *authz_system_state;
    globus_gsi_authz_handle_t          *handle;

    globus_result_t                     result = GLOBUS_SUCCESS;

    handle = va_arg(ap, globus_gsi_authz_handle_t *);
    service_name = va_arg(ap, char *);
    context = va_arg(ap, gss_ctx_id_t);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    current_context = context;

    if (strcmp(service_name, "goodservice") == 0)
    {
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = GLOBUS_FAILURE;
    }

    callback(callback_arg, callback_arg, result);

    return result;
}


globus_result_t
authz_test_authorize_async_callout(
                                   va_list ap)
{
    globus_gsi_authz_handle_t           handle;
    char                               *action;
    char                               *object;
    globus_gsi_authz_cb_t               callback;
    void                               *callback_arg;
    void                               *authz_system_state;

    globus_result_t                     result = GLOBUS_SUCCESS;


    handle = va_arg(ap, globus_gsi_authz_handle_t);
    action = va_arg(ap, char *);
    object = va_arg(ap, char *);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    if (strcmp(action, "action") == 0)
    {
        if (strcmp(object, "good") == 0)
        {
            result = GLOBUS_SUCCESS;
        }
        else
        {
            result = GLOBUS_FAILURE;
        }
    }
    else
    {
        result = GLOBUS_FAILURE;
    }

    callback(callback_arg, handle, result);

    return result;
}

int
authz_test_cancel_callout(
                          va_list ap)
{
    void                               *authz_system_state;

    int                                 result = (int)GLOBUS_SUCCESS;

    authz_system_state = va_arg(ap, void *);

    return result;
}

int
authz_test_handle_destroy_callout(
                                  va_list ap)
{
    globus_gsi_authz_handle_t   handle;
    globus_gsi_authz_cb_t callback;
    void * callback_arg;
    void * authz_system_state;
    int                                 result = (int)GLOBUS_SUCCESS;


    handle = va_arg(ap, globus_gsi_authz_handle_t);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void **);
    current_context = GSS_C_NO_CONTEXT;

    callback(callback_arg, handle, result);

    return result;

}

int
authz_test_get_authorization_identity(va_list ap)
{
    globus_gsi_authz_handle_t           handle;
    char                              **identity_ptr;
    globus_gsi_authz_cb_t               callback;
    void                               *callback_arg;
    void                               *authz_system_state;

    globus_result_t                     result = GLOBUS_SUCCESS;

    handle = va_arg(ap, globus_gsi_authz_handle_t);
    identity_ptr = va_arg(ap, char **);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    if (current_context != NULL)
    {
        *identity_ptr = strdup("identity");
    }
    else
    {
        *identity_ptr = NULL;
        result = GLOBUS_FAILURE;
    }

    callback(callback_arg, handle, result);

    return result;
}
