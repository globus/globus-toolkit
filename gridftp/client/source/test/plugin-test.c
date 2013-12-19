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

/* Test inserting/removing plugins from handle attributes and handles */
#include "globus_common.h"
#include "globus_ftp_client.h"
#include "globus_ftp_client_restart_plugin.h"
#include "globus_ftp_client_debug_plugin.h"

#include <stdio.h>

int main()
{
    int rc = 0;
    int count=0;
    globus_ftp_client_handle_t handle;
    globus_ftp_client_plugin_t restart_plugin;
    globus_ftp_client_plugin_t debug_plugin;
    globus_result_t result;
    globus_ftp_client_handleattr_t handleattr;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_module_activate(GLOBUS_FTP_CLIENT_RESTART_PLUGIN_MODULE);
    globus_module_activate(GLOBUS_FTP_CLIENT_DEBUG_PLUGIN_MODULE);

    /* Test using attributes */
    result = globus_ftp_client_handleattr_init(&handleattr);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_ftp_client_restart_plugin_init(
	    &restart_plugin,
	    0,
	    GLOBUS_NULL,
	    GLOBUS_NULL);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_ftp_client_debug_plugin_init(
	    &debug_plugin,
	    stderr,
	    "hello");
    globus_assert(result == GLOBUS_SUCCESS);

    /* Test 1: insert restart plugin into handle attr */
    count++;
    result = globus_ftp_client_handleattr_add_plugin(&handleattr,
	                                             &restart_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 2: insert restart plugin into handle attr (fail) */
    count++;
    result = globus_ftp_client_handleattr_add_plugin(&handleattr,
	                                             &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 3: create/destroy handle with attr */
    count++;
    result = globus_ftp_client_handle_init(&handle, &handleattr);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    else if(globus_ftp_client_handle_destroy(&handle) != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 4: insert debug plugin into handle attr */
    count++;
    result = globus_ftp_client_handleattr_add_plugin(&handleattr,
	                                             &debug_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 5: create/destroy handle with attr */
    count++;
    result = globus_ftp_client_handle_init(&handle, &handleattr);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    else if(globus_ftp_client_handle_destroy(&handle) != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 6: remove restart plugin from handle attr */
    count++;
    result = globus_ftp_client_handleattr_remove_plugin(&handleattr,
	                                                &restart_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 7: remove restart plugin from handle attr (fail) */
    count++;
    result = globus_ftp_client_handleattr_remove_plugin(&handleattr,
	                                                &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 8: insert debug plugin into handle attr (fail) */
    count++;
    result = globus_ftp_client_handleattr_add_plugin(&handleattr,
	                                             &debug_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 9: remove debug plugin from handle attr */
    count++;
    result = globus_ftp_client_handleattr_remove_plugin(&handleattr,
	                                                &debug_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 10: remove restart plugin from handle attr (fail) */
    count++;
    result = globus_ftp_client_handleattr_remove_plugin(&handleattr,
	                                                &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test 11: create/destroy handle with attr */
    count++;
    result = globus_ftp_client_handle_init(&handle, &handleattr);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    else if(globus_ftp_client_handle_destroy(&handle) != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    /* Test without attributes */
    /* Test 12: create handle without attr */
    count++;
    result = globus_ftp_client_handle_init(&handle, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 13: add restart plugin into handle */
    count++;
    result = globus_ftp_client_handle_add_plugin(&handle, &restart_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 14: add restart plugin into handle (fail) */
    count++;
    result = globus_ftp_client_handle_add_plugin(&handle, &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 15: add debug plugin into handle */
    count++;
    result = globus_ftp_client_handle_add_plugin(&handle, &debug_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 16: remove restart plugin from handle */
    count++;
    result = globus_ftp_client_handle_remove_plugin(&handle, &restart_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 17: remove restart plugin from handle (fail) */
    count++;
    result = globus_ftp_client_handle_remove_plugin(&handle, &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 18: add debug plugin into handle (fail) */
    count++;
    result = globus_ftp_client_handle_add_plugin(&handle, &debug_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 19: remove debug plugin into handle */
    count++;
    result = globus_ftp_client_handle_remove_plugin(&handle, &debug_plugin);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 20: remove restart plugin into handle (fail) */
    count++;
    result = globus_ftp_client_handle_remove_plugin(&handle, &restart_plugin);
    if(result == GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }
    /* Test 21: destroy handle */
    count++;
    result = globus_ftp_client_handle_destroy(&handle);
    if(result != GLOBUS_SUCCESS)
    {
	printf("Failed test %d\n", count);
	rc++;
    }

    globus_module_deactivate_all();
    return rc;
}
