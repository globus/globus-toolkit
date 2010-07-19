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

/* test the various I/O routines */

#include "globus_gram_protocol.h"
#include <string.h>

void
callback_func(
    void *				callback_arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			msg,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri)
{
}

/* Disable a bogus callback contact */
int test1()
{
    int					rc;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error activating protocol module beacuse %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }
    rc = globus_gram_protocol_callback_disallow(
	    "https://globus.org:1234/123/345/678");
    if(rc == GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Succeeded disallowing callbacks to a bogus contact!?!\n");
    }
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return (!rc);
}

/* Create and disable a callback contact */
int test2()
{
    int					rc;
    char *				callback_contact;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error activating protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }
    rc = globus_gram_protocol_allow_attach(
	    &callback_contact,
	    callback_func,
	    GLOBUS_NULL);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error creating callback contact because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    rc = globus_gram_protocol_callback_disallow(
	    callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error disallowing callbacks because %s.\n",
		globus_gram_protocol_error_string(rc));
    }
    
    globus_free(callback_contact);
    
error_exit:
    rc = globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* Create and disable multiple callback contacts */
int test3()
{
    int					rc;
    char *				callback_contact[5];
    int					i;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error activating protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }
    for(i = 0; i < 5; i++)
    {
	rc = globus_gram_protocol_allow_attach(
		&callback_contact[i],
		callback_func,
		GLOBUS_NULL);
	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr, "Error creating callback contact because %s.\n",
		    globus_gram_protocol_error_string(rc));
	    i--;
	    goto disallow_exit;
	}
    }
    for(--i; i >=0; i--)
    {
	rc = globus_gram_protocol_callback_disallow(
		callback_contact[i]);
	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr,
		    "Error disallowing callbacks because %s.\n",
		    globus_gram_protocol_error_string(rc));
	    goto disallow_exit;
	}
    }
    rc = globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);

    for(i = 0; i < 5; i++)
    {
	globus_free(callback_contact[i]);
    }
    return rc;

disallow_exit:
    for(; i >=0; i--)
    {
	globus_gram_protocol_callback_disallow(
		callback_contact[i]);
    }
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* Create multiple callback contacts and then deactivate */
int test4()
{
    int					rc;
    char *				callback_contact[5];
    int					i;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error activating protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }
    for(i = 0; i < 5; i++)
    {
	rc = globus_gram_protocol_allow_attach(
		&callback_contact[i],
		callback_func,
		GLOBUS_NULL);
	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr, "Error creating callback contact because %s.\n",
		    globus_gram_protocol_error_string(rc));
	    goto error_exit;
	}
    }
    for(i = 0; i < 5; i++)
    {
	globus_free(callback_contact[i]);
    }
    rc = globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;

error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

int main(int argc, char **argv)
{
    int					not_ok = 0;
    int					rc;
    int					test_num = 0;

    if(argc > 1)
    {
	test_num = atoi(argv[1]);
    }
    if(test_num == 0 || test_num == 1)
    {
	rc = test1();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 2)
    {
	rc = test2();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 3)
    {
	rc = test3();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 4)
    {
	rc = test4();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }

    return not_ok;
}
