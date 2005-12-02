/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
