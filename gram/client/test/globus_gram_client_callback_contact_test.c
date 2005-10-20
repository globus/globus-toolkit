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

#include "globus_gram_client.h"

static
void
callback_func(
    void *				user_arg,
    char *				job_contact,
    int					state,
    int					errorcode);

/* add and remove a callback contact */
static
int
test1()
{
    char * callback_contact;
    int rc;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_allow(
	    callback_func,
	    GLOBUS_NULL,
	    &callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(
	    callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    globus_libc_free(callback_contact);
    return globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);
}

/* remove a bogus callback contact */
static
int 
test2()
{
    int rc;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(
	    "bogus_callback_contact");

    if(rc == GLOBUS_SUCCESS)
    {
	return !rc;
    }
    return globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);
}

/* create a few callback contacts, and remove them out of order */
static
int
test3()
{
    char *callback_contact[3];
    int rc;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_allow(
	    callback_func,
	    GLOBUS_NULL,
	    &callback_contact[0]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_allow(
	    callback_func,
	    GLOBUS_NULL,
	    &callback_contact[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_allow(
	    callback_func,
	    GLOBUS_NULL,
	    &callback_contact[2]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(callback_contact[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(callback_contact[2]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(callback_contact[0]);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    globus_libc_free(callback_contact[0]);
    globus_libc_free(callback_contact[1]);
    globus_libc_free(callback_contact[2]);
    return globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);
}

/* create a callback contact, and then don't disable it before
 * deactivating.
 */
static 
int
test4()
{
    int rc;
    char * callback_contact;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_allow(
	    callback_func,
	    GLOBUS_NULL,
	    &callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_gram_client_callback_disallow(callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }
    globus_libc_free(callback_contact);
    return globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);
}

int main(int argc, char *argv[])
{
    int rc;
    int test_num = 0;
    int not_ok = 0;

    if(argc > 1)
    {
	test_num = atoi(argv[1]);
    }
    if(test_num == 0 || test_num == 1)
    {
	rc = test1();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }

    if(test_num == 0 || test_num == 2)
    {
	rc = test2();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }

    if(test_num == 0 || test_num == 3)
    {
	rc = test3();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 4)
    {
	rc = test4();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }

    return not_ok;
}

static
void
callback_func(
    void *				user_arg,
    char *				job_contact,
    int					state,
    int					errorcode)
{
    return;
}
