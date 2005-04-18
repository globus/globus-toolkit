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

int main(int argc, char *argv[])
{
    int rc;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Error activating GRAM Client\n");

	goto error_exit;
    }
    if(argc < 2)
    {
	rc = -1;

	fprintf(stderr, "Usage: %s rm_contact\n", argv[0]);

	goto deactivate_exit;
    }
    rc = globus_gram_client_ping(argv[1]);
    if(rc == GLOBUS_SUCCESS)
    {
	printf("Success pinging %s\n", argv[1]);
    }
    else
    {
	printf("Failed pinging %s because %s\n",
		argv[1],
		globus_gram_client_error_string(rc));
    }

  deactivate_exit:
    globus_module_deactivate_all();
  error_exit:
    return rc;
}
