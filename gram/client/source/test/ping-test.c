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
