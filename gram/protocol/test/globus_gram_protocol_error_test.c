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

#include "globus_gram_protocol.h"
#include <string.h>

int main(int argc, char * argv[])
{
    int rc = 0;
    int i;
    char * str;
    int verbose = 0;
    int testno = 0;

    if(argc > 1)
    {
	testno = atoi(argv[1]);
    }
    if(argc > 2)
    {
	verbose = 1;
    }

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	goto out;
    }
    if(testno == 0 || testno == 1)
    {
	for(i = -1; i < GLOBUS_GRAM_PROTOCOL_ERROR_LAST+1; i++)
	{
	    str = (char *) globus_gram_protocol_error_string(i);

	    if(str == NULL)
	    {
		rc = 1;
		goto error_exit;
	    }

	    if(verbose) printf("%d: %s\n", i, str);
	}
    }
    if(testno == 0 || testno == 2)
    {
	char *error1 = "error1";
	char *error2 = "error2";
	char *error3 = "error3";

	globus_gram_protocol_error_7_hack_replace_message(error1);
	str = globus_gram_protocol_error_string(7);
	if(verbose)
	{
	    printf("comparing %p:%s to %p:%s\n", 
		    error1, error1, str, str);
	}
	if(strcmp(str, "error1") != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
	globus_gram_protocol_error_7_hack_replace_message(error2);
	str = globus_gram_protocol_error_string(7);
	if(verbose)
	{
	    printf("comparing %p:%s to %p:%s\n", 
		    error2, error2, str, str);
	}
	if(strcmp(str, error2) != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
	globus_gram_protocol_error_7_hack_replace_message(error3);
	str = globus_gram_protocol_error_string(7);
	if(verbose)
	{
	    printf("comparing %p:%s to %p:%s\n", 
		    error3, error3, str, str);
	}
	if(strcmp(str, error3) != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
    }

error_exit:
    globus_module_deactivate_all();
out:
    if(rc == 0)
    {
	printf("ok\n");
    }
    return rc;
}
