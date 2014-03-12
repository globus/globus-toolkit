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
#include "globus_preload.h"

int main(int argc, char * argv[])
{
    int rc = 0;
    int i;
    const char * str;
    int testno = 0;
    int fail_count=0;

    LTDL_SET_PRELOADED_SYMBOLS();
    printf("1..3\n");

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    printf("%s - activate GLOBUS_GRAM_PROTOCOL_MODULE %d\n",
        rc == GLOBUS_SUCCESS ? "ok" : "not ok", rc);
    if (rc)
    {
        fail_count++;
    }
    rc = 0;
    for(i = -1; i < GLOBUS_GRAM_PROTOCOL_ERROR_LAST+1; i++)
    {
        str = (char *) globus_gram_protocol_error_string(i);

        if(str == NULL)
        {
            rc = 1;
            fail_count++;
            break;
        }
    }
    printf("%s - globus_gram_protocol_error_string\n",
        (rc == 0) ? "ok" : "not ok");
    {
	char *error1 = "error1";
	char *error2 = "error2";
	char *error3 = "error3";

	globus_gram_protocol_error_7_hack_replace_message(error1);
	str = globus_gram_protocol_error_string(7);
	if(strcmp(str, "error1") != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
	globus_gram_protocol_error_7_hack_replace_message(error2);
	str = globus_gram_protocol_error_string(7);
	if(strcmp(str, error2) != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
	globus_gram_protocol_error_7_hack_replace_message(error3);
	str = globus_gram_protocol_error_string(7);
	if(strcmp(str, error3) != 0)
	{
	    rc = GLOBUS_FAILURE;
	}
    }
    printf("%s - globus_gram_protocol_error_7_hack_replace_message\n",
        (rc == 0) ? "ok" : "not ok");
    if (rc)
    {
        fail_count++;
    }

error_exit:
    globus_module_deactivate_all();
out:
    return fail_count;
}
