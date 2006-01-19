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

/*
 * SYNTAX
 *     globus-is-local-user [-help][-usage][-version] <username>
 *
 * RETURNS
 *     0    if <username> is a valid local username
 *     1    otherwise
 */

#include "globus_common.h"
#include "version.h"

const char *  oneline_usage = 
"globus-is-local-user [-help][-usage][-version] <username>";

const char *  long_usage = 
"\n"
"Syntax: globus-is-local-user [-help][-usage][-version] <username>\n"
"\n"
"    Returns\n"
"       0    if <username> is a valid local username\n"
"       1    otherwise\n\n";


int main(int argc, char * argv[])
{
    globus_list_t *  dummy_list;
    int              exit_code = 1;
    int              rc;
    char             buf[1024];
	#if !defined(TARGET_ARCH_WIN32)
    struct passwd    pwd;
    struct passwd *  result;
    #endif
    
    globus_module_activate(GLOBUS_COMMON_MODULE);

    rc = globus_args_scan( &argc,
			   &argv,
			   0,
			   GLOBUS_NULL,
                           "globus-is-local-user",
                           &local_version,
			   _GCSL(oneline_usage),
			   _GCSL(long_usage),
			   &dummy_list,
			   GLOBUS_NULL );
			   
    if (rc < 0)
    {
	exit_code = (rc == GLOBUS_FAILURE) ? 1 : 0;
    }
    else if (argc < 2)
    {
	globus_libc_fprintf(stderr,
			   _GCSL("ERROR: provide a username\n\nSyntax: %s\n\n"
			   "Use -help to display full usage\n"),
			   oneline_usage);
	exit_code = 1;
    }
    else
    {
	/* ToDo: This call is not defined in common\globus_libc.c for Win32  */
    /*       Do we need to add this to Common?                           */
	#if !defined(TARGET_ARCH_WIN32)
	rc = globus_libc_getpwnam_r( argv[1],
				     &pwd,
				     buf,
				     1024,
				     &result );
	#else
	globus_libc_fprintf(stderr,
			    _GCSL("NOTE: globus_libc_getpwnam_r not supported on Windows\n"));
	/* leave return code as undisturbed from previous tests */
	#endif
	/* ~ToDo */

	if (rc == GLOBUS_SUCCESS)
	    exit_code = 0;
    }

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return exit_code;
}
