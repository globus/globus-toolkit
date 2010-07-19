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

#include "globus_gsi_authz.h"

#include <string.h>
#include <strings.h>

#define USAGE "Usage: %s objectype object servicename action\n"

static void
authtest_l_init_callback(void *					cb_arg,
			 globus_gsi_authz_handle_t 		handle,
			 globus_result_t			result);

static void
authtest_l_authorize_callback(void *				cb_arg,
			      globus_gsi_authz_handle_t 	handle,
			      globus_result_t			result);



int
main(int argc, char **argv)
{
  globus_gsi_authz_handle_t        handle;
  char *			   cfname = 0;
  char *			   objecttype = 0;
  char *			   object = 0;
  char *			   servicename = 0;
  char *			   action = 0;
  gss_ctx_id_t                     ctx = 0;
  globus_result_t		   result;

  switch(argc) {
    case 5:
      objecttype = argv[1];
      object = argv[2];
      servicename = argv[3];
      action = argv[4];
      break;
    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(1);
  }

  if (globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE) != (int)GLOBUS_SUCCESS)
  {
      fprintf(stderr, "globus_module_activate failed\n");
      exit(1);
  }
  
  globus_gsi_authz_handle_init(&handle, servicename, ctx,
			       authtest_l_init_callback,
			       "init callback arg");

  result = globus_gsi_authorize(handle, action, object,
				authtest_l_authorize_callback,
				"authorize callback arg");
  if (result != GLOBUS_SUCCESS)
  {
      printf("authorize failed\n");
  }

  globus_module_deactivate(GLOBUS_GSI_AUTHZ_MODULE);

  exit(0);
}

static void
authtest_l_init_callback(void *				cb_arg,
			 globus_gsi_authz_handle_t 	handle,
			 globus_result_t		result)
{
    printf("in authtest_l_init_callback, arg is %s\n", (char *)cb_arg);
}

static void
authtest_l_authorize_callback(void *				cb_arg,
			      globus_gsi_authz_handle_t 	handle,
			      globus_result_t			result)
{
    printf("in authtest_l_authorize_callback, arg is %s\n", (char *)cb_arg);
}
