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

#include <gaa.h>
#include "gssapi_test_utils.h"
#include "gssapi.h"
#include "globus_gsi_authz.h"
#include <gaa_gss_generic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define USAGE "Usage: %s service_name\n"

struct context_arg
{
    gss_cred_id_t                       credential;
    int                                 fd;
    struct sockaddr_un *                address;
};

static void *
server_func(
    void *                              arg,
    char *				servicename
    );

static void *
client_func(
    void *                              arg);

#ifdef notdef
static void
process_gaa(char *gaa_config_file, gss_ctx_id_t ctx);
#endif


static void
authtest_l_handle_init_callback(void *				cb_arg,
				globus_gsi_authz_handle_t 	handle,
				globus_result_t		result);

static void
authtest_l_authorize_callback(void *				cb_arg,
			      globus_gsi_authz_handle_t 	handle,
			      globus_result_t			result);

static void
authtest_l_authz_handle_destroy_callback(void *				cb_arg,
				   globus_gsi_authz_handle_t 	handle,
				   globus_result_t		result);

static void
authtest_l_authz_get_authz_id_callback(void *				cb_arg,
				       globus_gsi_authz_handle_t 	handle,
				       globus_result_t		result);

int
main(int argc, char **argv)
{
    gss_cred_id_t                       credential;
    int                                 listen_fd;
    int                                 accept_fd;
    struct sockaddr_un *                address;
    struct context_arg *                arg = NULL;
    pid_t                               pid;
    char *				servicename = NULL;

    if (argc != 2)
    {
	fprintf(stderr, USAGE, argv[0]);
	exit(1);
    }
    servicename = argv[1];
    /* module activation */

    globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE);
    
    /* setup listener */

    address = malloc(sizeof(struct sockaddr_un));

    memset(address,0,sizeof(struct sockaddr_un));

    address->sun_family = PF_UNIX;

    tmpnam(address->sun_path);
    
    listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);

    bind(listen_fd, (struct sockaddr *) address, sizeof(struct sockaddr_un));

    listen(listen_fd,1);

    /* acquire credentials */

    credential = globus_gsi_gssapi_test_acquire_credential();

    if(credential == GSS_C_NO_CREDENTIAL)
    {
        fprintf(stderr,"Unable to aquire credential\n");
        exit(-1);
    }

    pid = fork();

    if(pid == 0)
    {
        /* child */
     	arg = malloc(sizeof(struct context_arg));
        
	arg->address = address;
        
	arg->credential = credential;

        client_func(arg);
    }
    else
    {
        accept_fd = accept(listen_fd,NULL,0);
        
	if(accept_fd < 0)
	{
	    abort();
	}
	
	arg = malloc(sizeof(struct context_arg));
        
	arg->fd = accept_fd;
        
	arg->credential = credential;

        server_func(arg, servicename);
    }

    /* close the listener */

    close(listen_fd);
    
    /* release credentials */
    
    globus_gsi_gssapi_test_release_credential(&credential); 
    
    /* free address */
    
    free(address);
    
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);

    exit(0);
}


void *
server_func(
    void *                              arg,
    char *				servicename)
{
    struct context_arg *                server_args;
    globus_bool_t                       boolean_result;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    globus_result_t			result;
    globus_gsi_authz_handle_t		authz_handle;
    char 				buf[2048];
    char *				request_action = 0;
    char *				request_object = 0;
    char *				identity = 0;
    
    server_args = (struct context_arg *) arg;

    boolean_result = globus_gsi_gssapi_test_authenticate(
	server_args->fd,
	GLOBUS_TRUE, 
	server_args->credential, 
	&context_handle, 
	&user_id, 
	&delegated_cred);
    
    if(boolean_result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Authentication failed\n");
        exit(1);
    }

    if (globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE) != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "SERVER: activation of authz module failed\n");
	exit(1);
    }
  
    result = globus_gsi_authz_handle_init(&authz_handle,
					  servicename,
					  context_handle,
					  authtest_l_handle_init_callback,
					  "init callback arg");
    if (result != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "SERVER: globus_gsi_authz_handle_init failed: %s\n",
		globus_error_print_chain(globus_error_get(result)));
	exit(1);
    }

    printf("> ");
    while (fgets(buf, sizeof(buf), stdin)) {
	request_action = strtok(buf, " \t\n");
	request_object = strtok(0, " \t\n");

	identity = 0;
	if (strcmp(request_action, "authz") == 0)
	{
	    result = globus_gsi_authz_get_authorization_identity (
		authz_handle,
		&identity,
		authtest_l_authz_get_authz_id_callback,
		"get_authz_id_callback_arg");
	    if (result == GLOBUS_SUCCESS)
	    {
		printf("%s\n", (identity ? identity : ""));
	    }
	    else
	    {
		printf("SERVER: globus_gsi_authz_get_authorization_identity failed: %s\n",
		       globus_error_print_chain(globus_error_get(result)));
	    }
	}
	else if (request_action && request_object)
	{
	    result = globus_gsi_authorize(authz_handle,
					  request_action,
					  request_object,
					  authtest_l_authorize_callback, 
					  "authorize_callback_arg");
	    if (result == GLOBUS_SUCCESS)
	    {
		printf("SERVER: authorize succeeded\n");
	    }
	    else
	    {
		printf("SERVER: authz denied or failed: %s\n",
		       globus_error_print_chain(globus_error_get(result)));
	    }
	}
	printf("> ");
    }

    result = globus_gsi_authz_handle_destroy(authz_handle,
					     authtest_l_authz_handle_destroy_callback,
					     "authz_handle_destroy_arg");
    if (result != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "SERVER: authz_handle_destroy failed: %s\n",
		globus_error_print_chain(globus_error_get(result)));
    }

    result = globus_module_deactivate(GLOBUS_GSI_AUTHZ_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "SERVER: deactivation of authz module failed: %s\n",
		globus_error_print_chain(globus_error_get(result)));
	exit(1);
    }


    close(server_args->fd);
    
    free(server_args);
    
    globus_gsi_gssapi_test_cleanup(&context_handle,
				   user_id,
				   &delegated_cred);

    return NULL;
}

void *
client_func(
    void *                              arg)
{
    struct context_arg *                client_args;
    globus_bool_t                       result;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    int                                 connect_fd;
    int                                 rc;

    client_args = (struct context_arg *) arg;

    connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);

    rc = connect(connect_fd,
                 (struct sockaddr *) client_args->address,
                 sizeof(struct sockaddr_un));

    if(rc != 0)
    {
        abort();
    }


    result = globus_gsi_gssapi_test_authenticate(
        connect_fd,
        GLOBUS_FALSE, 
        client_args->credential, 
        &context_handle, 
        &user_id, 
        &delegated_cred);
    
    if(result == GLOBUS_FALSE)
    {
        fprintf(stderr, "CLIENT: Authentication failed\n");
        exit(1);
    }

    globus_gsi_gssapi_test_cleanup(&context_handle,
                                   user_id,
                                   &delegated_cred);
    user_id = NULL;
    
    close(connect_fd);

    free(client_args);

    return NULL;
}

static void
authtest_l_handle_init_callback(void *				cb_arg,
				globus_gsi_authz_handle_t 	handle,
				globus_result_t		result)
{
    printf("in authtest_l_handle_init_callback, arg is %s\n",
	   (char *)cb_arg);
    if (result == GLOBUS_SUCCESS)
    {
	printf("handle_init succeeded\n");
    }
    else
    {
	printf("handle_init failed\n");
    }
}

static void
authtest_l_authorize_callback(void *				cb_arg,
			      globus_gsi_authz_handle_t 	handle,
			      globus_result_t			result)
{
    printf("in authtest_l_authorize_callback, arg is %s\n",
	   (char *)cb_arg);
    if (result == GLOBUS_SUCCESS)
    {
	printf("authorization succeeded\n");
    }
    else
    {
	printf("authorization failed\n");
    }
}

static void
authtest_l_authz_handle_destroy_callback(void *				cb_arg,
					 globus_gsi_authz_handle_t 	handle,
					 globus_result_t		result)
{
    printf("in authtest_l_authz_handle_destroy_callback, arg is %s\n",
	   (char *)cb_arg);
    if (result == GLOBUS_SUCCESS)
    {
	printf("handle_destroy succeeded\n");
    }
    else
    {
	printf("handle_destroy failed\n");
    }
}

static void
authtest_l_authz_get_authz_id_callback(void *				cb_arg,
					 globus_gsi_authz_handle_t 	handle,
					 globus_result_t		result)
{
    printf("in authtest_l_authz_get_authz_id_callback, arg is %s\n",
	   (char *)cb_arg);
    if (result == GLOBUS_SUCCESS)
    {
	printf("get_authz_id succeeded\n");
    }
    else
    {
	printf("get_authz_id failed\n");
    }
}
