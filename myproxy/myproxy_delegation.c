#include "myproxy_common.h"	/* all needed headers included here */

int myproxy_set_delegation_defaults(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request)
{ 
    char *pshost;

    client_request->version = strdup(MYPROXY_VERSION);
    client_request->command_type = MYPROXY_GET_PROXY;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    client_request->proxy_lifetime = 60*60*MYPROXY_DEFAULT_DELEG_HOURS;

    if (getenv("MYPROXY_SERVER_PORT")) {
	socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
	socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    return 0;
}
    
int myproxy_get_delegation(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request,
    myproxy_response_t     *server_response,
    char *outfile)
{    
    char delegfile[128];
    char request_buffer[2048];
    int  requestlen;

    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "Error: %s\n", verror_get_string());
        return(1);
    }
    
    /* Attempt anonymous-mode credential retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

     /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        fprintf(stderr, "Error: %s: %s\n", 
		socket_attrs->pshost, verror_get_string());
        return(1);
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, request_buffer,
					   sizeof(request_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "Error in myproxy_serialize_request():\n");
        return(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "Error in myproxy_send_request(): %s\n", 
		verror_get_string());
        return(1);
    }

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) != 0) {
	fprintf(stderr, "%s\n", verror_get_string());
	return(1);
    }
    
    /* Accept delegated credentials from server */
    if (myproxy_accept_delegation(socket_attrs, delegfile, sizeof(delegfile),
				  NULL) < 0) {
        fprintf(stderr, "Error in myproxy_accept_delegation(): %s\n", 
		verror_get_string());
	return(1);
    }      

#if 0 /* response was lost in myproxy_accept_delegation() */
    if (myproxy_recv_response(socket_attrs, server_response) < 0) {
       fprintf(stderr, "%s\n", verror_get_string());
       return(1);
    }
#endif

    /* move delegfile to outputfile if specified */
    if (outfile != NULL) {
        if (copy_file(delegfile, outfile, 0600) < 0) {
	    fprintf(stderr, "Error creating file: %s\n", outfile);
	    return(1);
	}
	ssl_proxy_file_destroy(delegfile);
    }

    return(0);
}
