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
    char                   *certfile, /* for backward compatibility.
					 use client_request->authzcreds
					 instead. */
    myproxy_response_t     *server_response,
    char                   *outfile)
{    
    char *credentials = NULL;
    char *request_buffer = NULL;
    int  requestlen, credential_len;
    myproxy_request_t tmp_request = { 0 };

    assert(socket_attrs != NULL);
    assert(client_request != NULL);
    assert(server_response != NULL);

    /* Compatibility with older API. Caller's client_request struct
       may not have the new authzcreds member, so we need a new struct. */
    if (certfile != NULL) {
	tmp_request.version        = client_request->version;
	tmp_request.username       = client_request->username;
	tmp_request.command_type   = client_request->command_type;
	tmp_request.proxy_lifetime = client_request->proxy_lifetime;
	tmp_request.credname       = client_request->credname;
	tmp_request.authzcreds     = certfile;
	strcpy(tmp_request.passphrase, client_request->passphrase);
	client_request = &tmp_request;
    }

    /* Set up client socket attributes */
    if (socket_attrs->gsi_socket == NULL) {
	if (myproxy_init_client(socket_attrs) < 0) {
	    return(1);
	}
    }
    
    /* Attempt anonymous-mode credential retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

     /* Authenticate client to server */
    if (GSI_SOCKET_context_established(socket_attrs->gsi_socket) == 0) {
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        return(1);
    }
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request_ex(client_request, &request_buffer);
    if (requestlen < 0) {
        return(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        return(1);
    }
    free(request_buffer);
    request_buffer = 0;

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) != 0) {
	return(1);
    }

    if (!outfile) {
	return(0);		/* if no outfile specified, just do auth */
    }
    
    /* Accept delegated credentials from server */
    if (myproxy_accept_delegation_ex(socket_attrs, &credentials,
				     &credential_len, NULL) < 0) {
	return(1);
    }      

#if 0 /* response was lost in myproxy_accept_delegation() */
    if (myproxy_recv_response(socket_attrs, server_response) < 0) {
       return(1);
    }
#endif

    if (outfile[0] == '-' && outfile[1] == '\0') {
        printf("%.*s", credential_len, credentials);
    } else {
	int fd;
	unlink(outfile);
	if ((fd = open(outfile, O_CREAT | O_EXCL | O_WRONLY,
		       S_IRUSR | S_IWUSR)) < 0) {
	    verror_put_string("open(%s) failed: %s\n", outfile,
			      strerror(errno));
	    return(1);
	}
	if (write(fd, credentials, credential_len) == -1) {
	    verror_put_errno(errno);
	    verror_put_string("error writing %s", outfile);
	    close(fd);
	    return(1);
	}
	close(fd);
    }

    memset(credentials, 0, credential_len);
    free(credentials);

    return(0);
}
