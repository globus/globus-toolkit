#include "myproxy_common.h"	/* all needed headers included here */

int myproxy_set_delegation_defaults(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request)
{ 
    if( myproxy_init( socket_attrs,
                      client_request,
                      MYPROXY_GET_PROXY ) < 0 )
    {
      return( 1 );
    }

    client_request->proxy_lifetime = 60*60*MYPROXY_DEFAULT_DELEG_HOURS;

    return 0;
}
    
int myproxy_get_delegation(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request,
    char                   *certfile, /* for backward compatibility.
					 use client_request->authzcreds
					 instead. */
    myproxy_response_t     *server_response,
    char                   *outputfile,
    int                     use_empty_passwd,
    int                     read_passwd_from_stdin,
    int                     dn_as_username,
    char                   *outfile)
{    
    char delegfile[MAXPATHLEN];
    myproxy_request_t tmp_request = { 0 };

    assert(socket_attrs != NULL);
    assert(client_request != NULL);
    assert(server_response != NULL);

    myproxy_debug("want_trusted_certs = %d\n", client_request->want_trusted_certs);
    
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

    if (!outputfile) {
        GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(&outputfile,
                                                GLOBUS_PROXY_FILE_OUTPUT);
    }

    if( myproxy_user_password( client_request,
                               use_empty_passwd,
                               read_passwd_from_stdin ) != 0 )
    {
      return( 1 );
    }

    if( myproxy_client_username( client_request,
                                 NULL,
                                 dn_as_username ) != 0 )
    {
      return( 1 );
    }

    if( myproxy_open_server_com( socket_attrs, NULL ) != 0 )
    {
      return( 1 );
    }
    
    /* Attempt anonymous-mode credential retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

    /* Serialize client request object */
    /* Send request to the myproxy-server */
    /* Continue unless the response is not OK */
    client_request->replicate_info = "1";

    if( myproxy_serialize_send_recv( client_request,
                                     server_response,
                                     socket_attrs ) != 0 )
    {
      return( 1 );
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
    if (outputfile != NULL) {
        if (copy_file(delegfile, outputfile, 0600) < 0) {
	    fprintf(stderr, "Error creating file: %s\n", outputfile);
	    return(1);
	}
	ssl_proxy_file_destroy(delegfile);
    }

    printf("A proxy has been received for user %s in %s\n",
           client_request->username, outputfile);

    /* Store file in trusted directory if requested and returned */
    if (client_request->want_trusted_certs)
    {
        if (server_response->trusted_certs != NULL)
        {

            if (myproxy_install_trusted_cert_files(server_response->trusted_certs) != 0)
            {       
                return (1);
            }
        }
        else
        {
            myproxy_debug("Requested trusted certs but didn't get any.\n");
        }
    }
    
    return(0);
}
