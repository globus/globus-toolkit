#include "myproxy.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"
#include "myproxy_delegation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <assert.h>
#include <errno.h>
#include <unistd.h>

static int copy_file(const char *source,
		     const char *dest,
		     const mode_t mode);

static int myproxy_authorize_init(myproxy_socket_attrs_t *attrs,
                                  char *passphrase,
				  char *certfile);

int myproxy_set_delegation_defaults(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request)
{ 
    char *username, *pshost;

    client_request->version = strdup(MYPROXY_VERSION);
    client_request->command_type = MYPROXY_GET_PROXY;

    username = getenv("LOGNAME");
    if (username != NULL) {
      client_request->username = strdup(username);
    }

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    client_request->proxy_lifetime = 60*60*MYPROXY_DEFAULT_DELEG_HOURS;

    socket_attrs->psport = MYPROXY_SERVER_PORT;

    return 0;
}
    
int myproxy_get_delegation(
myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request,
    char *certfile,
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
    requestlen = myproxy_serialize_request(client_request, 
                                           request_buffer, sizeof(request_buffer));
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
    if (myproxy_authorize_init(socket_attrs, client_request->passphrase,
	                       certfile) < 0) {
	  //fprintf(stderr, "Error in myproxy_authorize_init(): %s\n",
	    //      verror_get_string());
	  fprintf(stderr, "%s\n",
	          verror_get_string());
	  return(1);
    }

    /* Accept delegated credentials from server */
    if (myproxy_accept_delegation(socket_attrs, delegfile, sizeof(delegfile), NULL) < 0) {
        fprintf(stderr, "Error in myproxy_accept_delegation(): %s\n", 
		verror_get_string());
	return(1);
    }      

    if (myproxy_recv_response(socket_attrs, server_response) < 0) {
       fprintf(stderr, "Error in myproxy_recv_response(): %s %s\n",
	       verror_get_string(), (server_response->data).error_str);
       return(1);
    }

    /* move delegfile to outputfile if specified */
    if (outfile != NULL) {
        if (copy_file(delegfile, outfile, 0600) < 0) {
		fprintf(stderr, "Error creating file: %s\n",
		outfile);
		return(1);
	}
	unlink(delegfile);
	strcpy(delegfile, outfile);
    }

    return(0);
}

/*
 * copy_file()
 *
 * Copy source to destination, creating destination if necessary
 * Set permissions on destination to given mode.
 *
 * Returns 0 on success, -1 on error. 
 */
static int
copy_file(const char *source,
	  const char *dest,
	  const mode_t mode)
{
    int src_fd = -1;
    int dst_fd = -1;
    int src_flags = O_RDONLY;
    int dst_flags = O_WRONLY | O_CREAT;
    char buffer[2048];
    int bytes_read;
    int return_code = -1;
    
    assert(source != NULL);
    assert(dest != NULL);
    
    src_fd = open(source, src_flags);
    
    if (src_fd == -1)
    {
	verror_put_errno(errno);
	verror_put_string("opening %s for reading", source);
	goto error;
    }
     
    dst_fd = open(dest, dst_flags, mode);
    
    if (dst_fd == -1)
    {
	verror_put_errno(errno);
	verror_put_string("opening %s for writing", dest);
	goto error;
    }
    
    do 
    {
	bytes_read = read(src_fd, buffer, sizeof(buffer));
	
	if (bytes_read == -1)
	{
	    verror_put_errno(errno);
	    verror_put_string("reading %s", source);
	    goto error;
	}

	if (bytes_read != 0)
	{
	    if (write(dst_fd, buffer, bytes_read) == -1)
	    {
		verror_put_errno(errno);
		verror_put_string("writing %s", dest);
		goto error;
	    }
	}
    }
    while (bytes_read > 0);
    
    /* Success */
    return_code = 0;
	
  error:
    if (src_fd != -1)
    {
	close(src_fd);
    }
    
    if (dst_fd != -1)
    {
	close(dst_fd);

	if (return_code == -1)
	{
	    unlink(dest);
	}
    }
    
    return return_code;
}

static int
myproxy_authorize_init(myproxy_socket_attrs_t *attrs,
                       char *passphrase,
		       char *certfile)
{
   myproxy_response_t *server_response = NULL;
   myproxy_proto_response_type_t response_type;
   authorization_data_t *d; 
   /* just pointer into server_response->authorization_data, no memory is 
      allocated for this pointer */
   int return_status = -1;
   char buffer[8192];
   int bufferlen;

   do {
      server_response = malloc(sizeof(*server_response));
      memset(server_response, 0, sizeof(*server_response));
      if (myproxy_recv_response(attrs, server_response) < 0) {
	 //verror_put_string("Error in receive_response()");
	 verror_put_string((server_response->data).error_str);
	 goto end;
      }

      response_type = server_response->response_type;
      if (response_type == MYPROXY_AUTHORIZATION_RESPONSE) {
	 if (certfile == NULL)
	    d = authorization_create_response(
		              server_response->authorization_data,
			      AUTHORIZETYPE_PASSWD,
			      passphrase,
			      strlen(passphrase) + 1);
	 else 
	    d = authorization_create_response(
		               server_response->authorization_data,
			       AUTHORIZETYPE_CERT,
			       certfile,
			       strlen(certfile) + 1);
	 if (d == NULL) {
	    verror_put_string("Cannot create authorization response");
       	    goto end;
	 }

	 if (d->client_data_len + sizeof(int) > sizeof(buffer)) {
	       verror_put_string("Internal buffer too small");
	       goto end;
	 }
	 (*buffer) = d->method;
	 bufferlen = d->client_data_len + sizeof(int);

	 memcpy(buffer + sizeof(int), d->client_data, d->client_data_len);
	 /* Send the authorization data to the server */
	 if (myproxy_send(attrs, buffer, bufferlen) < 0) {
	    //verror_put_string("Error in myproxy_send()");
	    goto end;
	 }
      }
      myproxy_free(NULL, NULL, server_response);
      server_response = NULL;
   } while (response_type == MYPROXY_AUTHORIZATION_RESPONSE);

   return_status = 0;
end:
   myproxy_free(NULL, NULL, server_response);

   return return_status;
}
