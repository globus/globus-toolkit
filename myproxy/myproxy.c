/*
 * myproxy.c
 *
 * See myproxy.h for documentation
 *
 */

#include "myproxy.h"
#include "gsi_socket.h"
#include "version.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <unistd.h>
#include <assert.h>


int 
myproxy_init_client(myproxy_socket_attrs_t *attrs) 
{
    char error_string[1024]; 
    struct sockaddr_in sin;
    struct hostent *host_info;

    attrs->socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (attrs->socket_fd == -1)
    {
        perror("socket");
        return -1;
    } 

    host_info = gethostbyname(attrs->pshost); 

    if (host_info == NULL)
    {
        fprintf(stderr, "Unknown host \"%s\"\n", attrs->pshost);
        return -1;
    } 

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&(sin.sin_addr), host_info->h_addr, sizeof(sin.sin_addr));
    sin.sin_port = htons(attrs->psport);

    if (connect(attrs->socket_fd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
        perror("connect\n");
        return -1;
    }

    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    
    if (attrs->gsi_socket == NULL)
    {
	perror("GSI_SOCKET_new()\n");
	return -1;
    }

    if (GSI_SOCKET_authentication_init(attrs->gsi_socket) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error authenticating: %s\n", error_string);
	return -1;
    }
    return attrs->socket_fd;
}


int
myproxy_create_request(const myproxy_request_t *request, char *data, const int datalen) 
{
    int len;
    int totlen = 0;

    assert(data != NULL);

    len = snprintf(data, datalen, "%s%s\n", MYPROXY_VERSION_STRING, request->version);
    if (len == -1) 
      return -1;
    
    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
		   "%s%s\n", MYPROXY_COMMAND_STRING, request->command);
    if (len == -1) 
      return -1;
    
    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
		   "%s%s\n", MYPROXY_USERNAME_STRING, request->username);
    if (len == -1)
      return -1;

    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
		   "%s%s\n", MYPROXY_PASSPHRASE_STRING, request->passphrase);
    if (len == -1)
      return -1;

    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
		   "%s%d\n", MYPROXY_LIFETIME_STRING, 3600*request->hours);
    if (len == -1)
      return -1;
    
    totlen += len;
    return totlen;
}


int 
myproxy_send_request(myproxy_socket_attrs_t *attrs,
		     const char *data, const int datalen) 
{
    char error_string[1024];

    assert(data != NULL);

    if (GSI_SOCKET_write_buffer(attrs->gsi_socket, data, datalen) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error writing: %s\n", error_string);
	return -1;
    }
    return 0;
}

int 
myproxy_recv_response(myproxy_socket_attrs_t *attrs,
		     char *data, const int datalen) 
{
   char error_string[1024];
   int readlen;

   assert(data != NULL);
   
   readlen = GSI_SOCKET_read_buffer(attrs->gsi_socket, data, datalen);
   if (readlen == GSI_SOCKET_ERROR)
   {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
       fprintf(stderr, "Error reading: %s\n", error_string);
       return -1;
   } else if (readlen == GSI_SOCKET_TRUNCATED) {
       fprintf(stderr, "Response was truncated\n");
       return -2;
   } 
   return readlen;
} 

int
myproxy_create_response(myproxy_response_t *response, const char *data, const int datalen) 
{
    int len;
    char version_str[128];
    char response_str[128];
    char error_str[1024];

    response->version = NULL;
    response->response_string = NULL;
    response->error_string = NULL;

    len = convert_message(data, (const char*)MYPROXY_VERSION_STRING, version_str, sizeof(version_str));
    if (len > 0) {
      response->version = (char *)malloc((len+1)*sizeof(char));
      strncpy(response->version, version_str, len);
    } else {
      return -1;
    }

    len = convert_message(data, (const char*)MYPROXY_RESPONSE_STRING, response_str, sizeof(response_str));
    if (len > 0) {
      response->response_string = (char *)malloc((len+1)*sizeof(char));
      strncpy(response->response_string, response_str, len);
    } else {
      return -1;
    }

    len = convert_message(data, MYPROXY_ERROR_STRING, error_str, sizeof(error_str));
    if (len > 0) {
      response->error_string = (char *)malloc((len+1)*sizeof(char));
      strncpy(response->error_string, error_str, len);
    } else {
      return -1;
    }
    return 0;
}

int
myproxy_check_response(myproxy_response_t *response) 
{
    int err = 0;

    if (strcmp(response->version, MYPROXY_VERSION) != 0) {
      fprintf(stderr, "Invalid version number received from myproxy-server\n");
      err = 1;
    } 

    if (strcmp(response->response_string, MYPROXY_ERROR_RESPONSE)) {
      fprintf(stderr, "myproxy_check_response: received MYPROXY_ERROR_RESPONSE\n");
      fprintf(stderr, "%s", response->error_string);
    } else if (strcmp(response->response_string, MYPROXY_OK_RESPONSE)) {
      fprintf(stderr, "myproxy_check_response: received MYPROXY_OK_RESPONSE\n");
    } else {
      fprintf(stderr, "myproxy_check_response: received unknown response\n");
      err = 1;
    }
    
    return err;
} 
  

int
myproxy_delegate_proxy(myproxy_socket_attrs_t *attrs, const char *delegfile)
{
  char file[1024];
  char error_string[1024];
  if (delegfile == NULL) {
    sprintf(file, "%s", MYPROXY_DEFAULT_PROXY);
  } else {
    strncpy(file, delegfile, strlen(delegfile)); 
  }

  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_delegation_init_ext(attrs->gsi_socket, 
				     file /* delegation file */,
				     0 /* flags */,
				     0 /* lifetime */,
				     NULL /* restrictions */) == GSI_SOCKET_ERROR) {
    
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				sizeof(error_string));
    fprintf(stderr, "Error delegating credentials: %s\n", error_string);
    return -1;
  }
  return 0;
}

void
myproxy_destroy_client(myproxy_socket_attrs_t *attrs, 
		       myproxy_request_t *request, 
		       myproxy_response_t *response)
{ 
    if ((attrs == NULL) || (request == NULL)) 
      return;
  
    if (attrs->pshost != NULL) 
      free(attrs->pshost);

    if (request->version != NULL)     
      free(request->version);
    
    if (request->username != NULL) 
      free(request->username);
    
    if (request->command != NULL) 
      free(request->command);
    
    if (response->version != NULL) 
      free(response->version);
    
    if (response->response_string != NULL) 
      free(response->response_string);
    
    if (response->error_string != NULL) 
      free(response->error_string);

    GSI_SOCKET_destroy(attrs->gsi_socket);
    close(attrs->socket_fd);

    free(attrs);
    free(request);
}

/*--------- Helper functions ------------*/
int convert_message(const char *buffer, const char *varname, 
		    char *line, const int linelen) {

    int i = 0;
    int foundone = 0;
    char *ptr, *first;
    assert(buffer != NULL);
    assert(varname != NULL);
    while ((first = strstr(&buffer[i], varname)) != NULL) {
        first += strlen(varname);
        for (ptr = first; *ptr != '\n'; ptr++) {
            if (i > linelen-1) {
                return -1;
            }
            line[i] = *ptr;
            i++;
        }
        /* add LF */
        line[i] = *ptr++;
        i++;
        foundone = 1;
    }
    if (!foundone) return -1;
    /* replace final LF with NUL */
    line[i-1] = '\0';
    return (i-1 == 0 ? -1 : i-1);  
}
	
