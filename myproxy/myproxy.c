/*
 * myproxy.c
 *
 * See myproxy.h for documentation
 *
 */

#include "myproxy.h"
#include "gsi_socket.h"
#include "version.h"
#include "verror.h"

#include <errno.h> 
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

int convert_message(const char *buffer, const char *varname, 
                    char *line, const int linelen);

int 
myproxy_init_client(myproxy_socket_attrs_t *attrs) {
    struct sockaddr_in sin;
    struct hostent *host_info;
    char error_string[1024];

    attrs->socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (attrs->socket_fd == -1) {
	verror_put_errno(errno);
	verror_put_string("socket() failed");
        return -1;
    } 

    host_info = gethostbyname(attrs->pshost); 

    if (host_info == NULL)
    {
        verror_put_string("Unknown host \"%s\"\n", attrs->pshost);
        return -1;
    } 

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&(sin.sin_addr), host_info->h_addr, sizeof(sin.sin_addr));
    sin.sin_port = htons(attrs->psport);

    if (connect(attrs->socket_fd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        verror_put_errno(errno);
        verror_put_string("Unable to connect to %s\n", attrs->pshost);
        return -1;
    }

    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    
    if (attrs->gsi_socket == NULL) {
        verror_put_string("GSI_SOCKET_new()\n");
        return -1;
    }

   if (GSI_SOCKET_set_encryption(attrs->gsi_socket, 1) == GSI_SOCKET_ERROR)
   {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       verror_put_string("Error enabling encryption: %s\n", error_string);
       return -1;
   }


    return attrs->socket_fd;
}
    
int 
myproxy_authenticate_init(myproxy_socket_attrs_t *attrs, const char *proxyfile) 
{
   char error_string[1024];
   
   if (GSI_SOCKET_use_creds(attrs->gsi_socket, proxyfile) == GSI_SOCKET_ERROR) {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       verror_put_string("Error setting credentials to use: %s\n", error_string);
       return -1;
   }

   if (GSI_SOCKET_authentication_init(attrs->gsi_socket) == GSI_SOCKET_ERROR) {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       verror_put_string("Error authenticating: %s\n", error_string);
       return -1;
   }
   return 0;
}


int 
myproxy_authenticate_accept(myproxy_socket_attrs_t *attrs, char *client_name, const int namelen) 
{
    char error_string[1024];
   
    assert(client_name != NULL);

    if (GSI_SOCKET_authentication_accept(attrs->gsi_socket) == GSI_SOCKET_ERROR) {
        GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                    sizeof(error_string));

        verror_put_string("Error authenticating client: %s\n", error_string);

        return -1;
    }

    if (GSI_SOCKET_get_client_name(attrs->gsi_socket,
                                   client_name,
                                   namelen) == GSI_SOCKET_ERROR) {
        GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                    sizeof(error_string));
        verror_put_string("Error getting client name: %s\n", error_string);
        return -1;
    }
    return 0;
}

int
myproxy_init_delegation(myproxy_socket_attrs_t *attrs, const char *delegfile, const int lifetime)
{
  
  char error_string[1024];
 
  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_delegation_init_ext(attrs->gsi_socket, 
				     delegfile,  /* delegation file */
				     0,          /* flags */
				     lifetime,   /* lifetime */
				     NULL        /* restrictions */) == GSI_SOCKET_ERROR) {
    
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				sizeof(error_string));

    verror_put_string("Error delegating credentials: %s\n", error_string);
    return -1;
  }
  return 0;
}

int
myproxy_accept_delegation(myproxy_socket_attrs_t *attrs, char *data, const int datalen)
{
  char error_string[1024];

  assert(data != NULL);

  if (GSI_SOCKET_delegation_accept_ext(attrs->gsi_socket, data, datalen) == GSI_SOCKET_ERROR) {
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				sizeof(error_string));
    verror_put_string("Error accepting delegating credentials: %s\n", error_string);
    return -1;
  }
  
  return 0;
}

int
myproxy_serialize_request(const myproxy_request_t *request, char *data, const int datalen) 
{
    int len;
    int totlen = 0;

    assert(data != NULL);

    len = snprintf(data, datalen, "%s%s\n", MYPROXY_VERSION_STRING, request->version);
    if (len < 0) 
      return -1;
    
    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, "%s%d\n", MYPROXY_COMMAND_STRING, 
                   (myproxy_proto_request_type_t)request->command_type);
    if (len < 0)
      return -1;
    
    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, "%s%s\n", 
                   MYPROXY_USERNAME_STRING, request->username); 
    if (len < 0)
      return -1;

    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
                 "%s%s\n", MYPROXY_PASSPHRASE_STRING, request->passphrase);
    if (len < 0)
      return -1;

    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen, 
                 "%s%d\n", MYPROXY_LIFETIME_STRING, request->portal_lifetime);
    if (len < 0)
      return -1;
    totlen += len;
    data[totlen] = '\0';
    return totlen+1;
}

int 
myproxy_deserialize_request(const char *data, const int datalen,
                            myproxy_request_t *request)
{
    int len;
    char version_str[128];
    char command_str[128];
    char username_str[128];
    char passphrase_str[MAX_PASS_LEN+1];
    char lifetime_str[128];

    assert(request != NULL);
    assert(data != NULL);
    
    len = convert_message(data, (const char*)MYPROXY_VERSION_STRING, version_str, sizeof(version_str));
    if (len > 0) {
      request->version = (char *)malloc((len+1)*sizeof(char));
      strcpy(request->version, version_str);
    } else {
      return -1;
    }

    len = convert_message(data, (const char*)MYPROXY_COMMAND_STRING, command_str, sizeof(command_str));
    if (len > 0) {
      request->command_type = (myproxy_proto_response_type_t)atoi(command_str);
    } else {
      return -1;
    }

    len = convert_message(data, (const char*)MYPROXY_USERNAME_STRING, username_str, sizeof(username_str));
    if (len > 0) {
      request->username = (char *)malloc((len+1)*sizeof(char));
      strcpy(request->username, username_str);
    } else {
      return -1;
    }

    len = convert_message(data, MYPROXY_PASSPHRASE_STRING, 
                          passphrase_str, sizeof(passphrase_str));
    if (len > 0) {
      if ((sizeof(passphrase_str) < MIN_PASS_LEN) && (sizeof(passphrase_str) > MAX_PASS_LEN)) {
        return -1;
      } else {
        strncpy(request->passphrase, passphrase_str, sizeof(request->passphrase));
      }
    } else {
      return -1;
    }

    len = convert_message(data, MYPROXY_LIFETIME_STRING, 
                          lifetime_str, sizeof(lifetime_str));
    if (len > 0) {
      request->portal_lifetime = atoi(lifetime_str);
    } else {
      return -1;
    }
    return 0;
} 

int
myproxy_serialize_response(const myproxy_response_t *response, 
                           char *data, const int datalen) 
{
    int len;
    int totlen = 0;

    assert(data != NULL);
    assert(response != NULL);

    len = snprintf(data, datalen, "%s%s\n", MYPROXY_VERSION_STRING, response->version);
    if (len < 0)
        return -1;
    
    totlen += len;
    len = snprintf(&data[totlen], datalen - totlen,
                 "%s%d\n", MYPROXY_RESPONSE_STRING, 
                 (myproxy_proto_response_type_t)response->response_type);
    if (len < 0)
        return -1;
    
    totlen += len;

    /* Only add error string if necessary */
    if (strcmp(response->error_string, "") != 0) {
        len = snprintf(&data[totlen], datalen - totlen, 
                       "%s%s\n", MYPROXY_ERROR_STRING, response->error_string);
        if (len < 0)
	  return -1;

        totlen += len;
    }
    data[totlen] = '\0';

    return totlen+1;
}


int
myproxy_deserialize_response(myproxy_response_t *response,
                             const char *data, const int datalen) 
{
    int len;
    char version_str[128];
    char response_str[128];

    assert(data != NULL); 
      
    strcpy(response->error_string, "");

    len = convert_message(data, (const char*)MYPROXY_VERSION_STRING, version_str, sizeof(version_str));
    if (len > 0) {
      response->version = (char *)malloc((len+1)*sizeof(char));
      strcpy(response->version, version_str);
    } else {
      return -1;
    }

    len = convert_message(data, (const char*)MYPROXY_RESPONSE_STRING, response_str, sizeof(response_str));
    if (len > 0) {
      response->response_type = (myproxy_proto_response_type_t)atoi(response_str);
    } else {
      return -1;
    }

    /* It's ok if ERROR not present */
    len = convert_message(data, MYPROXY_ERROR_STRING, 
                          response->error_string, sizeof(response->error_string));
    if (len > 0) {
      response->error_string[len] = '\0';
    }
    return 0;
}

int 
myproxy_send(myproxy_socket_attrs_t *attrs,
		     const char *data, const int datalen) 
{
    char error_string[1024];

    assert(data != NULL);

    if (GSI_SOCKET_write_buffer(attrs->gsi_socket, data, datalen) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	verror_put_string("Error writing: %s\n", error_string);
	return -1;
    }
    return 0;
}

int 
myproxy_recv(myproxy_socket_attrs_t *attrs,
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
       verror_put_string("Error reading: %s\n", error_string);
       return -1;
   } else if (readlen == GSI_SOCKET_TRUNCATED) {
       verror_put_string("Response was truncated\n");
       return -2;
   }
   return readlen;
} 

void
myproxy_destroy(myproxy_socket_attrs_t *attrs, 
		       myproxy_request_t *request, 
		       myproxy_response_t *response)
{ 
    if ((attrs == NULL) || (request == NULL) || (response == NULL)) 
      return;
  
    if (attrs->pshost != NULL) 
      free(attrs->pshost);

    if (request->version != NULL)     
      free(request->version);
    
    if (request->username != NULL) 
      free(request->username);
    
    if (response->version != NULL) 
      free(response->version);

    GSI_SOCKET_destroy(attrs->gsi_socket);
    close(attrs->socket_fd);

    free(attrs);
    free(request);
    free(response);
}

/*--------- Helper functions ------------*/
/*
 * convert_message()
 *
 * Searches a buffer and locates varname. Stores contents of varname into line
 * e.g. convert_message(buf, "VERSION=", version, sizeof(version));
 * If multiple varnames exist, the contents are concatenated following a newline
 *
 * return the number of characters copied into the line 
 * (not including the terminating '\0'), or -1 if varname not found or error
 */
int convert_message(const char *buffer, const char *varname, 
		    char *line, const int linelen) {

    int i = 0;
    int j = 0;
    int foundone = 0;
    char *ptr, *find;
    assert(buffer != NULL);
    assert(varname != NULL);
    assert(line != NULL);
    
    while ((find = strstr(&buffer[j], varname)) != NULL) {
        /* find start of varname value */
        find += strlen(varname);
        j = strlen(buffer) - strlen(find);
        /* loop through until LF or NUL */
        for (ptr = find; ((*ptr != '\n') && (*ptr != '\0')); ptr++, j++) {
            if (i > linelen-1) {
                return -1;
            }
            line[i] = *ptr;
            i++; 
        }
        /* add LF */
        line[i] = '\n';
        i++;
        foundone = 1;
    }
    if (!foundone) return -1;
    /* replace final LF with NUL */
    line[i-1] = '\0';
    return i -1;
}
