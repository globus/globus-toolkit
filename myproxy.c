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
#include "string_funcs.h"

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
#include <limits.h>

/**********************************************************************
 *
 * Internal functions
 *
 */
static int convert_message(const char		*buffer,
			   int			buffer_len,
			   const char		*varname, 
			   int			flags,
			   char			*line,
			   int			linelen);

/* Values for convert_message() flags */
#define CONVERT_MESSAGE_NO_FLAGS		0x0000
#define CONVERT_MESSAGE_ALLOW_MULTIPLE		0x0001

#define CONVERT_MESSAGE_DEFAULT_FLAGS		CONVERT_MESSAGE_NO_FLAGS
#define CONVERT_MESSAGE_KNOWN_FLAGS		CONVERT_MESSAGE_ALLOW_MULTIPLE


static int parse_command(const char			*command_str,
			 myproxy_proto_request_type_t	*command_value);

/* returns 0 if character not found */
static int findchr (const char *p, const char c)
{
  int i = 0;

  while (*(p+i) != c && *(p+i) != '\0') i++;

  return (*(p+i) == '\0')?0:i; 
}

static int countchr (const char *p, const char c)
{
    int i=0;

    while (*p != '\0') {
	if (*p == c) i++;
	p++;
    }

    return i;
}

static int parse_add_creds (char *response_str, char ***pstrs, int *num_creds)
{
	char *p = response_str;
	int tmp = 0, len = 0;
	int idx = 0;
	int num_entries;
	char **strs;

	/* allocate memory for a string-list, returned to caller */
	num_entries = countchr(response_str, ',')+1;
	*pstrs = strs = (char **)malloc(num_entries*sizeof(char *));

	do
	{
		tmp = findchr(p+len, ',');

		if (tmp == 0) /* last credential name */
		{
			size_t slen;
			slen = strlen (p+len);
			strs[idx] = (char *) malloc(slen+1);
			if (strncpy (strs[idx], p+len, slen) == NULL)
				return -1;

			strs[idx++][slen] = '\0';
		}
		else
		{
			strs[idx] = (char *) malloc (tmp+1);
			if (strncpy (strs[idx], p+len, tmp) == NULL)
				return -1;

			strs[idx++][tmp] = '\0';
		}

		len += (tmp+1);
	}
	while (tmp != 0);

	assert(num_entries == idx);
	
	*num_creds = idx;
	return 0;
}
		

		
static const char *
encode_command(const myproxy_proto_request_type_t	command_value);

static int
parse_string(const char			*str,
	       int			*value);

static int
encode_integer(int				value,
		char				*string,
		int				string_len);
		
static int
parse_response_type(const char				*type_str,
		    myproxy_proto_response_type_t	*type_value);

static const char *
encode_response(myproxy_proto_response_type_t	response_value);

static int
string_to_int(const char			*string,
	      int				*integer);

static char *
parse_entry(char *buffer, authorization_data_t *data);

static int
parse_auth_data(char *buffer, authorization_data_t ***auth_data);

/* Values for string_to_int() */
#define STRING_TO_INT_SUCCESS		1
#define STRING_TO_INT_ERROR		-1
#define STRING_TO_INT_NONNUMERIC	0

/**********************************************************************
 *
 * Exported functions
 *
 */

int 
myproxy_init_client(myproxy_socket_attrs_t *attrs) {
    struct sockaddr_in sin;
    struct hostent *host_info;
    char error_string[1024];
    char *expected_dn;
    char *port_range;
    
    attrs->socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (attrs->socket_fd == -1) {
	verror_put_errno(errno);
	verror_put_string("socket() failed");
        return -1;
    } 

    host_info = gethostbyname(attrs->pshost); 

    if ((port_range = getenv("MYPROXY_TCP_PORT_RANGE")) ||
	(port_range = getenv("GLOBUS_TCP_PORT_RANGE"))) {
	unsigned short port, max_port;
	if (sscanf(port_range, "%hu,%hu", &port, &max_port)) {
	    memset(&sin, 0, sizeof(sin));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = htons(port);
	    while (bind(attrs->socket_fd, (struct sockaddr *)&sin,
			sizeof(sin)) < 0) {
		if (errno != EADDRINUSE || port >= max_port) {
		    verror_put_string("Error in bind()");
		    return -1;
		}
		sin.sin_port = htons(++port);
	    }
	    /* fprintf(stderr, "Socket bound to port %hu.\n", port); */
	}
    }

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

   /*
    * Are we connecting to a server that has a non-standard DN.
    */
   expected_dn = getenv("MYPROXY_SERVER_DN");
   
   if (expected_dn != NULL)
   {
       fprintf(stderr, "NOTE: Expecting non-standard server DN:\n\t\"%s\"\n",
	       expected_dn);
       
       if (GSI_SOCKET_set_expected_peer_name(attrs->gsi_socket,
					     expected_dn) == GSI_SOCKET_ERROR)
       {
	   GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
	   verror_put_string("Error setting expected peername: %s\n",
			     error_string);
	   return -1;
       }
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
myproxy_init_delegation(myproxy_socket_attrs_t *attrs, const char *delegfile, const int lifetime, char *passphrase)
{
  
  char error_string[1024];
 
  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_delegation_init_ext(attrs->gsi_socket, 
				     delegfile,
				     lifetime,
				     passphrase) == GSI_SOCKET_ERROR) {
    
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				sizeof(error_string));

    verror_put_string("Error delegating credentials: %s\n", error_string);
    return -1;
  }
  return 0;
}

int
myproxy_accept_delegation(myproxy_socket_attrs_t *attrs, char *data, const int datalen, char *passphrase)
{
  char error_string[1024];

  assert(data != NULL);

  if (GSI_SOCKET_delegation_accept_ext(attrs->gsi_socket, data, datalen, passphrase) == GSI_SOCKET_ERROR) {
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				sizeof(error_string));
    verror_put_string("Error accepting delegated credentials: %s\n", error_string);
    return -1;
  }
  
  return 0;
}

int
myproxy_serialize_request(const myproxy_request_t *request, char *data, const int datalen) 
{
    int len;
    int totlen = 0;
    char lifetime_string[64];
    char str[64];
    const char *command_string;

    assert(data != NULL);
    assert(datalen > 0);
   
    /* version */
    data[0] = '\0';
    
    len = concatenate_strings(data, datalen, MYPROXY_VERSION_STRING,
			      request->version, "\n", NULL);
    if (len < 0) 
      return -1;
    
    totlen += len;

    /* command type */
    command_string = encode_command((myproxy_proto_request_type_t)request->command_type);
    
    if (command_string == NULL)
    {
	return -1;
    }
    
    len = concatenate_strings(data, datalen, MYPROXY_COMMAND_STRING, 
			      command_string, "\n", NULL);
    
    if (len < 0)
      return -1;
    
    totlen += len;

    /* username */
    len = concatenate_strings(data, datalen, MYPROXY_USERNAME_STRING,
			      request->username, "\n", NULL); 
    if (len < 0)
      return -1;

    totlen += len;

    /* passphrase */
    len = concatenate_strings(data, datalen, MYPROXY_PASSPHRASE_STRING,
			       request->passphrase, "\n", NULL);
    if (len < 0)
      return -1;

    totlen += len;

    /* lifetime */
    if (encode_integer(request->proxy_lifetime,
			lifetime_string,
			sizeof(lifetime_string)) == -1)
    {
	return -1;
    }
			
    len = concatenate_strings(data, datalen, MYPROXY_LIFETIME_STRING,
			      lifetime_string, "\n", NULL);
    if (len < 0)
      return -1;

    totlen += len;
   
    /* retrievers */
    if (request->retrievers != NULL)
    { 
      len = concatenate_strings(data, datalen, MYPROXY_RETRIEVER_STRING,
			      request->retrievers, "\n", NULL); 
      if (len < 0)
        return -1;

      totlen += len;

    }

    /* renewers */
    if (request->renewers != NULL)
    { 
      len = concatenate_strings(data, datalen, MYPROXY_RENEWER_STRING,
			      request->renewers, "\n", NULL); 
      if (len < 0)
        return -1;

      totlen += len;

    }

    /* credential name */
    if (request->credname!= NULL)
    {
	char *buf = strdup (request->credname);
	strip_char ( buf, '\n');
				
      len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX, "_", MYPROXY_CRED_NAME_STRING,
			      buf, "\n", NULL); 
      if (len < 0)
        return -1;

      totlen += len;

    }

    /* credential description */
    if (request->creddesc != NULL)
    { 
	char *buf = strdup (request->creddesc);
	strip_char ( buf, '\n');
      len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX, "_", MYPROXY_CRED_DESC_STRING,
			      buf, "\n", NULL); 
      if (len < 0)
        return -1;

      totlen += len;

    }

    /* force database write */
    if (encode_integer(request->force_credential_overwrite,
			str,
			sizeof(str)) == -1)
    {
	return -1;
    }
			
    len = concatenate_strings(data, datalen, MYPROXY_FORCE_CREDENTIAL_OVERWRITE,
			      str, "\n", NULL);
    if (len < 0)
      return -1;

    totlen += len;
   
    return totlen+1;
}

int 
myproxy_deserialize_request(const char *data, const int datalen,
                            myproxy_request_t *request)
{
    int len;
    char tmp[100];
    char buf[1024];

    assert(request != NULL);
    assert(data != NULL);

    /* version */
    len = convert_message(data, datalen,
			  MYPROXY_VERSION_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len <= -1)
    {
	verror_prepend_string("Error parsing version from client request");
	return -1;
    }

    request->version = strdup(buf);
    
    if (request->version == NULL)
    {
	verror_put_errno(errno);
	return -1;
    }

    /* command */
    len = convert_message(data, datalen,
			  MYPROXY_COMMAND_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len <= -1)
    {
	verror_prepend_string("Error parsing command from client request");
	return -1;
    }
    
    if (parse_command(buf, &request->command_type) == -1)
    {
	return -1;
    }

    /* username */
    len = convert_message(data, datalen,
			  MYPROXY_USERNAME_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));
    if (len <= -1)
    {
	verror_prepend_string("Error parsing usename from client request");
	return -1;
    }
    
    request->username = strdup(buf);

    if (request->username == NULL)
    {
	verror_put_errno(errno);
	return -1;
    }

    /* passphrase */
    len = convert_message(data, datalen,
			  MYPROXY_PASSPHRASE_STRING, 
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
                          buf, sizeof(buf));

    if (len <= -1) 
    {
	verror_prepend_string("Error parsing passphrase from client request");
	return -1;
    }
    
    /* XXX request_passphrase is a static buffer. Why? */
    strncpy(request->passphrase, buf, sizeof(request->passphrase));

    /* lifetime */
    len = convert_message(data, datalen,
			  MYPROXY_LIFETIME_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
                          buf, sizeof(buf));
    if (len <= -1)
    {
	verror_prepend_string("Error parsing lifetime from client request");
	return -1;
    }
    
    if (parse_string(buf, &request->proxy_lifetime) == -1)
    {
	return -1;
    }

    /* retriever */
    len = convert_message(data, datalen,
			  MYPROXY_RETRIEVER_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len == -2)  /*-2 indicates string not found*/
       request->retrievers = NULL;
    else
    if (len <= -1)
    {
	verror_prepend_string("Error parsing retriever from client request");
	return -1;
    }
    else
    {
      request->retrievers = strdup(buf);
    
      if (request->retrievers == NULL)
      {
	verror_put_errno(errno);
	return -1;
      }
    }


    /* renewer */
    len = convert_message(data, datalen,
			  MYPROXY_RENEWER_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len == -2)  /*-2 indicates string not found*/
       request->renewers = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing renewer from client request");
	return -1;
       }
       else
       {
         request->renewers = strdup(buf);
    
         if (request->renewers == NULL)
         {
	  verror_put_errno(errno);
	  return -1;
         }
       }

    /* credential name */
    tmp[0] = '\0';
    len = concatenate_strings (tmp, sizeof(tmp), MYPROXY_CRED_PREFIX, "_", 
				MYPROXY_CRED_NAME_STRING, NULL);

    if (len == -1)
	return -1;
				
    len = convert_message(data, datalen,
			  tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len == -2)  /*-2 indicates string not found - assign default*/
	request->credname = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing credential name from client request");
	return -1;
       }
       else
       {
         request->credname = strdup(buf);
    
         if (request->credname == NULL)
         {
	  verror_put_errno(errno);
	  return -1;
         }
       }

    /* credential description */
    tmp[0] = '\0';
    len = concatenate_strings (tmp, sizeof(tmp), MYPROXY_CRED_PREFIX, "_",
    				MYPROXY_CRED_DESC_STRING, NULL);

    len = convert_message(data, datalen,
			  tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));

    if (len == -2)  /*-2 indicates string not found*/
	request->creddesc = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing credential description from client request");
	return -1;
       }
       else
       {
         request->creddesc = strdup(buf);
    
         if (request->creddesc == NULL)
         {
	  verror_put_errno(errno);
	  return -1;
         }
       }

    /* force credential overwrite */
    len = convert_message(data, datalen,
			  MYPROXY_FORCE_CREDENTIAL_OVERWRITE,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
                          buf, sizeof(buf));
    if (len == -1)
    {
	verror_prepend_string("Error parsing force_database_write from client request");
	return -1;
    }
    else
	if (len == -2) /* string not found */
         request->force_credential_overwrite = 0;
      else
    	if (parse_string(buf, &request->force_credential_overwrite) == -1)  
    	{
		return -1;
    	}

    /* Success */
    return 0;
} 

int
myproxy_serialize_response(const myproxy_response_t *response, 
                           char *data, const int datalen) 
{
    int len;
    int totlen = 0;
    authorization_data_t **p;
    const char *response_string;
    
    assert(data != NULL);
    assert(response != NULL);

    data[0] = '\0';

    /*Version*/    
    len = concatenate_strings(data, datalen, MYPROXY_VERSION_STRING,
			      response->version, "\n", NULL);
    if (len < 0)
        return -1;
    
    totlen += len;

    response_string = encode_response((myproxy_proto_response_type_t) response->response_type);

    /*Response string*/
    if (response_string == NULL) {
	return -1;
    }
    
    len = concatenate_strings(data, datalen, MYPROXY_RESPONSE_TYPE_STRING, 
			      response_string, "\n", NULL);
    if (len < 0)
        return -1;
    
    totlen += len;

    /*Authorization data*/
    if ((p = response->authorization_data)) {
       while (*p) {
	  len = concatenate_strings(data, datalen, MYPROXY_AUTHORIZATION_STRING,
		     authorization_get_name((*p)->method), ":", 
		     (*p)->server_data, "\n", NULL);
	  if (len < 0)
	     return -1;
	  totlen += len;
	  p++;
       }
    }

    /* Include credential info in OK response to INFO request */
    if (response->response_type == MYPROXY_OK_RESPONSE &&
	response->info_creds) {
	int first_cred = 1;
	myproxy_creds_t *cred;
	char date[40];
	for (cred = response->info_creds; cred != NULL; cred = cred->next) {
	    /* Include name on first cred only.  Other creds are indexed by
	       name, so there is no need for an additional name field. */
	    if (cred->credname && first_cred) {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", MYPROXY_CRED_NAME_STRING,
					  cred->credname, "\n", NULL);
		if (len == -1)
		    goto error;
		totlen += len;
	    }
	    assert(cred->credname || first_cred);
	    if (cred->creddesc) {
		if (first_cred) {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", MYPROXY_CRED_DESC_STRING,
					      cred->creddesc, "\n", NULL);
		} else {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", cred->credname,
					      "_", MYPROXY_CRED_DESC_STRING,
					      cred->creddesc, "\n", NULL);
		}
		if (len == -1)
		    goto error;
		totlen += len;
	    }
	    sprintf(date, "%lu",  cred->start_time);
	    if (first_cred) {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", MYPROXY_START_TIME_STRING, 
					  date, "\n", NULL);
	    } else {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", cred->credname,
					  "_", MYPROXY_START_TIME_STRING, 
					  date, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    totlen += len;
	    sprintf(date, "%lu", cred->end_time);
	    if (first_cred) {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", MYPROXY_END_TIME_STRING, 
					  date, "\n", NULL);
	    } else {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", cred->credname,
					  "_", MYPROXY_END_TIME_STRING, 
					  date, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    totlen += len;
	    if (first_cred) {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", MYPROXY_CRED_OWNER_STRING,
					  cred->owner_name, "\n", NULL);
	    } else {
		len = concatenate_strings(data, datalen, MYPROXY_CRED_PREFIX,
					  "_", cred->credname,
					  "_", MYPROXY_CRED_OWNER_STRING,
					  cred->owner_name, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    totlen += len;
	    if (cred->retrievers) {
		if (first_cred) {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", MYPROXY_RETRIEVER_STRING,
					      cred->retrievers, "\n", NULL);
		} else {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", cred->credname,
					      "_", MYPROXY_RETRIEVER_STRING,
					      cred->retrievers, "\n", NULL);
		}
		if (len == -1)
		    goto error;
		totlen += len;
	    }	
	    if (cred->renewers) {
		if (first_cred) {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", MYPROXY_RENEWER_STRING,
					      cred->renewers, "\n", NULL);
		} else {
		    len = concatenate_strings(data, datalen,
					      MYPROXY_CRED_PREFIX,
					      "_", cred->credname,
					      "_", MYPROXY_RENEWER_STRING,
					      cred->renewers, "\n", NULL);
		}
		if (len == -1)
		    goto error;
		totlen += len;
	    }
	    first_cred = 0;
	}
	if (response->info_creds->next) {
	    len = concatenate_strings(data, datalen,
				      MYPROXY_ADDITIONAL_CREDS_STRING, NULL);
	    totlen += len;
	    for (cred = response->info_creds->next;
		 cred != NULL;
		 cred = cred->next) {
		if (cred->next) {
		    len = concatenate_strings(data, datalen, cred->credname,
					      "," , NULL);
		} else {
		    len = concatenate_strings(data, datalen, cred->credname,
					      NULL);
		}
		totlen += len;
	    }
	}
    }

    /* Only add error string if necessary */
    if (response->response_type == MYPROXY_ERROR_RESPONSE) {
	char *buf;
	buf = strdup (verror_get_string());
	strip_char (buf, '\n');
        len = concatenate_strings(data, datalen, MYPROXY_ERROR_STRING,
				  buf, "\n", NULL);
        if (len < 0)
	  return -1;
        totlen += len;
	free(buf);
    }

    return totlen+1;

    error:
    	return -1;
}


int
myproxy_deserialize_response(myproxy_response_t *response,
                             const char *data, const int datalen) 
{
    int len;
    char version_str[128];
    char response_type_str[128];
    char authorization_data[4096];
    int value,i, num_creds ;
    char tmp[100];
    char buffer[1024];

    assert(data != NULL); 

    response->authorization_data = NULL;

    len = convert_message(data, datalen,
			  MYPROXY_VERSION_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  version_str, sizeof(version_str));

    if (len == -1) {
	verror_prepend_string("Error parsing version from server response");
	return -1;
    }

    if (response->version) {
	free(response->version);
    }

    response->version = strdup(version_str);

    if (response->version == NULL) {
	verror_put_errno(errno);
	return -1;
    }

    len = convert_message(data, datalen,
			  MYPROXY_RESPONSE_TYPE_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  response_type_str, sizeof(response_type_str));

    if (len == -1 || len == -2) {
	return -1;
    }

    if (parse_response_type(response_type_str,
			    &response->response_type) == -1) {
	return -1;
    }

    if (response->response_type == MYPROXY_ERROR_RESPONSE) {
	/* It's ok if ERROR not present */
	response->error_str = (char *) malloc (1024);
	len = convert_message(data, datalen,
			      MYPROXY_ERROR_STRING, 
			      CONVERT_MESSAGE_ALLOW_MULTIPLE,
			      response->error_str,
			      1024);
	return 0;
    }

    /* Parse any cred info in response */
    
    /* start time */
    tmp[0] = '\0';
    len = concatenate_strings(tmp, sizeof(tmp), MYPROXY_CRED_PREFIX, "_",
			      MYPROXY_START_TIME_STRING, NULL);
    if (len < 0) return -1;
    len = convert_message(data, datalen, tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buffer, sizeof(buffer));
    if (len == -1) return -1;

    if (len > 0) {		/* credential info present */
	response->info_creds = malloc(sizeof(struct myproxy_creds));
	memset(response->info_creds, 0, sizeof(struct myproxy_creds));

	switch(string_to_int(buffer, &value)) {
	case STRING_TO_INT_SUCCESS:
	    response->info_creds->start_time = value;
	    break;
	case STRING_TO_INT_NONNUMERIC:
	    verror_put_string("Non-numeric characters in CRED_START_TIME \"%s\"", buffer);
	    return -1;
	case STRING_TO_INT_ERROR:
	    return -1;
	}

    	tmp[0] = '\0';
    	len = concatenate_strings (tmp, sizeof(tmp), MYPROXY_CRED_PREFIX,
				   "_", MYPROXY_END_TIME_STRING, NULL);
    	if (len < 0) return -1;
		
	len = convert_message(data, datalen, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      buffer, sizeof(buffer));

	if (len > 0) {
	    switch(string_to_int(buffer, &value)) {
	    case STRING_TO_INT_SUCCESS:
		response->info_creds->end_time = value;
		break;
	    case STRING_TO_INT_NONNUMERIC:
		verror_put_string("Non-numeric characters in CRED_END_TIME \"%s\"", buffer);
		return -1;
	    case STRING_TO_INT_ERROR:
		return -1;
	    }
	}

	tmp[0] = '\0';
	len = concatenate_strings(tmp, sizeof(tmp), MYPROXY_CRED_PREFIX,
				  "_", MYPROXY_CRED_DESC_STRING, NULL);
	if (len < 0) return -1;

	len = convert_message(data, datalen, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      buffer, sizeof(buffer));
	if (len == -1) return -1;
	if (len > 0)
	    response->info_creds->creddesc = strdup(buffer);
		
	tmp[0] = '\0';
    	len = concatenate_strings(tmp, sizeof(tmp), MYPROXY_CRED_PREFIX,
				  "_", MYPROXY_CRED_OWNER_STRING, NULL);
    	if (len < 0) return -1;
		
	len = convert_message(data, datalen, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      buffer, sizeof(buffer));
    	if (len == -1) return -1;
	if (len >= 0)
	    response->info_creds->owner_name = strdup(buffer); 

	tmp[0] = '\0';
    	len = concatenate_strings(tmp, sizeof(tmp), MYPROXY_CRED_PREFIX,
				  "_", MYPROXY_RETRIEVER_STRING, NULL);
    	if (len < 0) return -1;
		
	len = convert_message(data, datalen, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      buffer, sizeof(buffer));
    	if (len == -1) return -1;
	if (len >= 0)
	    response->info_creds->retrievers = strdup(buffer); 

	tmp[0] = '\0';
    	len = concatenate_strings(tmp, sizeof(tmp), MYPROXY_CRED_PREFIX,
				  "_", MYPROXY_RENEWER_STRING, NULL);
    	if (len < 0) return -1;
		
	len = convert_message(data, datalen, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      buffer, sizeof(buffer));
    	if (len == -1) return -1;
	if (len >= 0)
	    response->info_creds->renewers = strdup(buffer); 

	len = convert_message(data, datalen, MYPROXY_ADDITIONAL_CREDS_STRING,
			      CONVERT_MESSAGE_DEFAULT_FLAGS, 
			      buffer, sizeof(buffer));

    	if (len == -1) return -1;
	if (len >= 0) {		/* addl credentials */
	    char **strs;
	    struct myproxy_creds *cred = response->info_creds;

	    len = parse_add_creds(buffer, &strs, &num_creds);
	    if (len == -1) {
		verror_put_string("Error parsing additional cred string");
		return -1;
	    }

	    for (i = 0; i < num_creds; i++) {
		cred->next = malloc(sizeof(struct myproxy_creds));
		cred = cred->next;
		memset(cred, 0, sizeof(struct myproxy_creds));

		cred->credname = strdup(strs[i]);

		tmp[0] = '\0';
		len = concatenate_strings(tmp, sizeof(tmp),
					  MYPROXY_CRED_PREFIX, "_", strs[i],
					  "_", MYPROXY_CRED_DESC_STRING, NULL);
		if (len == -1) return -1;

		len = convert_message(data, datalen, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
					buffer, sizeof(buffer));
		if (len == -1) return -1;
			
		if (len >= 0)
		    cred->creddesc = strdup(buffer);

		tmp[0]='\0';
		len = concatenate_strings (tmp, sizeof(tmp),
					   MYPROXY_CRED_PREFIX, "_", strs[i],
					   "_", MYPROXY_START_TIME_STRING,
					   NULL);
		if (len == -1) return -1;

		len = convert_message(data, datalen, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      buffer, sizeof(buffer));
		if (len == -1) return -1;
		if (len > 0) {
		    switch(string_to_int(buffer, &value)) {
		    case STRING_TO_INT_SUCCESS:
			cred->start_time = value;
			break;
		    case STRING_TO_INT_NONNUMERIC:
			verror_put_string("Non-numeric characters in CRED_START_TIME \"%s\"", buffer);
			return -1;
		    case STRING_TO_INT_ERROR:
			return -1;
		    }
		}

		tmp[0] = '\0';
		len = concatenate_strings(tmp, sizeof(tmp),
					  MYPROXY_CRED_PREFIX, "_", strs[i],
					  "_", MYPROXY_END_TIME_STRING, NULL);
		if (len == -1) return -1;

		len = convert_message(data, datalen, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      buffer, sizeof(buffer));
		if (len == -1) return -1;
		if (len > 0) {
		    switch(string_to_int(buffer, &value)) {
		    case STRING_TO_INT_SUCCESS:
			cred->end_time = value;
			break;
		    case STRING_TO_INT_NONNUMERIC:
			verror_put_string("Non-numeric characters in CRED_END_TIME \"%s\"", buffer);
			return -1;
		    case STRING_TO_INT_ERROR:
			return -1;
		    }
		}

		tmp[0] = '\0';
		len = concatenate_strings (tmp, sizeof(tmp),
					   MYPROXY_CRED_PREFIX, "_", strs[i],
					   "_", MYPROXY_CRED_OWNER_STRING,
					   NULL);
		if (len == -1) return -1;
		
		len = convert_message(data, datalen, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      buffer, sizeof (buffer));
		if (len == -1) return -1;
			
		if (len >= 0)
		    cred->owner_name = strdup(buffer);

		tmp[0] = '\0';
		len = concatenate_strings(tmp, sizeof(tmp),
					  MYPROXY_CRED_PREFIX, "_", strs[i],
					  "_", MYPROXY_RETRIEVER_STRING,
					  NULL);
		if (len == -1) return -1;

		len = convert_message (data, datalen, tmp,
				       CONVERT_MESSAGE_DEFAULT_FLAGS,
				       buffer, sizeof (buffer));
		if (len == -1) return -1;
		
		if (len >= 0)
		    cred->retrievers = strdup(buffer);

		tmp[0] = '\0';
		len = concatenate_strings (tmp, sizeof(tmp),
					   MYPROXY_CRED_PREFIX, "_", strs[i],
					   "_", MYPROXY_RENEWER_STRING, NULL);
		if (len == -1) return -1;

		len = convert_message(data, datalen, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      buffer, sizeof (buffer));
		if (len == -1) return -1;
			
		if (len >= 0)
		    cred->renewers = strdup(buffer);

	    }
	    /* de-allocate string-list from parse_add_creds() */
	    for (i=0; i < num_creds; i++) {
		free(strs[i]);
	    }
	    free(strs);
	}
    }

    len = convert_message(data, datalen,
	                  MYPROXY_AUTHORIZATION_STRING,
			  CONVERT_MESSAGE_ALLOW_MULTIPLE,
			  authorization_data, sizeof(authorization_data));
    if (len > 0) {
	if (parse_auth_data(authorization_data, 
			    &response->authorization_data)) {
	    verror_put_string("Error parsing authorization data from server response");
	    return -1;
	}
    }

    /* Success */
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

int
myproxy_recv_response(myproxy_socket_attrs_t *attrs, myproxy_response_t *response) {
    int responselen;
    char response_buffer[10240];

    /* Receive a response from the server */
    responselen = myproxy_recv(attrs, response_buffer, sizeof(response_buffer));
    if (responselen < 0) {
        return(-1);
    }

    if (responselen == 0) {
	verror_put_string("Server closed connection.\n");
	return(-1);
    }

    /* Make a response object from the response buffer */
    if (myproxy_deserialize_response(response, response_buffer, responselen) < 0) {
      return(-1);
    }

    /* Check version */
    if (strcmp(response->version, MYPROXY_VERSION) != 0) {
      verror_put_string("Error: Received invalid version number from server");
      return(-1);
    } 

    /* Check response */
    switch(response->response_type) {
        case MYPROXY_ERROR_RESPONSE:
            verror_put_string("ERROR from server: %s", response->error_str);
	    return(-1);
            break;
        case MYPROXY_OK_RESPONSE:
	case MYPROXY_AUTHORIZATION_RESPONSE:
            break;
        default:
            verror_put_string("Received unknown response type");
	    return(-1);
            break;
    }
    return 0;
}

void
myproxy_free(myproxy_socket_attrs_t *attrs, 
	     myproxy_request_t *request, 
	     myproxy_response_t *response)
{ 
    if (attrs != NULL) {
       if (attrs->pshost != NULL) 
	  free(attrs->pshost);
       GSI_SOCKET_destroy(attrs->gsi_socket);
       close(attrs->socket_fd);
       free(attrs);
    }

    if (request != NULL) {
       if (request->version != NULL)     
	  free(request->version);
       if (request->username != NULL) 
    	  free(request->username);
       if (request->retrievers != NULL)
	  free(request->retrievers);
       if (request->renewers != NULL)
	  free(request->renewers);
       free(request);
    }
    
    if (response != NULL) {
       if (response->version != NULL) 
    	  free(response->version);
       if (response->authorization_data != NULL)
    	  authorization_data_free(response->authorization_data);
       free(response);
    }
}

/*--------- Helper functions ------------*/
/*
 * convert_message()
 *
 * Searches a buffer and locates varname. Stores contents of varname into line
 * e.g. convert_message(buf, "VERSION=", version, sizeof(version));
 *
 * flags is a bitwise or of the following values:
 *     CONVERT_MESSAGE_ALLOW_MULTIPLE      Allow a multiple instances of
 *                                         varname, in which case the rvalues
 *                                         are concatenated.
 *
 * Returns the number of characters copied into the line (not including the
 * terminating '\0'). On error returns -1, setting verror. Returns -2 if string  * not found
 */
static int
convert_message(const char			*buffer,
		const int			buffer_len,
		const char			*varname, 
		const int			flags,
		char				*line,
		const int			line_len)
{
    int				foundone = 0;
    char			*varname_start;
    int				return_value = -1;
    int				line_index = 0;
    char			*buffer_copy = NULL;
    const char			*buffer_p;

    assert(buffer != NULL);
    assert(buffer_len > 0);
    
    assert(varname != NULL);
    assert(line != NULL);

    if ((flags & ~CONVERT_MESSAGE_KNOWN_FLAGS) != 0)
    {
	verror_put_string("Illegal flags value (%d)", flags);
	goto error;
    }

    /*
     * XXX
     *
     * Be very paranoid parsing this. buffer should be a NUL-terminated,
     * but since we don't know that for sure, we're going to make sure it
     * is by making a copy (since the copy we have is a const) and NUL-
     * terminating it.
     *
     * Yes, this needs complete revamping.
     */
    buffer_copy = malloc(buffer_len+1);
    
    if (buffer_copy == NULL)
    {
	verror_put_errno(errno);
	goto error;
    }

    memcpy(buffer_copy, buffer, buffer_len);
    buffer_copy[buffer_len] = '\0';
    
    /*
     * Our current position in buffer is in buffer_p. Since we're
     * done modifying buffer buffer_p can be a const.
     */
    buffer_p = buffer_copy;
    
    while ((varname_start = strstr(buffer_p, varname)) != NULL)
    {
	char			*value_start;
	int			value_length;
	
	/* Have is this the first varname we've found? */
	if (foundone == 1)
	{
	    /* No. Is that OK? */
	    if (flags * CONVERT_MESSAGE_ALLOW_MULTIPLE)
	    {
		/* Yes. Add carriage return to existing line and concatenate */

		if (line_index + 2 > line_len)
		{
		    verror_put_string("Internal buffer (line) too small");
		    goto error;
		}

		line[line_index] = '\n';
		line_index++;
		line[line_index] = '\0';
	    }
	    else
	    {
		/* No. That's an error */
		verror_put_string("Multiple values found in convert_message()");
		goto error;
	    }
	}
	
	/* Find start of value */
	value_start = &varname_start[strlen(varname)];

	/* Find length of value (might be zero) */
	value_length = strcspn(value_start, "\n");

	/* Is there room in line for this value */
	if ((line_index + value_length + 1 /* for NUL */) > line_len)
	{
	    verror_put_string("Internal buffer (line) too small");
	    goto error;
	}
	
	/* Copy it over */
	strncpy(&line[line_index], value_start, value_length);
	line_index += value_length;
	
	/* Make sure line stays NULL-terminated */
	line[line_index] = '\0';

	/* Indicate we've found a match */
        foundone = 1;

	/* Advance our buffer position pointer */
	buffer_p = &value_start[value_length];
    }
	
    /* Did we find anything */
    if (foundone == 0)
    {
	/* verror_put_string("No value found"); */
        return_value = -2; /*string not found*/
	goto error;
    }

    /* Success */
    return_value = strlen(line);
    
  error:
    if (buffer_copy)
       free(buffer_copy);

    if (return_value == -1 || return_value == -2)
    {
	/* Don't return anything in line on error */
	line[0] = '\0';
    }

    return return_value;
}

/*
 * parse_command()
 *
 * Parse command_str return the respresentation of the command in
 * command_value.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
static int
parse_command(const char			*command_str,
	      myproxy_proto_request_type_t	*command_value)
{
    int				value;
    int				return_value = -1;
    
    assert(command_str != NULL);
    assert(command_value != NULL);
    
    /* XXX Should also handle string commands */

    switch (string_to_int(command_str, &value))
    {
      case STRING_TO_INT_SUCCESS:
	return_value = 0;
	*command_value = (myproxy_proto_request_type_t) value;
	break;
	
      case STRING_TO_INT_NONNUMERIC:
	verror_put_string("Non-numeric characters in command string \"%s\"",
			  command_str);
	break;
	
      case STRING_TO_INT_ERROR:
	break;
    }
    
    return return_value;
}


/*
 * encode_command()
 *
 * Return a string encoding of the command in command_value.
 * Returns NULL on error, setting verror.
 */
static const char *
encode_command(const myproxy_proto_request_type_t	command_value)
{
    const char *string;
    
    /*
     * XXX Should return actual string description.
     */
    switch(command_value)
    {
      case MYPROXY_GET_PROXY:
	string = "0";
	break;
	
      case MYPROXY_PUT_PROXY:
	string = "1";
	break;
	
      case MYPROXY_INFO_PROXY:
	string = "2";
	break;
	
      case MYPROXY_DESTROY_PROXY:
	string = "3";
	break;
	
      default:
	/* Should never get here */
	string = NULL;
	verror_put_string("Internal error: Bad command type(%d)",
			  command_value);
	break;
    }

    return string;
}


/*
 * parse_string
 *
 * Given a string representation of an integer value, fill in the given
 * integer with its integral value.
 *
 * Currently the string is just an ascii representation of the integer.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
static int
parse_string(const char			*str,
	       int			*value)
{
    int				val;
    int				return_value = -1;
    
    assert(str != NULL);
    assert(value != NULL);
    
    /* XXX Should also handle string commands */

    switch (string_to_int(str, &val))
    {
      case STRING_TO_INT_SUCCESS:
	return_value = 0;
	*value = val;
	break;
	
      case STRING_TO_INT_NONNUMERIC:
	verror_put_string("Non-numeric characters in string \"%s\"",
			  str);
	break;
	
      case STRING_TO_INT_ERROR:
	break;
    }
    
    return return_value;
}


/*
 * encode_integer()
 *
 * Encode the given integer as a string into the given buffer with
 * length of buffer_len.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
static int
encode_integer(int				value,
		char				*string,
		int				string_len)
{
    /* Buffer large enough to hold string representation of lifetime */
    char buffer[20];
    
    assert(string != NULL);

    sprintf(buffer, "%d", value);
    
    if (my_strncpy(string, buffer, string_len) == -1)
    {
	return -1;
    }
    
    return 0;
}


/*
 * parse_response_type()
 *
 * Given a string representation of a response_type, fill in type_value
 * with the value.
 *
 * Currently the string is just an ascii representation of the value.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
static int
parse_response_type(const char				*type_str,
		    myproxy_proto_response_type_t	*type_value)
{
    int				value;
    int				return_value = -1;
    
    assert(type_str != NULL);
    assert(type_value != NULL);
    
    /* XXX Should also handle string representations */

    switch (string_to_int(type_str, &value))
    {
      case STRING_TO_INT_SUCCESS:
	return_value = 0;
	*type_value = (myproxy_proto_response_type_t) value;
	break;
	
      case STRING_TO_INT_NONNUMERIC:
	verror_put_string("Non-numeric characters in string \"%s\"",
			  type_str);
	break;
	
      case STRING_TO_INT_ERROR:
	break;
    }
    
    return return_value;
}

/*
 * encode_response()
 *
 * Return a string encoding of the response_type in response_value.
 * Returns NULL on error.
 */
static const char *
encode_response(const myproxy_proto_response_type_t	response_value)
{
    const char *string;
    
    /*
     * XXX Should return actual string description.
     */
    switch(response_value)
    {
      case MYPROXY_OK_RESPONSE:
	string = "0";
	break;
	
      case MYPROXY_ERROR_RESPONSE:
	string = "1";
	break;

      case MYPROXY_AUTHORIZATION_RESPONSE:
	string = "2";
	break;
	
      default:
	/* Should never get here */
	string = NULL;
	verror_put_string("Internal error: Bad reponse type (%d)",
			  response_value);
	break;
    }

    return string;
}

/*
 * string_to_int()
 *
 * Convert a string representation of an integer into an integer.
 *
 * Returns 1 on success, 0 if string contains non-numeric characters,
 * -1 on error setting verror.
 */
static int
string_to_int(const char			*string,
	      int				*integer)
{
    char			*parse_end = NULL;
    int				base = 0 /* Any */;
    long int			value;
    int				return_value = -1;
    
    assert(string != NULL);
    assert(integer != NULL);
    
    /* Check for empty string */
    if (strlen(string) == 0)
    {
	verror_put_string("Zero-length string");
	goto error;
    }
    
    value = strtol(string, &parse_end, base);
    
    if (value == LONG_MIN)
    {
	verror_put_string("Underflow error");
	goto error;
    }
    
    if (value == LONG_MAX)
    {
	verror_put_string("Overflow error");
	goto error;
    }
    
    /* Make sure we parsed all the characters in string */
    if (*parse_end != '\0')
    {
	return_value = 0;
	goto error;
    }
    
    /* Success */
    *integer = (int) value;
    return_value = 1;
    
  error:
    return return_value;
}

/* Returns pointer to last processed char in the buffer or NULL on error */
/* The entries are separated either by '\n' or by '\0' */
static char *
parse_entry(char *buffer, authorization_data_t *data)
{
   char *str;
   char *str_method;
   char *p = buffer;
   author_method_t method;

   assert (data != NULL);

   while (*p == '\0') 
      p++;
   str_method = p;

   if ((p = strchr(str_method, ':')) == NULL) {
      verror_put_string("Parse error");
      return NULL;
   }
   *p = '\0';
   method = authorization_get_method(str_method);
   
   str = p + 1;

   if ((p = strchr(str, '\n'))) 
      *p = '\0';

   data->server_data = malloc(strlen(str) + 1);
   if (data->server_data == NULL) {
      verror_put_errno(errno);
      return NULL;
   }
   strcpy(data->server_data, str);
   data->client_data = NULL;
   data->client_data_len = 0;
   data->method = method;

   return str + strlen(str);
}

/* 
  Parse buffer into author_data. The buffer is supposed to be '0'-terminated
*/
static int
parse_auth_data(char *buffer, authorization_data_t ***auth_data)
{
   char *p = buffer;
   char *buffer_end;
   void *tmp;
   authorization_data_t **data = NULL;
   int num_data = 0;
   authorization_data_t entry;
   int return_status = -1;

   data = malloc(sizeof(*data));
   if (data == NULL) {
      verror_put_errno(errno);
      return -1;
   }
   data[0] = NULL;
   
   buffer_end = buffer + strlen(buffer);
   do {
      p = parse_entry(p, &entry);
      if (p == NULL)
	 goto end;

      if (entry.method == AUTHORIZETYPE_NULL)
	 continue;

      tmp = realloc(data, (num_data + 1 + 1) * sizeof(*data));
      if (tmp == NULL) {
	 verror_put_errno(errno);
	 goto end;
      }
      data = tmp;

      data[num_data] = malloc(sizeof(entry));
      if (data[num_data] == NULL) {
	 verror_put_errno(errno);
	 goto end;
      }

      data[num_data]->server_data = entry.server_data;
      data[num_data]->client_data = entry.client_data;
      data[num_data]->client_data_len = entry.client_data_len;
      data[num_data]->method = entry.method;
      data[num_data + 1] = NULL;
      num_data++;
   } while (p < buffer_end);

   return_status = 0;
   *auth_data = data;

end:
   if (return_status == -1)
      authorization_data_free(data);
   return return_status;
}
