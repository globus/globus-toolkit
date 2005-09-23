/*
 * myproxy.c
 *
 * See myproxy.h for documentation
 *
 */

#include "myproxy_common.h"	/* all needed headers included here */

/**********************************************************************
 *
 * Internal functions
 *
 */
static int convert_message(const char		*buffer,
			   const char		*varname, 
			   int			flags,
			   char			**line);

/* Values for convert_message() flags */
#define CONVERT_MESSAGE_NO_FLAGS		0x0000
#define CONVERT_MESSAGE_ALLOW_MULTIPLE		0x0001

#define CONVERT_MESSAGE_DEFAULT_FLAGS		CONVERT_MESSAGE_NO_FLAGS
#define CONVERT_MESSAGE_KNOWN_FLAGS		CONVERT_MESSAGE_ALLOW_MULTIPLE

#define MYPROXY_DEFAULT_PROXY                   "/tmp/myproxy-proxy"
#define SECONDS_PER_HOUR                        (60 * 60)


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

int grid_proxy_init(int hours, const char *proxyfile, int read_passwd_from_stdin);

int grid_proxy_destroy(const char *proxyfile);

int
is_a_retry_command( int command );

int
parse_secondary( char *tmp, char *server, char *port );


/* Values for string_to_int() */
#define STRING_TO_INT_SUCCESS		1
#define STRING_TO_INT_ERROR		-1
#define STRING_TO_INT_NONNUMERIC	0

/**********************************************************************
 *
 * Exported functions
 *
 */

char *
myproxy_version(int *major, int *minor, int *micro) {
    if (major) *major = MYPROXY_VERSION_MAJOR;
    if (minor) *minor = MYPROXY_VERSION_MINOR;
    if (micro) *micro = MYPROXY_VERSION_MICRO;
    return MYPROXY_VERSION_DATE;
}

int
myproxy_check_version_ex(int major, int minor, int micro) {
    if (major != MYPROXY_VERSION_MAJOR) return 1;
    if (minor != MYPROXY_VERSION_MINOR) return 2;
    if (micro != MYPROXY_VERSION_MICRO) return 3;
    return 0;
}

int 
myproxy_init_client(myproxy_socket_attrs_t *attrs) {
    struct sockaddr_in sin;
    struct hostent *host_info;
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
	    myproxy_debug("Socket bound to port %hu.\n", port);
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
        verror_put_string("Unable to connect to %s:%d\n", attrs->pshost,
			  attrs->psport);
        return -1;
    }

    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    
    if (attrs->gsi_socket == NULL) {
        verror_put_string("GSI_SOCKET_new()\n");
        return -1;
    }

   return attrs->socket_fd;
}
    
/* The Globus standard is to resolve the hostname we're given on the
   command-line with gethostbyname(), ignoring concerns about DNS
   spoofing.
*/
void
myproxy_resolve_hostname(char **host)
{
    struct hostent *hostinfo;

    hostinfo = gethostbyname(*host);
    if (hostinfo == NULL || hostinfo->h_name == NULL) {
	myproxy_debug("gethostbyname(%s) failed", *host);
	return;
    }
    if (hostinfo->h_addrtype == AF_INET) { /* check for localhost */
	struct in_addr addr;
	addr = *(struct in_addr *)(hostinfo->h_addr);
	if (ntohl(addr.s_addr) == INADDR_LOOPBACK) {
	    char buf[MAXHOSTNAMELEN];
	    if (gethostname(buf, sizeof(buf)) < 0) {
		myproxy_debug("gethostname() failed");
		return;
	    }
	    hostinfo = gethostbyname(buf);
	    if (hostinfo == NULL || hostinfo->h_name == NULL) {
		free(*host);
		*host = strdup(buf);
		return;
	    }
	}
    }
    free(*host);
    *host = strdup(hostinfo->h_name);
}

int 
myproxy_authenticate_init(myproxy_socket_attrs_t *attrs,
			  const char *proxyfile) 
{
   char error_string[1024];
   char peer_name[1024] = "";
   char *accepted_peer_names[3] = { 0 };
   char *server_dn;
   int  rval, return_value = -1;

   if (GSI_SOCKET_use_creds(attrs->gsi_socket,
			    proxyfile) == GSI_SOCKET_ERROR) {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       verror_put_string("Error setting credentials to use: %s\n",
			 error_string);
       goto error;
   }

   /*
    * What identity to we expect the server to have?
    */
   server_dn = getenv("MYPROXY_SERVER_DN");
   if (server_dn) {
       myproxy_debug("Expecting non-standard server DN \"%s\"\n", server_dn);
       accepted_peer_names[0] = strdup(server_dn);
   } else {
       char *fqhn, *buf;
       fqhn = GSI_SOCKET_get_peer_hostname(attrs->gsi_socket);
       buf = malloc(strlen(fqhn)+strlen("myproxy@")+1);
       sprintf(buf, "myproxy@%s", fqhn);
       accepted_peer_names[0] = buf;
       buf = malloc(strlen(fqhn)+strlen("host@")+1);
       sprintf(buf, "host@%s", fqhn);
       accepted_peer_names[1] = buf;
       free(fqhn);
   }
   
   rval = GSI_SOCKET_authentication_init(attrs->gsi_socket,
					 accepted_peer_names);
   if (rval == GSI_SOCKET_UNAUTHORIZED) {
       /* This is a common error.  Send the GSI errors to debug and
	  return a more friendly error message in verror(). */
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       myproxy_debug("Error authenticating: %s\n", error_string);
       GSI_SOCKET_get_peer_name(attrs->gsi_socket, peer_name,
				sizeof(peer_name));
       if (server_dn) {
	   verror_put_string("Server authorization failed.  Server identity\n"
			     "(%s)\ndoes not match $MYPROXY_SERVER_DN\n"
			     "(%s).\nIf the server identity is acceptable, "
			     "set\nMYPROXY_SERVER_DN=\"%s\"\n"
			     "and try again.\n",
			     peer_name, server_dn, peer_name);
       } else {
	   verror_put_string("Server authorization failed.  Server identity\n"
			     "(%s)\ndoes not match expected identities\n"
			     "%s or %s.\n"
			     "If the server identity is acceptable, "
			     "set\nMYPROXY_SERVER_DN=\"%s\"\n"
			     "and try again.\n",
			     peer_name, accepted_peer_names[0],
			     accepted_peer_names[1], peer_name);
       }
       goto error;
   } else if (rval == GSI_SOCKET_ERROR) {
       GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
       verror_put_string("Error authenticating: %s\n", error_string);
       goto error;
   }

   return_value = 0;

 error:
   if (accepted_peer_names[0]) free(accepted_peer_names[0]);
   if (accepted_peer_names[1]) free(accepted_peer_names[1]);
   if (accepted_peer_names[2]) free(accepted_peer_names[2]);
   
   return return_value;
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

    if (GSI_SOCKET_get_peer_name(attrs->gsi_socket,
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
myproxy_serialize_request(const myproxy_request_t *request, char *data,
			  const int datalen) 
{
    int len;
    char *buf = NULL;

    assert(data != NULL);
    assert(datalen > 0);

    len = myproxy_serialize_request_ex(request, &buf);
    if (len <= 0) {
	if (buf) free(buf);
	return len;
    }
    if (len >= datalen) {
	verror_put_string("Buffer size exceeded in myproxy_serialize_request().");
	if (buf) free(buf);
	return -1;
    }
    memcpy(data, buf, len);
    free(buf);
    return len;
}

int
myproxy_serialize_request_ex(const myproxy_request_t *request, char **data) 
{
    int len;
    char lifetime_string[64];
    const char *command_string;

    assert(data != NULL);
    if (*data) (*data)[0] = '\0';

    /* version */
    len = my_append(data, MYPROXY_VERSION_STRING,
		    request->version, "\n", NULL);
    if (len < 0) 
      return -1;

    /* command type */
    command_string = encode_command((myproxy_proto_request_type_t)request->command_type);
    if (command_string == NULL) {
	return -1;
    }
    len = my_append(data, MYPROXY_COMMAND_STRING, 
		    command_string, "\n", NULL);
    if (len < 0)
      return -1;

    /* username */
    len = my_append(data, MYPROXY_USERNAME_STRING,
		    request->username, "\n", NULL); 
    if (len < 0)
      return -1;

    /* passphrase */
    len = my_append(data, MYPROXY_PASSPHRASE_STRING,
		    request->passphrase, "\n", NULL);
    if (len < 0)
      return -1;

    /* new passphrase */
    if (request->new_passphrase[0]!= '\0')
    {
	len = my_append(data, MYPROXY_NEW_PASSPHRASE_STRING,
			request->new_passphrase, "\n", NULL);
	if (len < 0)  return -1;
    }

    /* lifetime */
    if (encode_integer(request->proxy_lifetime,
			lifetime_string,
			sizeof(lifetime_string)) == -1)
    {
	return -1;
    }
			
    len = my_append(data, MYPROXY_LIFETIME_STRING,
		    lifetime_string, "\n", NULL);
    if (len < 0)
      return -1;

    /* retrievers */
    if (request->retrievers != NULL)
    { 
      len = my_append(data, MYPROXY_RETRIEVER_STRING,
		      request->retrievers, "\n", NULL); 
      if (len < 0)
        return -1;
    }

    /* renewers */
    if (request->renewers != NULL)
    { 
      len = my_append(data, MYPROXY_RENEWER_STRING,
		      request->renewers, "\n", NULL); 
      if (len < 0)
        return -1;
    }

    /* credential name */
    if (request->credname!= NULL)
    {
	char *buf = strdup (request->credname);
	strip_char ( buf, '\n');
				
	len = my_append(data, MYPROXY_CRED_PREFIX, "_",
			MYPROXY_CRED_NAME_STRING,
			buf, "\n", NULL); 
	free(buf);
	if (len < 0)
	    return -1;
    }

    /* credential description */
    if (request->creddesc != NULL)
    { 
	char *buf = strdup (request->creddesc);
	strip_char ( buf, '\n');
	len = my_append(data, MYPROXY_CRED_PREFIX, "_",
			MYPROXY_CRED_DESC_STRING,
			buf, "\n", NULL); 
	free(buf);
	if (len < 0)
	    return -1;
    }
   
    /* key retrievers */
    if (request->keyretrieve != NULL)
    { 
      len = my_append(data, MYPROXY_KEY_RETRIEVER_STRING,
		      request->keyretrieve, "\n", NULL); 
      if (len < 0)
        return -1;
    }

    /* owner */
    if (request->owner != NULL)
    {
        char *buf = strdup (request->owner);
        strip_char ( buf, '\n');
        len = my_append(data, MYPROXY_CRED_PREFIX, "_",
                        MYPROXY_CRED_OWNER_STRING,
                        buf, "\n", NULL);
        free(buf);
        if (len < 0)
            return -1;
    }

    /* server info */
    if (request->replicate_info != NULL)
    { 
/*
      len = concatenate_strings(data, datalen, MYPROXY_SERVER_INFO_STRING,
			        request->replicate_info, "\n", NULL); 
*/

      len =  my_append(data, MYPROXY_REPLICA_INFO_STRING,
                       request->replicate_info, "\n", NULL);

      if (len < 0)
        return -1;
    }

    /* trusted root certificates */
    myproxy_debug("want_trusted_certs = %d\n", request->want_trusted_certs);
    if (request->want_trusted_certs) {
      len = my_append(data, MYPROXY_TRUSTED_CERTS_STRING,
				"1", "\n", NULL);
      if (len < 0)
        return -1;
    }

    return len+1;
}

int 
myproxy_deserialize_request(const char *data, const int datalen,
                            myproxy_request_t *request)
{
    int len, return_code = -1;
    char *tmp=NULL, *buf=NULL, *new_data=NULL;

    assert(request != NULL);
    assert(data != NULL);

    /* if the input data isn't null terminated, fix it now. */
    if (data[datalen-1] != '\0') {
	new_data = malloc(datalen+1);
	memcpy(new_data, data, datalen);
	new_data[datalen] = '\0';
	data = new_data;
    }

    /* version */
    len = convert_message(data,
			  MYPROXY_VERSION_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len <= -1)
    {
	verror_prepend_string("Error parsing version from client request");
	goto error;
    }

    request->version = strdup(buf);
    
    if (request->version == NULL)
    {
	verror_put_errno(errno);
	goto error;
    }

    /* command */
    len = convert_message(data,
			  MYPROXY_COMMAND_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len <= -1)
    {
	verror_prepend_string("Error parsing command from client request");
	goto error;
    }
    
    if (parse_command(buf, &request->command_type) == -1)
    {
	goto error;
    }

    /* username */
    len = convert_message(data,
			  MYPROXY_USERNAME_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);
    if (len <= -1)
    {
	verror_prepend_string("Error parsing usename from client request");
	goto error;
    }
    
    request->username = strdup(buf);

    if (request->username == NULL)
    {
	verror_put_errno(errno);
	goto error;
    }

    /* passphrase */
    len = convert_message(data,
			  MYPROXY_PASSPHRASE_STRING, 
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
                          &buf);

    if (len <= -1) 
    {
	verror_prepend_string("Error parsing passphrase from client request");
	goto error;
    }
    
    /* XXX request_passphrase is a static buffer. Why? */
    strncpy(request->passphrase, buf, sizeof(request->passphrase));

    /* new passphrase (for change passphrase only) */
    len = convert_message(data,
			  MYPROXY_NEW_PASSPHRASE_STRING, 
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -1) 
    {
	verror_prepend_string("Error parsing passphrase from client request");
	goto error;
    }
    else
    	if (len == -2)
		request->new_passphrase[0] = '\0';
	else
		strncpy (request->new_passphrase, buf, sizeof(request->new_passphrase));
    
    /* lifetime */
    len = convert_message(data,
			  MYPROXY_LIFETIME_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
                          &buf);
    if (len <= -1)
    {
	verror_prepend_string("Error parsing lifetime from client request");
	goto error;
    }
    
    if (parse_string(buf, &request->proxy_lifetime) == -1)
    {
	goto error;
    }

    /* retriever */
    len = convert_message(data,
			  MYPROXY_RETRIEVER_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
       request->retrievers = NULL;
    else
    if (len <= -1)
    {
	verror_prepend_string("Error parsing retriever from client request");
	goto error;
    }
    else
    {
      request->retrievers = strdup(buf);

      if (request->retrievers == NULL)
      {
	verror_put_errno(errno);
	goto error;
      }
    }


    /* renewer */
    len = convert_message(data,
			  MYPROXY_RENEWER_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
       request->renewers = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing renewer from client request");
	goto error;
       }
       else
       {
         request->renewers = strdup(buf);
    
         if (request->renewers == NULL)
         {
	  verror_put_errno(errno);
	  goto error;
         }
       }

    /* credential name */
    if (tmp) tmp[0] = '\0';
    len = my_append(&tmp, MYPROXY_CRED_PREFIX, "_", 
		    MYPROXY_CRED_NAME_STRING, NULL);

    if (len == -1) {
	goto error;
    }
				
    len = convert_message(data,
			  tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found - assign default*/
	request->credname = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing credential name from client request");
	goto error;
       }
       else
       {
         request->credname = strdup(buf);
    
         if (request->credname == NULL)
         {
	  verror_put_errno(errno);
	  goto error;
         }
       }

    /* credential description */
    if (tmp) tmp[0] = '\0';
    len = my_append(&tmp, MYPROXY_CRED_PREFIX, "_",
		    MYPROXY_CRED_DESC_STRING, NULL);

    len = convert_message(data,
			  tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
	request->creddesc = NULL;
    else
       if (len <= -1)
       {
 	verror_prepend_string("Error parsing credential description from client request");
	goto error;
       }
       else
       {
         request->creddesc = strdup(buf);
    
         if (request->creddesc == NULL)
         {
	  verror_put_errno(errno);
	  goto error;
         }
       }

    /* key retriever */
    len = convert_message(data,
			  MYPROXY_KEY_RETRIEVER_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
       request->keyretrieve = NULL;
    else
    if (len <= -1)
    {
	verror_prepend_string("Error parsing key retriever from client request");
	goto error;
    }
    else
    {
      request->keyretrieve = strdup(buf);

      if (request->keyretrieve == NULL)
      {
	verror_put_errno(errno);
	goto error;
      }
    }

    /* Server info request */
/*
    len = convert_message(data, datalen,
			  MYPROXY_SERVER_INFO_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  buf, sizeof(buf));
*/
    len = convert_message(data,
			  MYPROXY_REPLICA_INFO_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
       request->replicate_info = NULL;
    else
    if (len <= -1)
    {
	verror_prepend_string("Error parsing server info from client request");
	return -1;
    }
    else
    {
      request->replicate_info = strdup(buf);

      if (request->replicate_info == NULL)
      {
	verror_put_errno(errno);
	return -1;
      }
    }

    /* credential owner */
    if (tmp) tmp[0] = '\0';
    len = my_append(&tmp, MYPROXY_CRED_PREFIX, "_",
                    MYPROXY_CRED_OWNER_STRING, NULL);

    len = convert_message(data,
                          tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
                          &buf);

    if (len == -2)  /*-2 indicates string not found*/
        request->owner = NULL;
    else
       if (len <= -1)
       {
        verror_prepend_string("Error parsing credential owner from client request");
        goto error;
       }
       else
       {
         request->owner = strdup(buf);

         if (request->owner == NULL)
         {
          verror_put_errno(errno);
          goto error;
         }
       }


    /* trusted root certificates */
    len = convert_message(data,
			  MYPROXY_TRUSTED_CERTS_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);

    if (len == -2)  /*-2 indicates string not found*/
       request->want_trusted_certs = 0;
    else
    if (len <= -1)
    {
	verror_prepend_string("Error parsing TRUSTED_CERTS in client request");
	goto error;
    }
    else
    {
	if (string_to_int(buf, &request->want_trusted_certs) !=
	    STRING_TO_INT_SUCCESS) {
	    verror_prepend_string("Error parsing TRUSTED_CERTS in client request");
	    goto error;
	}
    }

    /* Success */
    return_code = 0;

 error:
    if (tmp) free(tmp);
    if (buf) free(buf);
    if (new_data) free(new_data);

    return return_code;
} 

int
myproxy_serialize_response(const myproxy_response_t *response, 
                           char *data, const int datalen) 
{
    int len;
    char *buf = NULL;

    assert(data != NULL);
    assert(datalen > 0);

    len = myproxy_serialize_response_ex(response, &buf);
    if (len <= 0) {
	if (buf) free(buf);
	return len;
    }
    if (len >= datalen) {
	verror_put_string("Buffer size exceeded in myproxy_serialize_response().");
	if (buf) free(buf);
	return -1;
    }
    memcpy(data, buf, len);

    free(buf);
    return len;
}

int
myproxy_serialize_response_ex(const myproxy_response_t *response, 
			      char **data) 
{
    int len;
    authorization_data_t **p;
    const char *response_string;
    
    assert(data != NULL);
    assert(response != NULL);

    if (*data) (*data)[0] = '\0';

    /*Version*/    
    len = my_append(data, MYPROXY_VERSION_STRING,
		    response->version, "\n", NULL);
    if (len < 0)
        return -1;
    
    response_string = encode_response((myproxy_proto_response_type_t) response->response_type);

    /*Response string*/
    if (response_string == NULL) {
	return -1;
    }
    
    len = my_append(data, MYPROXY_RESPONSE_TYPE_STRING, 
		    response_string, "\n", NULL);
    if (len < 0)
        return -1;
    
    /*Authorization data*/
    if ((p = response->authorization_data)) {
       while (*p) {
	  len = my_append(data, MYPROXY_AUTHORIZATION_STRING,
			  authorization_get_name((*p)->method), ":", 
			  (*p)->server_data, "\n", NULL);
	  if (len < 0)
	     return -1;
	  p++;
       }
    }

    if( response->replicate_info != NULL )
    {
      if( response->replicate_info->secondary_servers != NULL )
      { 
/*
	len = concatenate_strings(data, datalen, MYPROXY_SLAVE_INFO_STRING,
		     response->replicate_info->secondary_servers, "\n", NULL);
*/
	len = my_append(data, MYPROXY_SECONDARY_INFO_STRING,
		     response->replicate_info->secondary_servers, "\n", NULL);
	if (len < 0)
	     return -1;
      }

      if( response->replicate_info->primary_server != NULL )
      { 
/*
	len = concatenate_strings(data, datalen, MYPROXY_MASTER_INFO_STRING,
		     response->replicate_info->primary_server, "\n", NULL);
*/
	len = my_append(data, MYPROXY_PRIMARY_INFO_STRING,
		     response->replicate_info->primary_server, "\n", NULL);
	if (len < 0)
	     return -1;
      }
/*
      if( response->replicate_info->primary_server != NULL )
      { 
	len = concatenate_strings(data, datalen, MYPROXY_MASTER_INFO_STRING,
		     response->replicate_info->primary_server, "\n", NULL);
	if (len < 0)
	     return -1;
	totlen += len;
      }
*/
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
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", MYPROXY_CRED_NAME_STRING,
				cred->credname, "\n", NULL);
		if (len == -1)
		    goto error;
	    }
	    assert(cred->credname || first_cred);
	    if (cred->creddesc) {
		if (first_cred) {
		    len = my_append(data, 
				    MYPROXY_CRED_PREFIX,
				    "_", MYPROXY_CRED_DESC_STRING,
				    cred->creddesc, "\n", NULL);
		} else {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", cred->credname,
				    "_", MYPROXY_CRED_DESC_STRING,
				    cred->creddesc, "\n", NULL);
		}
		if (len == -1)
		    goto error;
	    }
	    sprintf(date, "%lu",  cred->start_time);
	    if (first_cred) {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", MYPROXY_START_TIME_STRING, 
				date, "\n", NULL);
	    } else {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", cred->credname,
				"_", MYPROXY_START_TIME_STRING, 
				date, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    sprintf(date, "%lu", cred->end_time);
	    if (first_cred) {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", MYPROXY_END_TIME_STRING, 
				date, "\n", NULL);
	    } else {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", cred->credname,
				"_", MYPROXY_END_TIME_STRING, 
				date, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    if (first_cred) {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", MYPROXY_CRED_OWNER_STRING,
				cred->owner_name, "\n", NULL);
	    } else {
		len = my_append(data, MYPROXY_CRED_PREFIX,
				"_", cred->credname,
				"_", MYPROXY_CRED_OWNER_STRING,
				cred->owner_name, "\n", NULL);
	    }
	    if (len == -1)
		goto error;
	    if (cred->retrievers) {
		if (first_cred) {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", MYPROXY_RETRIEVER_STRING,
				    cred->retrievers, "\n", NULL);
		} else {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", cred->credname,
				    "_", MYPROXY_RETRIEVER_STRING,
				    cred->retrievers, "\n", NULL);
		}
		if (len == -1)
		    goto error;
	    }	
	    if (cred->keyretrieve) {
		if (first_cred) {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", MYPROXY_KEY_RETRIEVER_STRING,
				    cred->keyretrieve, "\n", NULL);
		} else {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", cred->credname,
				    "_", MYPROXY_KEY_RETRIEVER_STRING,
				    cred->keyretrieve, "\n", NULL);
		}
		if (len == -1)
		    goto error;
	    }	
	    if (cred->renewers) {
		if (first_cred) {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", MYPROXY_RENEWER_STRING,
				    cred->renewers, "\n", NULL);
		} else {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", cred->credname,
				    "_", MYPROXY_RENEWER_STRING,
				    cred->renewers, "\n", NULL);
		}
		if (len == -1)
		    goto error;
	    }
	    if (cred->lockmsg) {
		char *newline;
		newline = strchr(cred->lockmsg, '\n');
		if (newline) {
		    *newline = '\0'; /* only send first line */
		}
		if (first_cred) {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", MYPROXY_LOCKMSG_STRING,
				    cred->lockmsg, "\n", NULL);
		} else {
		    len = my_append(data,
				    MYPROXY_CRED_PREFIX,
				    "_", cred->credname,
				    "_", MYPROXY_LOCKMSG_STRING,
				    cred->lockmsg, "\n", NULL);
		}
		if (newline) {
		    *newline = '\n';
		}
		if (len == -1)
		    goto error;
	    }
	    first_cred = 0;
	}
	if (response->info_creds->next) {
	    len = my_append(data,
			    MYPROXY_ADDITIONAL_CREDS_STRING, NULL);
	    if (len < 0)
		return -1;
	    for (cred = response->info_creds->next;
		 cred != NULL;
		 cred = cred->next) {
		if (cred->next) {
		    len = my_append(data, cred->credname,
				    "," , NULL);
		} else {
		    len = my_append(data, cred->credname,
				    NULL);
		}
		if (len < 0)
		    return -1;
	    }
	    len = my_append(data, 
			    "\n", NULL);
	    if (len < 0)
		return -1;
	}
    }

    /* Only add error string(s) if necessary */
    if (response->response_type == MYPROXY_ERROR_RESPONSE) {
	char *start, *end;
	/* send each line individually */
	for (start=response->error_string;
	     (end = strchr(start, '\n')) != NULL;
	     start = end+1) {
	    *end = '\0';
	    len = my_append(data, MYPROXY_ERROR_STRING,
			    start, "\n", NULL);
	    if (len < 0) return -1;
	}
	/* send the last line */
	if (start[0] != '\0') {
	    len = my_append(data, MYPROXY_ERROR_STRING,
			    start, "\n", NULL);
	    if (len < 0) return -1;
	}
    }

    /* Include trusted certificates */
    if (response->trusted_certs) {
	myproxy_certs_t *cert;

	len = my_append(data, MYPROXY_TRUSTED_CERTS_STRING,
			NULL);
	if (len < 0)
	    return -1;

	for (cert = response->trusted_certs; cert; cert = cert->next) {
	    if (cert->next) {
		len = my_append(data, cert->filename,
				"," , NULL);
	    } else {
		len = my_append(data, cert->filename,
				NULL);
	    }	    
	    if (len < 0)
		return -1;
	}
	len = my_append(data, "\n", NULL);
	if (len < 0)
	    return -1;
	
	
	for (cert = response->trusted_certs; cert; cert = cert->next) {
	    char *b64data;
	    if (b64_encode(cert->contents, &b64data) < 0) {
		goto error;
	    }
	    /* myproxy_debug("got b64:\n%s\n", b64data); */
	    len = my_append(data, MYPROXY_FILEDATA_PREFIX,
			    "_", cert->filename, "=",
			    b64data,
			    "\n", NULL);
	    free(b64data);

	    if (len < 0)
		return -1;
	}
    }

    /* myproxy_debug("sending %s\n", data); */

    return len+1;

    error:
    	return -1;
}


int
myproxy_deserialize_response(myproxy_response_t *response,
                             const char *data, const int datalen) 
{
    int len, return_code = -1;
    int value, i, num_creds;
    char *tmp=NULL, *buf=NULL, *new_data=NULL;

    assert(response != NULL);
    assert(data != NULL);

    /* if the input data isn't null terminated, fix it now. */
    if (data[datalen-1] != '\0') {
	new_data = malloc(datalen+1);
	memcpy(new_data, data, datalen);
	new_data[datalen] = '\0';
	data = new_data;
    }

    if (response->authorization_data) {
	free(response->authorization_data);
	response->authorization_data = NULL;
    }

    /* myproxy_debug("received %s\n", data); */

    len = convert_message(data,
			  MYPROXY_VERSION_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);
    if (len < 0) {
	goto error;
    }
    if (response->version) {
	free(response->version);
    }
    response->version = strdup(buf);
    if (response->version == NULL) {
	verror_put_errno(errno);
	goto error;
    }

    len = convert_message(data,
			  MYPROXY_RESPONSE_TYPE_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);
    if (len < 0) {
	goto error;
    }

    if (parse_response_type(buf,
			    &response->response_type) == -1) {
	goto error;
    }

/* Get server information. */
/*
len = convert_message(data, datalen, MYPROXY_SLAVE_INFO_STRING,
		      CONVERT_MESSAGE_DEFAULT_FLAGS,
		      buffer, sizeof(buffer));
*/
len = convert_message(data, 
                      MYPROXY_SECONDARY_INFO_STRING,
		      CONVERT_MESSAGE_DEFAULT_FLAGS,
		      &buf);
if (len == -1) return -1;
if (len > 0)
{        
  if( response->replicate_info == NULL )
  {
    response->replicate_info = malloc(sizeof(struct myproxy_server));
    memset(response->replicate_info, 0, sizeof(struct myproxy_server));
  }

  response->replicate_info->secondary_servers = strdup(buf);
}

/*
len = convert_message(data, datalen, MYPROXY_MASTER_INFO_STRING,
		      CONVERT_MESSAGE_DEFAULT_FLAGS,
		      buffer, sizeof(buffer));
*/
len = convert_message(data, 
                      MYPROXY_PRIMARY_INFO_STRING,
		      CONVERT_MESSAGE_DEFAULT_FLAGS,
		      &buf);
if (len == -1) return -1;
if (len > 0)
{        
  if( response->replicate_info == NULL )
  {
    response->replicate_info = malloc(sizeof(struct myproxy_server));
    memset(response->replicate_info, 0, sizeof(struct myproxy_server));
  }

  response->replicate_info->primary_server = strdup(buf);
}


    if (response->response_type == MYPROXY_ERROR_RESPONSE) {
	/* It's ok if ERROR not present */
	response->error_string = 0;
	len = convert_message(data,
			      MYPROXY_ERROR_STRING, 
			      CONVERT_MESSAGE_ALLOW_MULTIPLE,
			      &response->error_string);
	return 0;
    }

    /* Parse any cred info in response */
    
    /* start time */
    if (tmp) tmp[0] = '\0';
    len = my_append(&tmp, MYPROXY_CRED_PREFIX, "_",
		    MYPROXY_START_TIME_STRING, NULL);
    if (len < 0) goto error;
    len = convert_message(data, tmp, CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &buf);
    if (len == -1) goto error;

    if (len > 0) {		/* credential info present */
	response->info_creds = malloc(sizeof(struct myproxy_creds));
	memset(response->info_creds, 0, sizeof(struct myproxy_creds));

	switch(string_to_int(buf, &value)) {
	case STRING_TO_INT_SUCCESS:
	    response->info_creds->start_time = value;
	    break;
	case STRING_TO_INT_NONNUMERIC:
	    verror_put_string("Non-numeric characters in CRED_START_TIME \"%s\"", buf);
	    goto error;
	case STRING_TO_INT_ERROR:
	    goto error;
	}

    	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_END_TIME_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);

	if (len > 0) {
	    switch(string_to_int(buf, &value)) {
	    case STRING_TO_INT_SUCCESS:
		response->info_creds->end_time = value;
		break;
	    case STRING_TO_INT_NONNUMERIC:
		verror_put_string("Non-numeric characters in CRED_END_TIME \"%s\"", buf);
		goto error;
	    case STRING_TO_INT_ERROR:
		goto error;
	    }
	}

	if (tmp) tmp[0] = '\0';
	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_CRED_NAME_STRING, NULL);
	if (len < 0) goto error;

	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
	if (len == -1) goto error;
	if (len > 0)
	    response->info_creds->credname = strdup(buf);
		
	if (tmp) tmp[0] = '\0';
	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_CRED_DESC_STRING, NULL);
	if (len < 0) goto error;

	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
	if (len == -1) goto error;
	if (len > 0)
	    response->info_creds->creddesc = strdup(buf);

	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_CRED_OWNER_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
    	if (len == -1) goto error;
	if (len >= 0)
	    response->info_creds->owner_name = strdup(buf); 

	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_RETRIEVER_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
    	if (len == -1) goto error;
	if (len >= 0)
	    response->info_creds->retrievers = strdup(buf); 

	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_KEY_RETRIEVER_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
    	if (len == -1) goto error;
	if (len >= 0)
	    response->info_creds->keyretrieve = strdup(buf); 

	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_RENEWER_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
    	if (len == -1) goto error;
	if (len >= 0)
	    response->info_creds->renewers = strdup(buf); 

	if (tmp) tmp[0] = '\0';
    	len = my_append(&tmp, MYPROXY_CRED_PREFIX,
			"_", MYPROXY_LOCKMSG_STRING, NULL);
    	if (len < 0) goto error;
		
	len = convert_message(data, tmp,
			      CONVERT_MESSAGE_DEFAULT_FLAGS,
			      &buf);
    	if (len == -1) goto error;
	if (len >= 0)
	    response->info_creds->lockmsg = strdup(buf); 

	len = convert_message(data, MYPROXY_ADDITIONAL_CREDS_STRING,
			      CONVERT_MESSAGE_DEFAULT_FLAGS, 
			      &buf);

    	if (len == -1) goto error;
	if (len >= 0) {		/* addl credentials */
	    char **strs;
	    struct myproxy_creds *cred = response->info_creds;

	    len = parse_add_creds(buf, &strs, &num_creds);
	    if (len == -1) {
		verror_put_string("Error parsing additional cred string");
		goto error;
	    }

	    for (i = 0; i < num_creds; i++) {
		cred->next = malloc(sizeof(struct myproxy_creds));
		cred = cred->next;
		memset(cred, 0, sizeof(struct myproxy_creds));

		cred->credname = strdup(strs[i]);

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_CRED_DESC_STRING, NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
			
		if (len >= 0)
		    cred->creddesc = strdup(buf);

		if (tmp) tmp[0]='\0';
		len = my_append(&tmp, 
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_START_TIME_STRING,
				NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
		if (len > 0) {
		    switch(string_to_int(buf, &value)) {
		    case STRING_TO_INT_SUCCESS:
			cred->start_time = value;
			break;
		    case STRING_TO_INT_NONNUMERIC:
			verror_put_string("Non-numeric characters in CRED_START_TIME \"%s\"", buf);
			goto error;
		    case STRING_TO_INT_ERROR:
			goto error;
		    }
		}

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_END_TIME_STRING, NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
		if (len > 0) {
		    switch(string_to_int(buf, &value)) {
		    case STRING_TO_INT_SUCCESS:
			cred->end_time = value;
			break;
		    case STRING_TO_INT_NONNUMERIC:
			verror_put_string("Non-numeric characters in CRED_END_TIME \"%s\"", buf);
			goto error;
		    case STRING_TO_INT_ERROR:
			goto error;
		    }
		}

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_CRED_OWNER_STRING,
				NULL);
		if (len == -1) goto error;
		
		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
			
		if (len >= 0)
		    cred->owner_name = strdup(buf);

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_RETRIEVER_STRING,
				NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
		
		if (len >= 0)
		    cred->retrievers = strdup(buf);

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_KEY_RETRIEVER_STRING,
				NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
		
		if (len >= 0)
		    cred->keyretrieve = strdup(buf);

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_RENEWER_STRING, NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
			
		if (len >= 0)
		    cred->renewers = strdup(buf);

		if (tmp) tmp[0] = '\0';
		len = my_append(&tmp,
				MYPROXY_CRED_PREFIX, "_", strs[i],
				"_", MYPROXY_LOCKMSG_STRING, NULL);
		if (len == -1) goto error;

		len = convert_message(data, tmp,
				      CONVERT_MESSAGE_DEFAULT_FLAGS,
				      &buf);
		if (len == -1) goto error;
			
		if (len >= 0)
		    cred->lockmsg = strdup(buf);
	    }
	    /* de-allocate string-list from parse_add_creds() */
	    for (i=0; i < num_creds; i++) {
		free(strs[i]);
	    }
	    free(strs);
	}
    }

    len = convert_message(data,
	                  MYPROXY_AUTHORIZATION_STRING,
			  CONVERT_MESSAGE_ALLOW_MULTIPLE,
			  &buf);
    if (len > 0) {
	if (parse_auth_data(buf, 
			    &response->authorization_data)) {
	    verror_put_string("Error parsing authorization data from server response");
	    goto error;
	}
    }

    len = convert_message(data,
			  MYPROXY_TRUSTED_CERTS_STRING,
			  CONVERT_MESSAGE_DEFAULT_FLAGS,
			  &tmp);
    if (len > 0) {
	char *tok, *files;
	myproxy_certs_t *curr=NULL;
	
	files = strdup(tmp);
	for (tok = strtok(files, ",");
	     tok; tok = strtok(NULL, ",")) {

	    if (curr == NULL) {
		response->trusted_certs = curr =
		    (myproxy_certs_t *)malloc(sizeof(myproxy_certs_t));
	    } else {
		curr->next = (myproxy_certs_t *)malloc(sizeof(myproxy_certs_t));
		curr = curr->next;
	    }
	    memset(curr, 0, sizeof(myproxy_certs_t));
	    curr->filename = strdup(tok);
	    myproxy_debug("got cert file: %s\n", curr->filename);

	    if (tmp) tmp[0] = '\0';
	    len = my_append(&tmp,
			    MYPROXY_FILEDATA_PREFIX, "_", tok, "=",
			    NULL);
	    if (len == -1) goto error;

	    len = convert_message(data, tmp,
				  CONVERT_MESSAGE_DEFAULT_FLAGS,
				  &buf);
	    if (len == -1) goto error;
	    
	    if (b64_decode(buf, &curr->contents) < 0) {
		verror_put_string("b64 decode failed!");
		goto error;
	    }
	    /* myproxy_debug("contents:\n%s\n", curr->contents); */
	}
	free(files);
    }

    /* Success */
    return_code = 0;

 error:
    if (tmp) free(tmp);
    if (buf) free(buf);
    if (new_data) free(new_data);

    return return_code;
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
    unsigned char *buffer = NULL;
    char error_string[1024];
    size_t readlen;

    assert(data != NULL);
   
    if (GSI_SOCKET_read_token(attrs->gsi_socket, &buffer,
			      &readlen) == GSI_SOCKET_ERROR) {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	verror_put_string("Error reading: %s\n", error_string);
	return -1;
    }
    if (readlen > datalen) {
	memcpy(data, buffer, datalen);
	free(buffer);
	verror_put_string("Response was truncated\n");
	return -2;
    }
    memcpy(data, buffer, readlen);
    free(buffer);
    return readlen;
}

int
myproxy_recv_ex(myproxy_socket_attrs_t *attrs, char **data)
{
    size_t readlen;
    char error_string[1024];

    if (GSI_SOCKET_read_token(attrs->gsi_socket, (unsigned char **)data,
			      &readlen) == GSI_SOCKET_ERROR) {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	verror_put_string("Error reading: %s\n", error_string);
	return -1;
    }
    return readlen;
}

int
myproxy_recv_response(myproxy_socket_attrs_t *attrs,
		      myproxy_response_t *response)
{
    int responselen;
    char *response_buffer = NULL;

    /* Receive a response from the server */
    responselen = myproxy_recv_ex(attrs, &response_buffer);
    if (responselen < 0) {
        return(-1);
    }

    if (responselen == 0) {
	verror_put_string("Server closed connection.\n");
	return(-1);
    }

    /* Make a response object from the response buffer */
    if (myproxy_deserialize_response(response, response_buffer,
				     responselen) < 0) {
	free(response_buffer);
	return(-1);
    }
    free(response_buffer);
    response_buffer = NULL;

    /* Check version */
    if (strcmp(response->version, MYPROXY_VERSION) != 0) {
      verror_put_string("Error: Received invalid version number from server");
      return(-1);
    } 

    /* Check response */
    switch(response->response_type) {
        case MYPROXY_ERROR_RESPONSE:
            verror_put_string("ERROR from server: %s", response->error_string);
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

int myproxy_recv_response_ex(myproxy_socket_attrs_t *socket_attrs,
			     myproxy_response_t *server_response,
			     myproxy_request_t *client_request)
{
    do {
	if (myproxy_recv_response(socket_attrs, server_response) != 0) {
	    return -1;
	}
	if (server_response->response_type == MYPROXY_AUTHORIZATION_RESPONSE) {
	    if (myproxy_handle_authorization(socket_attrs, server_response,
					     client_request) != 0) {
		return -1;
	    }
	}
    } while (server_response->response_type == MYPROXY_AUTHORIZATION_RESPONSE);

    return 0;
}

int myproxy_handle_authorization(myproxy_socket_attrs_t *attrs,
				 myproxy_response_t *server_response,
				 myproxy_request_t *client_request)
{
   myproxy_proto_response_type_t response_type;
   authorization_data_t *d = NULL;
   /* just pointer into server_response->authorization_data, no memory is 
      allocated for this pointer */
   int return_status = -1;
   char *buffer = NULL;
   int bufferlen;

   response_type = server_response->response_type;
   if (response_type == MYPROXY_AUTHORIZATION_RESPONSE) {
       /* Server wants authorization. Try the possibilities. */
       if (client_request->authzcreds != NULL) { /* We have an AUTHZ cert. */
	   d = authorization_create_response(
	           server_response->authorization_data,
		   AUTHORIZETYPE_CERT, client_request->authzcreds,
		   strlen(client_request->authzcreds) + 1);
       }
#if defined(HAVE_LIBSASL2)
       if (d == NULL) { /* No luck with AUTHORIZETYPE_CERT. Try SASL. */
	   d = authorization_create_response(
		   server_response->authorization_data,
		   AUTHORIZETYPE_SASL, "", 1);
       }
#endif
       if (d == NULL) { /* No luck with previous methods. Try PASSWD. */
	   d = authorization_create_response(
		   server_response->authorization_data,
		   AUTHORIZETYPE_PASSWD,
		   client_request->passphrase,
		   strlen(client_request->passphrase) + 1);
       }
       if (d == NULL) { /* No acceptable methods found. */
	   verror_put_string("Cannot create authorization response.");
	   goto end;
       }

       buffer = malloc(d->client_data_len + sizeof(int));
       if (!buffer) {
	   verror_put_string("malloc() failed");
	   goto end;
       }
       (*buffer) = d->method;
       bufferlen = d->client_data_len + sizeof(int);

       memcpy(buffer + sizeof(int), d->client_data, d->client_data_len);

       /* Send the authorization data to the server */
       if (myproxy_send(attrs, buffer, bufferlen) < 0) {
	   goto end;
       }
	 
#if defined(HAVE_LIBSASL2)
       /* SASL method requires more negotiation. */
       if (d->method == AUTHORIZETYPE_SASL) {
	   if (auth_sasl_negotiate_client(attrs, client_request) < 0)
	       goto end;
       }
#endif
   }

   return_status = 0;
end:
   if (buffer) free(buffer);

   return return_status;
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
       if (request->keyretrieve != NULL)
	  free(request->keyretrieve);
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

/*
**
** MyProxy API functins
**
*/

/*
** 
** try_another_server()
**
** Get socket_attrs, request_butter, requestlen
**
*/

int 
myproxy_init( myproxy_socket_attrs_t *socket_attrs,
              myproxy_request_t      *client_request,
              int                     cmd_type )
{
  myproxy_log_use_stream (stderr);

  myproxy_init_socket_attrs( socket_attrs );
  myproxy_init_client_request( client_request, cmd_type );

  return( 0 );
}

int
myproxy_init_socket_attrs( myproxy_socket_attrs_t *socket_attrs )
{
  char *pshost;

  pshost = getenv("MYPROXY_SERVER");
  if (pshost != NULL) 
  {
    socket_attrs->pshost = strdup(pshost);
  }

  if (getenv("MYPROXY_SERVER_PORT")) 
  {
    socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
  } 
  else 
  {
    socket_attrs->psport = MYPROXY_SERVER_PORT;
  }

  return( 0 );
}

int
myproxy_init_client_request( myproxy_request_t *client_request,
                             int                cmd_type )
{
  /* setup defaults */
  client_request->version = strdup( MYPROXY_VERSION ); 
  client_request->command_type = cmd_type;
  
  return( 0 );
}

int
myproxy_open_server_com( myproxy_socket_attrs_t *socket_attrs,
                         const char             *proxyfile )
{
  /* Set up client socket attributes */
  if(myproxy_init_client(socket_attrs) < 0) 
  {
    verror_print_error(stderr);
    return 1;
  }

  /* Authenticate client to server */
  if(myproxy_authenticate_init(socket_attrs, proxyfile) < 0) 
  {
    verror_print_error(stderr);
    return 1;
  }

  return( 0 );
}

int
myproxy_client_username( myproxy_request_t *client_request,
                         const char        *proxyfile,
                         int                dn_as_username )
{
  if (client_request->username == NULL) 
  { /* set default username */
    if (dn_as_username) 
    {
      if (client_request->authzcreds) 
      {
        if (ssl_get_base_subject_file(client_request->authzcreds,
                                      &client_request->username)) 
        {
          fprintf(stderr, "Cannot get subject name from %s\n",
                  client_request->authzcreds);
          return( 1 );
        }
      } 
      else 
      {
        if (ssl_get_base_subject_file(proxyfile,
                                      &client_request->username)) 
        {
          fprintf(stderr,
                  "Cannot get subject name from your certificate\n");
          return( 1 );
        }
      }
    } 
    else 
    {
      char *username = NULL;

      if (!(username = getenv("LOGNAME"))) 
      {
        fprintf(stderr, "Please specify a username.\n");
        return( 1 );
      }
      client_request->username = strdup(username);
    }
  }

  return( 0 );
}

int
myproxy_user_password( myproxy_request_t *client_request,
                       int                use_empty_passwd,
                       int                read_passwd_from_stdin )
{
  if (!use_empty_passwd) 
  {
    /* Allow user to provide a passphrase */
    int rval;

    if (read_passwd_from_stdin) 
    {
      rval = myproxy_read_passphrase_stdin(
                     client_request->passphrase,
                     sizeof(client_request->passphrase),
                     NULL);
    } 
    else 
    {
      rval = myproxy_read_passphrase(client_request->passphrase,
                                     sizeof(client_request->passphrase),
                                     NULL);
    }

    if (rval == -1) 
    {
      myproxy_debug( "myproxy_user_password ERROR\n" );
      verror_print_error(stderr);
      return( 1 );
    }
  }

  return( 0 );
}

int
myproxy_serialize_send_recv( myproxy_request_t      *client_request,
                             myproxy_response_t     *server_response,
                             myproxy_socket_attrs_t *socket_attrs )
{
  char                    request_buffer[2048];
  int                     requestlen;

  /* Serialize client request object */
  requestlen = myproxy_serialize_request(client_request, request_buffer,
                                         sizeof(request_buffer));
  if (requestlen < 0) 
  {
    fprintf(stderr, "Error in myproxy_serialize_request():\n");
    return( 1 );
  }

  /* Send request to the myproxy-server */
  if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) 
  {
    fprintf(stderr, "Error in myproxy_send_request(): %s\n",
            verror_get_string());
    return( 1 );
  }

  /* Continue unless the response is not OK */
  if (myproxy_recv_response_ex(socket_attrs, server_response,
                               client_request) != 0) 
  {
    fprintf(stderr, "%s\n", verror_get_string());
    return( 1 );
  }

  return( 0 );
}

/*
**
** MyProxy API facade functions
**
*/

int
myproxy_init_client_env( myproxy_socket_attrs_t *socket_attrs,
                         myproxy_request_t      *client_request,
                         myproxy_response_t     *server_response,
                         myproxy_data_parameters_t  *data_parameters )
{
    int retval = 0;
    int rval   = 0;

    if( myproxy_client_username( client_request,
                                 NULL,
                                 data_parameters->dn_as_username ) != 0 )
    {
      retval = ( 1 );
    }

    switch(client_request->command_type)
    {
    case MYPROXY_INFO_PROXY:
        /*
         * We don't need to send the real pass phrase to the server as it
         * will just use our identity to authenticate and authorize us.
         * But we need to send over a dummy pass phrase at least
         * MIN_PASS_PHASE_LEN (currently 6) characters long.
         */
        strncpy(client_request->passphrase, "DUMMY-PASSPHRASE",
                sizeof(client_request->passphrase));
        break;

    case MYPROXY_GET_PROXY:
        if (!data_parameters->outputfile) 
        {
            GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(&(data_parameters->outputfile),
                                                    GLOBUS_PROXY_FILE_OUTPUT);
        }

    case MYPROXY_RETRIEVE_CERT:
        if( myproxy_user_password( client_request,
                                   data_parameters->use_empty_passwd,
                                   data_parameters->read_passwd_from_stdin ) != 0 )
        {
          return( 1 );
        }

        /* Attempt anonymous-mode credential retrieval if we don't have a
           credential. */
        GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

        printf("username: %s\n", client_request->username);
        myproxy_print_cred_info(server_response->info_creds, stdout);
        break;

    case MYPROXY_PUT_PROXY:
        /* Create a proxy by running [grid-proxy-init] */
        sprintf(data_parameters->proxyfile, "%s.%u.%u", MYPROXY_DEFAULT_PROXY,
                (unsigned)getuid(), (unsigned)getpid());

        /* If this is a retry the proxy file should be there.  We shouldn't */
        /* have to get it again.                                            */
        if( !(file_exists( data_parameters->proxyfile )) )
        {
          /* Run grid-proxy-init to create a proxy */
          if (grid_proxy_init(data_parameters->cred_lifetime, 
                              data_parameters->proxyfile,
                              data_parameters->read_passwd_from_stdin) != 0) 
          {
            fprintf(stderr, "grid-proxy-init failed\n");
            return( 1 );
          }
        }
       
        data_parameters->destroy_proxy = 1;

        if( myproxy_user_password( client_request,
                                   data_parameters->use_empty_passwd,
                                   data_parameters->read_passwd_from_stdin ) != 0 )
        {
          return( 1 );
        }

        if( myproxy_client_username( client_request,
                                     data_parameters->proxyfile,
                                     data_parameters->dn_as_username ) != 0 )
        {
          return( 1 );
        }

        break;

    case MYPROXY_STORE_CERT:
        if( myproxy_client_username( client_request,
                                     data_parameters->proxyfile,
                                     data_parameters->dn_as_username ) != 0 )
        {
          return( 1 );
        }
        break;

    case MYPROXY_DESTROY_PROXY:
    /*
     * We don't need to send the real pass phrase to the server as it
     * will just use our identity to authenticate and authorize us.
     * But we need to send over a dummy pass phrase at least
     * MIN_PASS_PHASE_LEN (currently 6) characters long.
     */
        strncpy(client_request->passphrase, "DUMMY-PASSPHRASE",
                sizeof(client_request->passphrase));

        if( myproxy_client_username( client_request,
                                     data_parameters->proxyfile,
                                     data_parameters->dn_as_username ) != 0 )
        {
          return( 1 );
        }
        break;

    case MYPROXY_CHANGE_CRED_PASSPHRASE:
        if( myproxy_user_password( client_request,
                                   data_parameters->use_empty_passwd,
                                   data_parameters->read_passwd_from_stdin ) != 0 )
        {
          return( 1 );
        }

        if (data_parameters->read_passwd_from_stdin) 
        {
          rval = myproxy_read_passphrase_stdin(client_request->new_passphrase,
                                        sizeof(client_request->new_passphrase),
                                             "Enter new MyProxy pass phrase:");
        } 
        else 
        {
          rval = myproxy_read_verified_passphrase(
                                         client_request->new_passphrase,
                                         sizeof(client_request->new_passphrase),
                                         "Enter new MyProxy pass phrase:");
        }

        if (rval == -1) 
        {
          verror_print_error(stderr);
          return( 1 );
        }

        if( myproxy_client_username( client_request,
                                     data_parameters->proxyfile,
                                     data_parameters->dn_as_username ) != 0 )
        {
          return( 1 );
        }

        break;

    case MYPROXY_REPLICA_INFO:
        break;

    default:
        fprintf(stderr, "Invalid response type received.\n");
        return( 1 );
        break;
    }

    if( myproxy_open_server_com( socket_attrs, data_parameters->proxyfile ) != 0 )
    {
      myproxy_debug( "myproxy_open_server_com FAILED\n" );
      return( 1 );
    }

    /* Request information on server configuration. */
    client_request->replicate_info = "1";

    if( myproxy_serialize_send_recv( client_request,
                                     server_response,
                                     socket_attrs ) != 0 )
    {
      myproxy_debug( "myproxy_serialize_send_recv FAILED\n" );
      retval = 1;
    }

    return( retval );
}

int
parse_secondary( char *tmp, char *server, char *port )
{
  char *secondary;

  secondary = strchr( tmp, ':' );
  if( secondary )
  {
    strncpy( server, tmp, secondary - tmp );
    server[secondary - tmp] = '\0';
    strcpy( port, secondary + 1 );
  }
  else
  {
    strcpy( server, tmp );
  }

  return( 0 );
}

int
is_a_retry_command( int command )
{
  int retval = 0;

  switch( command )
  {
    case MYPROXY_PUT_PROXY:
    case MYPROXY_DESTROY_PROXY:
    case MYPROXY_CHANGE_CRED_PASSPHRASE:
    case MYPROXY_STORE_CERT:
    case MYPROXY_REPLICA_INFO: 
    case MYPROXY_INFO_PROXY:
        retval = 0; 
        break;

    case MYPROXY_GET_PROXY:
    case MYPROXY_RETRIEVE_CERT: 
        retval = 1; 
        break;

    default: 
        retval = 0; 
        break;
  }

  return( retval );
}
  
int
myproxy_failover( myproxy_socket_attrs_t *socket_attrs,
                  myproxy_request_t      *client_request,
                  myproxy_response_t     *server_response,
                  myproxy_data_parameters_t  *data_parameters )
{
    struct    secondary_server
    {
      char   server[256];
      char   port[256];
      int    tried;
      struct secondary_server *next;
    };

    struct    secondary_server *secnds        = NULL;
    struct    secondary_server *another       = NULL;
    struct    secondary_server *newone        = NULL;
    struct    secondary_server *current_secnd = NULL;

    int       isprimary                    = 0; 
    int       retval                      = 0;
    int       done                        = 0;
    int       redirect                    = 0;
    int       doing_secnds                = 0;

    char     *primary                      = NULL;
    char      delegfile[128];
    char     *pos;
    char     *start;
    char      mhost[256];
    char      mport[256];
    char      tmp[256];

    do
    {
      myproxy_debug( "Trying socket: %s. %d\n", 
                     socket_attrs->pshost, 
                     socket_attrs->psport );

      /* Open communications.  Send the command type.  Get response */
      if( myproxy_init_client_env( socket_attrs, 
                                   client_request, 
                                   server_response, 
                                   data_parameters ) != 0 )
      {
        myproxy_debug( "myproxy_init_client_env FAILED\n" );
      }

      /* If this is our first time through, get primary and list of secondary */
      if( secnds == NULL && primary == NULL )
      {
      /* Did we get any info back.  Is failover set up?                    */
      /* If failover is configured, we should get back a list of secondary    */
      /* or a primary.  We we are dealing with a primary, we will have a     */
      /* list of secondary to retry some commands on (delegate and retrieve). */
      /* If we are dealing with a secondary, the command was probably sent to  */
      /* the wrong place.  Try to redirect it, unless it is a delegat or   */
      /* retrieve, then we can just deal with it on the secondary.             */
        if( server_response->replicate_info != NULL )
        {
          myproxy_debug( "SLAVE: %s\n",  
                         server_response->replicate_info->secondary_servers );
          myproxy_debug( "MASTER: %s\n",  
                         server_response->replicate_info->primary_server );
          myproxy_debug( "IS: %d\n",   
                         server_response->replicate_info->isprimary );

          if( server_response->replicate_info->primary_server )
          {
            primary = strdup( server_response->replicate_info->primary_server );
          }

          if( server_response->replicate_info->secondary_servers )
          {
            isprimary = 1;
            start = server_response->replicate_info->secondary_servers;

            while( (pos = strchr( start, ';' )) )
            {
              strncpy( tmp, start, pos - start );
              tmp[pos - start] = '\0';
              start = pos + 1;

              newone = malloc( sizeof( struct secondary_server ) );
              memset(newone, 0, sizeof(struct secondary_server));

              if( secnds == NULL )
              {
                secnds = newone;
                another = newone;
              } 

              parse_secondary( tmp, newone->server, newone->port );

              newone->tried = 0;
              newone->next = NULL;

              another->next = newone;
              another = newone;
            }     
 
            newone = malloc( sizeof( struct secondary_server ) );
            memset(newone, 0, sizeof(struct secondary_server));

            parse_secondary( start, newone->server, newone->port );
            newone->tried = 0;
            newone->next = NULL;

            if( secnds == NULL )
            {
              secnds = newone;
            }
            else
            {
              another->next = newone;
            }
          }
        }
      }

      if( (server_response->response_type == MYPROXY_ERROR_RESPONSE) ||
          ( (verror_is_error()) && (doing_secnds) ) )
      {
        /* figure out if it is an error we retry on */

        /* The failover stuff is not configured so do things like we use to, */
        /* fail out and give the user an error message.                      */
        if( secnds == NULL && primary == NULL )
        {
          myproxy_debug( "Slave and primary are not set.\n" );
          printf( "ERROR and no secondary or primary are not set: %s\n", 
                  verror_get_string() );
          return( 1 );
        }

        /* Figure out if this is a primary or secondary */
        if( isprimary )
        {
          /* Failover is configured and the command was originally sent to */
          /* the primary.  If the command can be done on the secondary, start  */
          /* looping through the secondary until we either have success or we */
          /* have tried all of them.                                       */
          if( is_a_retry_command( client_request->command_type ) )
          {
            myproxy_debug( "Find next secondary server in list\n" );

            /* Point to first secondary in the list. */
            if( current_secnd == NULL )
            {
              current_secnd = secnds;
            } 
            else
            {
              /* Try the next secondary in the list. */
              current_secnd = current_secnd->next;
            } 

            /* There is a secondary to try command on. */
            if( current_secnd != NULL )
            {
              /* close old socket */
              if (socket_attrs != NULL) 
              {
                 if (socket_attrs->pshost != NULL)
                 {
                   free(socket_attrs->pshost);
                 }

                 GSI_SOCKET_destroy(socket_attrs->gsi_socket);
                 close(socket_attrs->socket_fd);
                 free(socket_attrs);
              }

              socket_attrs = malloc(sizeof(*socket_attrs));
              memset(socket_attrs, 0, sizeof(*socket_attrs));

              socket_attrs->pshost = current_secnd->server;

              if( current_secnd->port )
              {
                socket_attrs->psport = atoi( current_secnd->port );
              }  

              /* Clear the server_response for next go around */
              server_response = malloc(sizeof(*server_response));
              memset(server_response, 0, sizeof(*server_response));

              /* We will be passing password in as a value */
              data_parameters->use_empty_passwd = 1;

              /* Clear old error messages (Should we do this???) */
              verror_clear();

              /* Hack for handling error conditions and stuff... */
              doing_secnds = 1;

              myproxy_debug( "NEW SOCK: %s. %d\n", 
                             socket_attrs->pshost, 
                             socket_attrs->psport ); 
            }
            else
            {
              printf( "Tried all servers, none worked.\n" );
              printf( "Tried all of the secondary, still had error: %s\n", 
                      verror_get_string() );
              return( 1 );
            }
          }
          else
          {
            printf( "Can't perform this operation on a secondary server.\n" );
            printf( "Bad secondary operation: %s\n", verror_get_string() );
            return( 1 );
          }
        }
        else
        {
          /* This is a secondary */
          /* A command was sent to a secondary that should be tried on the */
          /* primary.  Check to see if we have a primary and redirect.   */
          if( primary )
          {
            /* redirect to primary */
            myproxy_debug( "Redirect to primary: %s\n", primary );
            parse_secondary( primary, mhost, mport );

            if( redirect == 1 )
            {
              printf( "Already redirected once\n" );
              done = 1;
            }
            else
            {
              redirect = 1;
            }




              /* close old socket */
              if (socket_attrs != NULL) 
              {
                 if (socket_attrs->pshost != NULL)
                 {
                   free(socket_attrs->pshost);
                 }

                 GSI_SOCKET_destroy(socket_attrs->gsi_socket);
                 close(socket_attrs->socket_fd);
                 free(socket_attrs);
              }

              socket_attrs = malloc(sizeof(*socket_attrs));
              memset(socket_attrs, 0, sizeof(*socket_attrs));

              socket_attrs->pshost = mhost;

              if( mport )
              {
                socket_attrs->psport = atoi( mport );
              }  

              /* Clear the server_response for next go around */
              server_response = malloc(sizeof(*server_response));
              memset(server_response, 0, sizeof(*server_response));

              /* We will be passing password in as a value */
              data_parameters->use_empty_passwd = 1;

              /* Clear old error messages (Should we do this???) */
              verror_clear();

              myproxy_debug( "NEW SOCK: %s. %d\n", 
                             socket_attrs->pshost, 
                             socket_attrs->psport ); 



          }
          else
          {
            myproxy_debug( "No where to redirect.\n" );
            printf( "Can't redirect: %s\n", verror_get_string() );
            return( 1 );
          }
        }
      }
      else if( (verror_is_error()) )
      {
        printf( "VERROR: %s\n", verror_get_string() );
        return( 1 );
      }
      else if( server_response->response_type == MYPROXY_OK_RESPONSE )
      {
        done = 1;
      }
    }
    while( !done );

    switch(client_request->command_type)
    {
    case MYPROXY_INFO_PROXY:
        switch(server_response->response_type)
        {
        case MYPROXY_ERROR_RESPONSE:
            fprintf(stderr, "Received ERROR_RESPONSE: %s\n",
                    server_response->error_string);
            retval = (1);
            break;

        case MYPROXY_OK_RESPONSE:
            printf("username: %s\n", client_request->username);
            myproxy_print_cred_info(server_response->info_creds, stdout);
            break;

        default:
            fprintf(stderr, "Invalid response type received.\n");
            retval = (1);
            break;
        }
        break;

    case MYPROXY_GET_PROXY:
        /* Accept delegated credentials from server */
        if (myproxy_accept_delegation(socket_attrs, 
                                      delegfile, 
                                      sizeof(delegfile),
                                      NULL) < 0) 
        {
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
        if (data_parameters->outputfile != NULL) 
        {
            if (copy_file(delegfile, data_parameters->outputfile, 0600) < 0) 
            {
                fprintf(stderr, "Error creating file: %s\n", 
                        data_parameters->outputfile);
                return(1);
            }
            ssl_proxy_file_destroy(delegfile);
        }

        printf("A proxy has been received for user %s in %s\n",
               client_request->username, data_parameters->outputfile);

        printf("username: %s\n", client_request->username);
        myproxy_print_cred_info(server_response->info_creds, stdout);
        break;

    case MYPROXY_RETRIEVE_CERT:
        printf("username: %s\n", client_request->username);

        if (myproxy_accept_credentials(socket_attrs, delegfile,
                                       sizeof(delegfile)) < 0) 
        {
          fprintf(stderr, "Error in (myproxy_accept_credentials(): %s\n",
                  verror_get_string());
          return( 1 );
        }

        /* I need to get this file out so that I don't have to pass key */
        /* and cert in.                                                 */
        data_parameters->outputfile = strdup( delegfile );
        myproxy_print_cred_info(server_response->info_creds, stdout);
        break;

    case MYPROXY_PUT_PROXY:
        /* Delegate credentials to server using the default lifetime of */
        /* the cert.                                                    */

        if (myproxy_init_delegation(socket_attrs, 
                                    data_parameters->proxyfile, 
                                    data_parameters->cred_lifetime,
                                    NULL /* no passphrase */
                                   ) < 0) 
        {
          verror_print_error(stderr);
          return( 1 );
        }

        /* Get final response from server */
        if (myproxy_recv_response(socket_attrs, server_response) != 0) 
        {
          verror_print_error(stderr);
          return( 1 );
        }

        /* Get actual lifetime from credential. */
        if (data_parameters->cred_lifetime == 0) 
        {
          time_t cred_expiration;

          if( ssl_get_times(data_parameters->proxyfile, NULL, &cred_expiration) 
                  == 0 )
          {
            data_parameters->cred_lifetime = cred_expiration-time(0);

            if (data_parameters->cred_lifetime <= 0) 
            {
              fprintf(stderr, "Error: Credential expired!\n");
              return( 1 );
            }
          }
        }

        /* Delete proxy file */
        if (grid_proxy_destroy(data_parameters->proxyfile) != 0) 
        {
          fprintf(stderr, "Failed to remove temporary proxy credential.\n");
          return( 1 );
        }
        data_parameters->destroy_proxy = 0;

        printf( "A proxy valid for %d hours (%.1f days) for user %s now exists on %s.\n",
                (int)(data_parameters->cred_lifetime/SECONDS_PER_HOUR), 
                (float)((data_parameters->cred_lifetime/SECONDS_PER_HOUR)/24.0), 
                client_request->username, 
                socket_attrs->pshost );
        break;

    case MYPROXY_STORE_CERT:
        /* Send end-entity credentials to server. */
        if (myproxy_init_credentials(socket_attrs,
                                     data_parameters->credkeybuf) < 0) 
        {
            fprintf(stderr, "%s\n", verror_get_string());
            return( 1 );
        }

        /* Get final response from server */
        if (myproxy_recv_response(socket_attrs, server_response) != 0) 
        {
            fprintf(stderr, "%s\n", verror_get_string());
            return( 1 );
        }

        printf( "Credentials saved to myproxy server.\n" );
        break;

    case MYPROXY_DESTROY_PROXY:
        /* Check response */
        switch(server_response->response_type) 
        {
        case MYPROXY_ERROR_RESPONSE:
            fprintf(stderr, "Received error from server: %s\n",
                    server_response->error_string);
            return 1;

        case MYPROXY_OK_RESPONSE:
            if (client_request->credname) 
            {
              printf( "MyProxy credential '%s' for user %s was successfully removed.\n",
                     client_request->credname, client_request->username );
            } 
            else 
            {
              printf("Default MyProxy credential for user %s was successfully removed.\n",
                     client_request->username);
            }
            break;

        default:
            fprintf(stderr, "Invalid response type received.\n");
            return 1;
        }
        break;

    case MYPROXY_CHANGE_CRED_PASSPHRASE:
        /*Check response */
        switch (server_response->response_type) 
        {
        case MYPROXY_ERROR_RESPONSE:
            fprintf (stderr, "Error: %s\nPass phrase unchanged.\n",
                     server_response->error_string);

            return 1;

        case MYPROXY_OK_RESPONSE:
            printf("Pass phrase changed.\n");
            break;

        default:
            fprintf (stderr, "Invalid response type received.\n");
            return 1;
        }
        break;

    case MYPROXY_REPLICA_INFO:
        break;

    default:
        fprintf(stderr, "Invalid response type received.\n");
        retval = (1);
        break;
    }

    return( retval );
}

int
myproxy_get_info( myproxy_request_t      *client_request,
                  myproxy_response_t     *server_response,
                  myproxy_socket_attrs_t *socket_attrs,
                  int                     dn_as_username )
{
    int retval = 0;

    /*
     * We don't need to send the real pass phrase to the server as it
     * will just use our identity to authenticate and authorize us.
     * But we need to send over a dummy pass phrase at least
     * MIN_PASS_PHASE_LEN (currently 6) characters long.
     */
    strncpy(client_request->passphrase, "DUMMY-PASSPHRASE",
            sizeof(client_request->passphrase));

    if( myproxy_client_username( client_request,
                                 NULL,
                                 dn_as_username ) != 0 )
    {
      retval = ( 1 );
    }

    if( myproxy_open_server_com( socket_attrs,
                                 NULL ) != 0 )
    {
      retval = ( 1 );
    }

    /* Request information on server configuration. */
    client_request->replicate_info = "1";

    if( myproxy_serialize_send_recv( client_request,
                                     server_response,
                                     socket_attrs ) != 0 )
    {
      retval = ( 1 );
    }

    /* Check response */
    switch(server_response->response_type)
    {
    case MYPROXY_ERROR_RESPONSE:
        fprintf(stderr, "Received ERROR_RESPONSE: %s\n",
                server_response->error_string);
        retval = (1);
        break;

    case MYPROXY_OK_RESPONSE:
        printf("username: %s\n", client_request->username);
        myproxy_print_cred_info(server_response->info_creds, stdout);
        break;

    default:
        fprintf(stderr, "Invalid response type received.\n");
        retval = (1);
        break;
    }

    printf ("\n");

    return( retval );
}

/*--------- Helper functions ------------*/
/*
 * convert_message()
 *
 * Searches a buffer and locates varname. Stores contents of varname into line
 * e.g. convert_message(buf, "VERSION=", &version);
 * The line argument should be a pointer to NULL or a malloc'ed buffer.
 * The line buffer will be realloc'ed as required.
 * The buffer MUST BE NULL TERMINATED.
 *
 * flags is a bitwise or of the following values:
 *     CONVERT_MESSAGE_ALLOW_MULTIPLE      Allow a multiple instances of
 *                                         varname, in which case the rvalues
 *                                         are concatenated.
 *
 * Returns the number of characters copied into the line (not including the
 * terminating '\0'). On error returns -1, setting verror. Returns -2
 * if string not found
 */
static int
convert_message(const char			*buffer,
		const char			*varname, 
		const int			flags,
		char				**line)
{
    int				foundone = 0;
    char			*varname_start;
    int				return_value = -1;
    int				line_index = 0;
    const char			*buffer_p;

    assert(buffer != NULL);
    
    assert(varname != NULL);
    assert(line != NULL);

    if ((flags & ~CONVERT_MESSAGE_KNOWN_FLAGS) != 0)
    {
	verror_put_string("Illegal flags value (%d)", flags);
	goto error;
    }

    /*
     * Our current position in buffer is in buffer_p. Since we're
     * done modifying buffer buffer_p can be a const.
     */
    buffer_p = buffer;
    
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
		*line = realloc(*line, line_index+2);
		(*line)[line_index] = '\n';
		line_index++;
		(*line)[line_index] = '\0';
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

	*line = realloc(*line, line_index+value_length+1);
	/* Copy it over */
	strncpy((*line)+line_index, value_start, value_length);
	line_index += value_length;
	
	/* Make sure line stays NULL-terminated */
	(*line)[line_index] = '\0';

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
    return_value = strlen(*line);
    
  error:
    if (return_value == -1 || return_value == -2)
    {
	/* Don't return anything in line on error */
	if (*line) (*line)[0] = '\0';
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

      case MYPROXY_CHANGE_CRED_PASSPHRASE:
	string = "4";
	break;

      case MYPROXY_STORE_CERT:
        string = "5";
        break;

      case MYPROXY_RETRIEVE_CERT:
        string = "6";
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

int
myproxy_init_credentials(myproxy_socket_attrs_t *attrs,
                         const char             *delegfile)
{

  char error_string[1024];

  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_credentials_init_ext(attrs->gsi_socket,
                                     delegfile) == GSI_SOCKET_ERROR) {

    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                sizeof(error_string));

    verror_put_string("Error storing  credentials: %s\n", error_string);
    return -1;
  }
  return 0;
}

/*
** Accepts a credential and stores the information in a temp file
** delegfile. 
*/
int
myproxy_accept_credentials(myproxy_socket_attrs_t *attrs,
                           char                   *delegfile,
                           int                     delegfile_len)
{
  char error_string[1024];

  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_credentials_accept_ext(attrs->gsi_socket,
                                        delegfile,
                                        delegfile_len) == GSI_SOCKET_ERROR)
  {
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                sizeof(error_string));

    verror_put_string("Error accepting credentials: %s\n", error_string);
    return -1;
  }
  return 0;
}

/*
** Retrieves a credential from the repository and sends it to the client.  
*/
int
myproxy_get_credentials(myproxy_socket_attrs_t *attrs,
                         const char             *delegfile)
{
  char error_string[1024];

  if (attrs == NULL)
    return -1;

  if (GSI_SOCKET_get_creds(attrs->gsi_socket,
                                     delegfile) == GSI_SOCKET_ERROR)
  {
    GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                sizeof(error_string));

    verror_put_string("Error getting credentials: %s\n", error_string);
    return -1;
  }

  return 0;
}

/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int
grid_proxy_init(int seconds, const char *proxyfile, int read_passwd_from_stdin) {

    int rc;
    char command[128];
    int hours;
    char *proxy_mode;
    int old=0;

    assert(proxyfile != NULL);

    hours = seconds / SECONDS_PER_HOUR;

    proxy_mode = getenv("GT_PROXY_MODE");
    if (proxy_mode && strcmp(proxy_mode, "old") == 0) {
        old=1;
    }

    sprintf(command, "grid-proxy-init -verify -valid %d:0 -out %s%s%s%s",
            hours, proxyfile, read_passwd_from_stdin ? " -pwstdin" : "",
            myproxy_debug_get_level() ? " -debug" : "", old ? " -old" : "");
    rc = system(command);

    return rc;
}

/* grid_proxy_destroy()
 *
 * Fill the proxy file with zeros and unlink.
 *
 * returns 0 if OK, -1 on error
 */
int
grid_proxy_destroy(const char *proxyfile)
{
    if (ssl_proxy_file_destroy(proxyfile) != SSL_SUCCESS) {
        verror_print_error(stderr);
        return -1;
    }
    return 0;
}

