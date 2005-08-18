/*
 *
 * MyProxy protocol API
 *
 */
#ifndef __MYPROXY_PROTOCOL_H
#define __MYPROXY_PROTOCOL_H

/* Protocol commands */
typedef enum
{
    MYPROXY_GET_PROXY,
    MYPROXY_PUT_PROXY,
    MYPROXY_INFO_PROXY,
    MYPROXY_DESTROY_PROXY,
    MYPROXY_CHANGE_CRED_PASSPHRASE,
    MYPROXY_STORE_CERT,
    MYPROXY_RETRIEVE_CERT,
    MYPROXY_REPLICA_INFO
} myproxy_proto_request_type_t;

/* server response codes */
typedef enum
{
    MYPROXY_OK_RESPONSE,
    MYPROXY_ERROR_RESPONSE,
    MYPROXY_AUTHORIZATION_RESPONSE,
    MYPROXY_REPLICA_INFO_RESPONSE
} myproxy_proto_response_type_t;

/* client/server socket attributes */
typedef struct 
{
  char *pshost;	
  int psport;
  int socket_fd;
  struct _gsi_socket *gsi_socket; 
} myproxy_socket_attrs_t;

/* A client request object */
#define REGULAR_EXP 1
#define MATCH_CN_ONLY 0

typedef struct
{
    char                         *version;
    char                         *username;
    char                         passphrase[MAX_PASS_LEN+1];
    char                         new_passphrase[MAX_PASS_LEN+1];
    myproxy_proto_request_type_t command_type;
    int                          proxy_lifetime;
    char                         *retrievers;
    char                         *renewers;
    char			 *credname;
    char			 *creddesc;
    char			 *authzcreds;
    char 		         *keyretrieve;
    char                         *replicate_info;
    char                         *owner;
    int                          want_trusted_certs; /* 1=yes, 0=no */
} myproxy_request_t;

struct myproxy_server
{
  char                          *secondary_servers;
  char                          *primary_server;
  int                            isprimary;
}; 
typedef struct myproxy_server myproxy_server_t;

/*
** This is stuff used by the failover routine.  These are values that are
** unique to different operations.  Instead of passing lots of parameters
** to the failover function we can pass a single struct.  Most of these 
** values have meaning to only a single operation, it seemed silly to have
** every operation have to worry about them when calling failover.
*/
typedef struct myproxy_data_parameters
{
  /*
  ** Used by myproxy-store.  These values are the location of the 
  ** end-entity user credintail that is being stored.
  */
  char                          *certfile;
  char                          *keyfile;

  char                          *credkeybuf;

  /* File name holding returned proxy or credential. */
  char                          *outputfile;

  /* Proxy file created that will be stored in the repository */
  char                          *proxyfile;

  /* Define various ways data may be defined in reposiroty */
  int                            use_empty_passwd;
  int                            read_passwd_from_stdin;
  int                            dn_as_username;

  /* Used by myproxy-init.  Defines the lifetime of the proxy. */
  int                            cred_lifetime;

  /* Indicates if a proxy was created and needs to be destroyed */
  int                            destroy_proxy;
} myproxy_data_parameters_t;

/* A server response object */
typedef struct
{
  char                          *version;
  myproxy_proto_response_type_t response_type;
  authorization_data_t		**authorization_data;
  char				*error_string;
  myproxy_creds_t		*info_creds;

  /*
  ** Extensions for replication and fail-over.
  */
  myproxy_server_t              *replicate_info;
  char                          *redirect;
  myproxy_certs_t               *trusted_certs;
} myproxy_response_t;

  
/*
 * myproxy_init_client()
 *
 * Create a generic client by creating a GSI socket and connecting to a a host 
 *
 * returns the file descriptor of the connected socket or
 *   -1 if an error occurred
 */
int myproxy_init_client(myproxy_socket_attrs_t *attrs);

/*
 * myproxy_authenticate_init()
 * 
 * Perform client-side authentication
 *
 * returns -1 if unable to authenticate, 0 if authentication successful
 */ 
int myproxy_authenticate_init(myproxy_socket_attrs_t *attr,
			      const char *proxyfile);

/*
 * myproxy_authenticate_accept()
 * 
 * Perform server-side authentication and retrieve the client's DN
 *
 * returns -1 if unable to authenticate, 0 if authentication successful
 */ 
int myproxy_authenticate_accept(myproxy_socket_attrs_t *attr, 
                                char *client_name, const int namelen);

/*
 * myproxy_serialize_request()
 * 
 * Serialize a request object into a buffer to be sent over the network.
 * Use myproxy_serialize_request_ex() instead.
 *
 * Returns the serialized data length or -1 on error.
 */
int myproxy_serialize_request(const myproxy_request_t *request, 
			      char *data, const int datalen);

/*
 * myproxy_serialize_request_ex()
 * 
 * Serialize a request object into a newly allocated buffer of correct size.
 * The caller should free() the buffer after use.
 *
 * Returns the serialized data length or -1 on error.
 */
int myproxy_serialize_request_ex(const myproxy_request_t *request, 
				 char **data);


/*
 * myproxy_deserialize_request()
 * 
 * Deserialize a buffer into a request object.
 *
 * returns 0 if succesful, otherwise -1
 */
int myproxy_deserialize_request(const char *data, const int datalen, 
				myproxy_request_t *request);

/*
 * myproxy_serialize_response()
 * 
 * Serialize a response object into a buffer to be sent over the network.
 * Use myproxy_serialize_response_ex() instead.
 *
 * returns the number of characters put into the buffer 
 * (not including the trailing NULL)
 */
int
myproxy_serialize_response(const myproxy_response_t *response, 
                           char *data, const int datalen); 

/*
 * myproxy_serialize_response_ex()
 * 
 * Serialize a response object into a newly allocated buffer of correct size.
 * The caller should free() the buffer after use.
 *
 * returns the number of characters put into the buffer 
 * (not including the trailing NULL)
 */
int
myproxy_serialize_response_ex(const myproxy_response_t *response, 
			      char **data); 

/*
 * myproxy_deserialize_response()
 *
 * Serialize a a buffer into a response object.
 *
 * returns the number of characters put into the buffer 
 * (not including the trailing NULL)
 */
int myproxy_deserialize_response(myproxy_response_t *response, 
				 const char *data, const int datalen);

/*
 * myproxy_send()
 * 
 * Sends a buffer
 *
 * returns 0 on success, -1 on error
 */
int myproxy_send(myproxy_socket_attrs_t *attrs,
                 const char *data, const int datalen);

/*
 * myproxy_recv()
 *
 * Receives a message into the buffer.
 * Use myproxy_recv_ex() instead.
 *
 * returns bytes read on success, -1 on error, -2 on truncated response
 * 
 */
int myproxy_recv(myproxy_socket_attrs_t *attrs,
		 char *data, const int datalen);

/*
 * myproxy_recv_ex()
 *
 * Receives a message into a newly allocated buffer of correct size.
 * The caller must deallocate the buffer.
 *
 * returns bytes read on success, -1 on error
 * 
 */
int myproxy_recv_ex(myproxy_socket_attrs_t *attrs, char **data);

/*
 * myproxy_init_delegation()
 *
 * Delegates a proxy based on the credentials found in file 
 * location delegfile good for lifetime_seconds
 *
 * returns 0 on success, -1 on error 
 */
int myproxy_init_delegation(myproxy_socket_attrs_t *attrs,
			    const char *delegfile,
			    const int lifetime_seconds,
			    char *passphrase);

/*
 * myproxy_accept_delegation()
 *
 * Accepts delegated credentials into file location data
 *
 * returns 0 on success, -1 on error 
 */
int myproxy_accept_delegation(myproxy_socket_attrs_t *attrs, char *data,
			      const int datalen, char *passphrase);

/*
 * myproxy_accept_credentials()
 *
 * Accepts credentials into file location data
 *
 * returns 0 on success, -1 on error
 */
int
myproxy_accept_credentials(myproxy_socket_attrs_t *attrs,
                           char                   *delegfile,
                           int                     delegfile_len);

/*
 * myproxy_init_credentials()
 *
 * returns 0 on success, -1 on error 
 */
int
myproxy_init_credentials(myproxy_socket_attrs_t *attrs,
                         const char             *delegfile);

int
myproxy_get_credentials(myproxy_socket_attrs_t *attrs,
                         const char             *delegfile);

/*
 * myproxy_free()
 * 
 * Frees up memory used for creating request, response and socket objects 
 */
void myproxy_free(myproxy_socket_attrs_t *attrs, myproxy_request_t *request,
		  myproxy_response_t *response);

/*
 * myproxy_recv_response()
 *
 * Helper function that combines myproxy_recv() and
 * myproxy_deserialize_response() with some error checking.
 *
 */
int myproxy_recv_response(myproxy_socket_attrs_t *attrs,
			  myproxy_response_t *response); 

/*
 * myproxy_recv_response_ex()
 *
 * Helper function that combines myproxy_recv(),
 * myproxy_deserialize_response(), and myproxy_handle_authorization()
 * with some error checking.
 *
 */
int myproxy_recv_response_ex(myproxy_socket_attrs_t *attrs,
			     myproxy_response_t *response,
			     myproxy_request_t *client_request);

/*
 * myproxy_handle_authorization()
 *
 * If MYPROXY_AUTHORIZATION_RESPONSE is received, pass it to this
 * function to be processed.
 *
 */
int myproxy_handle_authorization(myproxy_socket_attrs_t *attrs,
				 myproxy_response_t *server_response,
				 myproxy_request_t *client_request);

/*
 * myproxy_resolve_hostname()
 *
 * Helper function to fully-qualify the given hostname for
 * authorization of server identity.
 *
 */
void myproxy_resolve_hostname(char **host);

int
myproxy_init( myproxy_socket_attrs_t                *socket_attrs,
              myproxy_request_t                     *client_request,
              int                                    cmd_type );

int
myproxy_init_socket_attrs( myproxy_socket_attrs_t   *socket_attrs );

int
myproxy_init_client_request( myproxy_request_t      *client_request,
                             int                     cmd_type );

int
myproxy_open_server_com( myproxy_socket_attrs_t     *socket_attrs,
                         const char                 *proxyfile );

int
myproxy_client_username( myproxy_request_t          *client_request,
                         const char                 *proxyfile,
                         int                         dn_as_username );

int
myproxy_user_password( myproxy_request_t            *client_request,
                       int                           use_empty_passwd,
                       int                           read_passwd_from_stdin );

int
myproxy_serialize_send_recv( myproxy_request_t      *client_request,
                             myproxy_response_t     *server_response,
                             myproxy_socket_attrs_t *socket_attrs );

/*
 * myproxy_failover()
 * 
 * Code to handle failover.  Each client operation calls this function.
 * The function will look for primary/secondary configuration information
 * and handle failover if configured. 
 *
 * returns !0 if unable to authenticate, 0 if authentication successful
 */ 
int
myproxy_failover( myproxy_socket_attrs_t *socket_attrs,
                  myproxy_request_t      *client_request,
                  myproxy_response_t     *server_response,
                  myproxy_data_parameters_t  *data_parameters );

int
myproxy_init_client_env( myproxy_socket_attrs_t *socket_attrs,
                         myproxy_request_t      *client_request,
                         myproxy_response_t     *server_response,
                         myproxy_data_parameters_t  *data_parameters );

#endif /* __MYPROXY_PROTOCOL_H */
