/*
 * myproxy.h
 *
 * Defines protocol for communciation with myproxy-server
 *
 */

#ifndef __MYPROXY_H
#define __MYPROXY_H

#include "gsi_socket.h"

/* Maximum and minimum lengths for password */
#define MAX_PASS_LEN  10
#define MIN_PASS_LEN  5

/* Define default myproxy-server */
#define MYPROXYSERVER_PORT     6667
#define MYPROXYSERVER_HOST     "localhost"

/* Default proxy lifetime */
#define MYPROXY_DEFAULT_HOURS  84

/* Protocol commands */
#define MYPROXY_GET_COMMAND   "GET_PROXY"
#define MYPROXY_PUT_COMMAND   "PUT_PROXY"
#define MYPROXY_INFO_COMMAND  "INFO_PROXY"

/* Location of default proxy */
#define MYPROXY_DEFAULT_PROXY  "/tmp/myproxy-proxy"

/* myproxy client protocol information */
#define MYPROXY_VERSION_STRING     "VERSION="
#define MYPROXY_COMMAND_STRING      "COMMAND="
#define MYPROXY_USERNAME_STRING     "USERNAME="
#define MYPROXY_PASSPHRASE_STRING   "PASSPHRASE="
#define MYPROXY_LIFETIME_STRING     "LIFETIME="


/* myproxy-server protocol information */
#define MYPROXY_RESPONSE_STRING     "RESPONSE="
#define MYPROXY_ERROR_STRING        "ERROR="
#define MYPROXY_OK_RESPONSE         "OK"
#define MYPROXY_ERROR_RESPONSE      "ERROR"

typedef struct 
{
  char *pshost;	
  int psport;
  int socket_fd;
  GSI_SOCKET *gsi_socket; 
} myproxy_socket_attrs_t;


typedef struct
{
    char *version;
    char *username;
    char passphrase[MAX_PASS_LEN+1];
    char *command;
    int hours;
} myproxy_request_t;


typedef struct
{
  char *version;
  char *response_string;
  char *error_string;
} myproxy_response_t;



/*
 * myproxy_init_client()
 *
 * Create a generic client by craeting a GSI socket and connecting to a a host 
 *
 * returns the file descriptor of the connected socket or -1 if an error occurred  
 */
int myproxy_init_client(myproxy_socket_attrs_t *attrs);

/*
 * myproxy_create_request()
 * 
 * Serialize a request object into a buffer to be sent over the network.
 *
 * returns the number of characters put into the buffer 
 * (not including the trailing NULL)
 */
int  myproxy_create_request_buffer(const myproxy_request_t *request, 
			    char *data, const int datalen);

/*
 * myproxy_send_request()
 * 
 * Sends a request buffer with authentication done via GSI
 *
 * returns -1 if GSI_SOCKET_write_buffer failed or 0 on success
 */
int  myproxy_send_request(myproxy_socket_attrs_t *attrs,
			  const char *data, const int datalen);

/*
 * myproxy_recv_response()
 *
 * Receives a response buffer from the myproxy-server 
 *
 * returns GSI_SOCKET_read_buffer()
 * 
 */
int  myproxy_recv_response(myproxy_socket_attrs_t *attrs,
			   char *data, const int datalen);

/*
 * myproxy_create_response()
 *
 * Serialize a response object into a buffer to be sent over the network.
 *
 * returns the number of characters put into the buffer 
 * (not including the trailing NULL)
 */
int myproxy_create_response(myproxy_response_t *response, 
			    const char *data, const int datalen);

/* 
 * myproxy_check_response()
 *
 * Verifies a response object matches the correct version 
 * and the header contains "RESULT=OK" 
 *
 * returns 0 if "RESULT=OK", 1 if "RESULT=ERROR" or unknown response
 */
int myproxy_check_response(myproxy_response_t *response);

/*
 * myproxy_delegate_proxy()
 *
 * Delegates a proxy based on the credentials found in file location delegfile
 *
 * returns 0 on success, -1 on error 
 */
int myproxy_delegate_proxy(myproxy_socket_attrs_t *attrs, const char *delegfile);

/*
 * myproxy_destroy_client()
 * 
 * Frees up memory used for creating request, response and socket objects 
 */
void myproxy_destroy_client(myproxy_socket_attrs_t *attrs, myproxy_request_t *request, myproxy_response_t *response);

/*---------------------------- Helper functions ----------------------------*/ 

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
int  convert_message(const char *buffer, const char *varname, 
		     char *line, const int linelen); 

/*--------------------------------------------------------------------------*/


#endif /* __MYPROXY_H */
