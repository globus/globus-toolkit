/*
 * myproxy_server.h
 *
 * Myproxy server header file
 */
#ifndef __MYPROXY_SERVER_H
#define __MYPROXY_SERVER_H

/* Minimum pass phrase length */
#define MIN_PASS_PHRASE_LEN		6

extern int errno;

typedef struct 
{
  char *my_name;                 /* My name for logging and such */
  int run_as_daemon;             /* Run as a daemon? */
  char  *config_file;            /* configuration file */     
  char **accepted_credential_dns;/* List of creds that can be stored */
  char **authorized_retriever_dns;/* List of DNs we'll delegate to */
  char **default_retriever_dns;/* List of DNs we'll delegate to */
  char **authorized_renewer_dns; /* List of DNs that can renew creds */
  char **default_renewer_dns; /* List of DNs that can renew creds */
} myproxy_server_context_t;


/**********************************************************************
 *
 * Routines from myproxy_server_config.c
 *
 */

/*
 * myproxy_server_config_read()
 *
 * Read the configuration file as indicated in the context, parse
 * it and store the results in the context.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
int myproxy_server_config_read(myproxy_server_context_t *context);

/*
 * myproxy_server_check_cred()
 *
 * Check to see if the given client is authorized to store credentials
 * with the server based on the previously read context.
 *
 * Returns 1 if the client is authorized, 0 if unauthorized,
 * -1 on error, setting verror.
 */
int myproxy_server_check_cred(myproxy_server_context_t *context,
			      const char *client_name);
/*
 * myproxy_server_check_retriever()
 *
 * Check to see if the given client is authorized to retrieve
 * credentials stored with the server based on the previously read
 * context.
 *
 * Returns 1 if the client is authorized, 0 if unauthorized,
 * -1 on error, setting verror.
 */
int myproxy_server_check_retriever(myproxy_server_context_t *context,
				   const char *service_name);

/*
 * myproxy_server_check_renewer()
 *
 * Check to see if the given client is authorized to renew
 * existing credentials based on the previously read context.
 *
 * Returns 1 if the client is authorized, 0 if unauthorized,
 * -1 on error, setting verror.
 */
int myproxy_server_check_renewer(myproxy_server_context_t *context,
				 const char *service_name);



#endif /* !__MYPROXY_SERVER_H */
