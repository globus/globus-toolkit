/*
 * myproxy_server.h
 *
 * Myproxy server header file
 */
#ifndef __MYPROXY_SERVER_H
#define __MYPROXY_SERVER_H

/* Borrowed from globus_gatekeeper.c */
static char tmpbuf[1024];
#define message2(a,b) {sprintf(tmpbuf, a,b); message(tmpbuf);}
#define message3(a,b,c) {sprintf(tmpbuf, a,b,c); message(tmpbuf);}
#define message4(a,b,c,d) {sprintf(tmpbuf, a,b,c,d); message(tmpbuf);}
#define failure2(a,b) {sprintf(tmpbuf, a,b); failure(tmpbuf);}
#define failure3(a,b,c) {sprintf(tmpbuf, a,b,c); failure(tmpbuf);}
#define failure4(a,b,c,d) {sprintf(tmpbuf, a,b,c,d); failure(tmpbuf);} 

extern int errno;

typedef struct 
{
  char *my_name;                 /* My name for logging and such */
  int run_as_daemon;             /* Run as a daemon? */
  char  *config_file;            /* configuration file */     
  char **authorized_client_dns;  /* List of clients that can be serviced */      
  char **authorized_service_dns; /* List of services will will delegate to */
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
 * myproxy_server_check_client()
 *
 * Check to see if the given client is authorized to store credentials
 * with the server based on the previously read context.
 *
 * Returns 1 if the client is authorized, 0 if unauthorized,
 * -1 on error, setting verror.
 */
int myproxy_server_check_client(myproxy_server_context_t *context,
				const char *client_name);
/*
 * myproxy_server_check_service()
 *
 * Check to see if the given service is authorized to retrieve
 * credentials stored with the server based on the previously read
 * context.
 *
 * Returns 1 if the client is authorized, 0 if unauthorized,
 * -1 on error, setting verror.
 */
int myproxy_server_check_service(myproxy_server_context_t *context,
				 const char *service_name);

#endif /* !__MYPROXY_SERVER_H */
