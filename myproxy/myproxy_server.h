/*
 * myproxy_server.h
 *
 * Myproxy server header file
 */
#ifndef __MYPROXY_SERVER_H
#define __MYPROXY_SERVER_H

typedef struct 
{
  char  *config_file;            /* configuration file */     
  char **authorized_client_dns;  /* List of clients that can be serviced */      
  char **authorized_service_dns; /* List of services will will delegate to */
} myproxy_server_context_t;

#endif /* !__MYPROXY_SERVER_H */
