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


/* In myproxy_server_config.c */
int mproxy_server_config_read(myproxy_server_context_t *context);


#endif /* !__MYPROXY_SERVER_H */
