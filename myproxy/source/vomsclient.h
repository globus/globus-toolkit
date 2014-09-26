
#ifndef __VOMSCLIENT_H_
#define __VOMSCLIENT_H_

#include <voms_apic.h>
#include <newformat.h>


#define DEFAULT_VOMS_DIR "/etc/grid-security/vomsdir"
#define DEFAULT_CACERT_DIR "/etc/grid-security/certificates"


typedef struct voms_command_s
{
    char *vo;       /* VO name */
    char *command;  /* Command to send VOMS Server */
                    /* example "G/voname[,Rrole-name[,...]]" */
    struct voms_command_s *next;
} voms_command_t;


void get_voms_proxy(myproxy_socket_attrs_t *attrs,
                    myproxy_creds_t *creds,
                    myproxy_request_t *request,
                    myproxy_response_t *response,
                    myproxy_server_context_t *config);

/*
 * voms_init_delegation()
 *
 * Delegates a voms proxy based on the credentials found in file
 * location delegfile good for lifetime_seconds
 *
 * returns 0 on success, -1 on error
 */
int voms_init_delegation(myproxy_socket_attrs_t *attrs,
                         const char *delegfile,
                         const int lifetime_seconds,
                         char *passphrase,
                         char *voname, char *vomses, char *voms_userconf);

int voms_contact(SSL_CREDENTIALS *creds, int lifetime, 
                 char *voname, char *vomses, char *voms_userconf,
                 unsigned char **aclist, int *aclist_length);

#endif

