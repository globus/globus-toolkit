#include <gssapi.h>
#include <globus_gss_assist.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#define accept_message "ACCEPTOR WRAP MESSAGE"

int main(int argc, char * argv[])
{
    gss_cred_id_t                       accept_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t                       delegated_init_cred 
        = GSS_C_NO_CREDENTIAL;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 token_status;
    gss_ctx_id_t                        accept_context = GSS_C_NO_CONTEXT;
    OM_uint32                           ret_flags = 0;
    int                                 sock, connect_sock;
    FILE *                              infd;
    FILE *                              outfd;
    char *                              print_buffer = NULL;
    char *                              recv_buffer = NULL;
    int                                 buffer_length;
    struct sockaddr_in                  sockaddr;
    int                                 length;
    char *                              init_name;
    char *                              verbose_env = NULL;
    
    verbose_env = getenv("GSS_ASSIST_VERBOSE_TEST");

    setbuf(stdout, NULL);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("opening stream socket");
        exit(1);
    }

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_port = 0;
    if(bind(sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)))
    {
        perror("binding stream socket");
        exit(1);
    }
    
    length = sizeof(sockaddr);
    if(getsockname(sock, (struct sockaddr *) &sockaddr, &length))
    {
        perror("getting socket name");
        exit(1);
    }

    fprintf(stdout, "Socket has port #%d\n", ntohs(sockaddr.sin_port));

    /* Start accepting connection */
    listen(sock, 1);
    connect_sock = accept(sock, 0, 0);
    if(connect_sock == -1) 
    {
        perror("accept");
        exit(1);
    }

    if(close(sock) < 0)
    {
        perror("Couldn't close listening socket");
        exit(1);
    }

    infd = fdopen(dup(connect_sock), "r");
    setbuf(infd, NULL);

    outfd = fdopen(dup(connect_sock), "w");
    setbuf(outfd, NULL);
    
    close(connect_sock);

    /* ACCEPTOR PROCESS */
    major_status = globus_gss_assist_acquire_cred(&minor_status,
                                                  GSS_C_ACCEPT,
                                                  &accept_cred);
    
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't acquire acceptor's credentials",
            major_status,
            minor_status,
            0);
        exit(1);
    }

    major_status = globus_gss_assist_accept_sec_context(
        &minor_status,
        &accept_context,
        accept_cred,
        &init_name,
        &ret_flags,
        NULL,
        &token_status,
        &delegated_init_cred,
        globus_gss_assist_token_get_fd,
        (void *) (infd),
        globus_gss_assist_token_send_fd,
        (void *) (outfd));
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't authenticate as acceptor\n",
            major_status,
            minor_status,
            token_status);
        exit(1);
    }

    if(verbose_env)
    {
        fprintf(stdout, 
                "ACCEPTOR: "__FILE__":%d"
                ": Acceptor successfully created context"
                " for initiator: %s\n", __LINE__, init_name);
    }

    /*
    
    major_status = globus_gss_assist_get_unwrap(
        &minor_status,
        accept_context,
        &recv_buffer,
        &buffer_length,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (infd),
        stdout);
    if(GSS_ERROR(major_status))
    {
        fprintf(stdout, "ACCEPTOR ERROR\n");
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't get encrypted message from initiator\n",
            major_status,
            minor_status,
            token_status);
        fprintf(stdout, "ACCEPTOR ERROR FINISHED\n");
        exit(1);
    }

    print_buffer = malloc(buffer_length + 1);
    globus_libc_snprintf(print_buffer, buffer_length + 1, "%s", recv_buffer);

    if(verbose_env)
    {
        fprintf(stdout,
                "ACCEPTOR: "__FILE__":%d"
                ": received: %s\n", __LINE__, print_buffer);
    }

    free(print_buffer);
    free(recv_buffer);

    */
    
    major_status = globus_gss_assist_get_unwrap(
        &minor_status,
        accept_context,
        &recv_buffer,
        &buffer_length,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (infd),
        stdout);
    if(GSS_ERROR(major_status))
    {
        fprintf(stdout, "ACCEPTOR ERROR\n");
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't get encrypted message from initiator\n",
            major_status,
            minor_status,
            token_status);
        fprintf(stdout, "ACCEPTOR ERROR FINISHED\n");
        exit(1);
    }

    print_buffer = malloc(buffer_length + 1);
    globus_libc_snprintf(print_buffer, buffer_length + 1, "%s", recv_buffer);

    if(verbose_env)
    {
        fprintf(stdout,
                "ACCEPTOR: "__FILE__":%d"
                ": received: %s\n", __LINE__, print_buffer);
    }

    free(print_buffer);
    free(recv_buffer);

    major_status = globus_gss_assist_wrap_send(
        &minor_status,
        accept_context,
        accept_message,
        sizeof(accept_message),
        &token_status,
        globus_gss_assist_token_send_fd,
        (void *) (outfd),
        stdout);
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't encrypt and send message\n",
            major_status,
            minor_status,
            token_status);
        exit(1);
    }

    major_status = globus_gss_assist_get_unwrap(
        &minor_status,
        accept_context,
        &recv_buffer,
        &buffer_length,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (infd),
        stdout);
    if(GSS_ERROR(major_status))
    {
        fprintf(stdout, "ACCEPTOR ERROR\n");
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't get encrypted message from initiator\n",
            major_status,
            minor_status,
            token_status);
        fprintf(stdout, "ACCEPTOR ERROR FINISHED\n");
        exit(1);
    }

    print_buffer = malloc(buffer_length + 1);
    globus_libc_snprintf(print_buffer, buffer_length + 1, "%s", recv_buffer);

    if(verbose_env)
    {
        fprintf(stdout,
                "ACCEPTOR: "__FILE__":%d"
                ": received: %s\n", __LINE__, print_buffer);
    }

    free(print_buffer);
    free(recv_buffer);

    major_status = globus_gss_assist_wrap_send(
        &minor_status,
        accept_context,
        accept_message,
        sizeof(accept_message),
        &token_status,
        globus_gss_assist_token_send_fd,
        (void *) (outfd),
        stdout);
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stdout,
            "ACCEPTOR: Couldn't encrypt and send message\n",
            major_status,
            minor_status,
            token_status);
        exit(1);
    }
                
    major_status = gss_delete_sec_context(&minor_status,
                                          &accept_context,
                                          GSS_C_NO_BUFFER);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(
            stdout,
            "INITIATOR: Couldn't delete security context\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }
            
    gss_release_cred(&minor_status,
                     &accept_cred);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(
            stdout,
            "INITIATOR: Couldn't delete security context\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }

    if(fclose(infd) == EOF)
    {
        perror("closing stream socket");
        exit(1);
    }

    if(fclose(outfd) == EOF)
    {
        perror("closing stream socket");
        exit(1);
    }

    exit(0);
}
