#include <gssapi.h>
#include <globus_gss_assist.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#define init_message "INITIATOR WRAP MESSAGE"

int main(int argc, char * argv[])
{
    gss_cred_id_t                       init_cred = GSS_C_NO_CREDENTIAL;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 token_status;
    gss_ctx_id_t                        init_context = GSS_C_NO_CONTEXT;
    OM_uint32                           ret_flags;
    int                                 sock;
    FILE *                              stre;
    char *                              print_buffer = NULL;
    char *                              recv_buffer = NULL;
    int                                 buffer_length;
    struct sockaddr_in                  sockaddr;
    struct hostent *                    hostname;
    char *                              verbose_env = NULL;

    verbose_env = getenv("GSS_ASSIST_VERBOSE_TEST");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("opening stream socket");
        exit(1);
    }
    
    sockaddr.sin_family = AF_INET;

    hostname = gethostbyname(argv[1]);
    if(hostname == 0)
    {
        fprintf(stderr, "%s: uknown host", argv[1]);
        exit(2);
    }

    bcopy(hostname->h_addr, &sockaddr.sin_addr, hostname->h_length);
    sockaddr.sin_port = htons(atoi(argv[2]));

    if(connect(sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
    {
        perror("connecting stream socket");
        exit(1);
    }

    stre = fdopen(sock, "r+");
    setbuf(stre, NULL);

    /* INITIATOR PROCESS */
    
    major_status = globus_gss_assist_acquire_cred(&minor_status,
                                                  GSS_C_INITIATE,
                                                  &init_cred);
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't acquire initiator's credentials",
            major_status,
            minor_status,
            0);
        exit(1);
    }

    major_status = globus_gss_assist_init_sec_context(
        &minor_status,
        init_cred,
        &init_context,
        NULL,
        GSS_C_MUTUAL_FLAG,
        &ret_flags,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (stre),
        globus_gss_assist_token_send_fd,
        (void *) (stre));
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't authenticate as initiator\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }
    
    if(verbose_env)
    {
        fprintf(stdout, 
                "INITIATOR: "__FILE__":%d"
                ": Initiator successfully created context\n", __LINE__);
    }

    major_status = globus_gss_assist_wrap_send(
        &minor_status,
        init_context,
        init_message,
        sizeof(init_message),
        &token_status,
        globus_gss_assist_token_send_fd,
        (void *) (stre),
        stderr);
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stderr,
            "INITATOR: Couldn't wrap and send message\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }
    
    major_status = globus_gss_assist_get_unwrap(
        &minor_status,
        init_context,
        &recv_buffer,
        &buffer_length,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (stre),
        stderr);
    if(GSS_ERROR(major_status))
    {
        fprintf(stderr, "INITIATOR ERROR\n");
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't get encrypted message from initiator\n",
            major_status,
            minor_status,
            0);
        fprintf(stderr, "INITIATOR ERROR FINISHED\n");
        exit(1);
    }

    print_buffer = malloc(buffer_length + 1);
    snprintf(print_buffer, buffer_length + 1, "%s", recv_buffer);
    
    if(verbose_env)
    {
        fprintf(stdout,
                "INITIATOR: "__FILE__":%d"
                ": received: %s\n", __LINE__, print_buffer);
    }

    free(print_buffer);
    free(recv_buffer);

    major_status = globus_gss_assist_wrap_send(
        &minor_status,
        init_context,
        init_message,
        sizeof(init_message),
        &token_status,
        globus_gss_assist_token_send_fd,
        (void *) (stre),
        stderr);
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
            stderr,
            "INITATOR: Couldn't wrap and send message\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }

    major_status = globus_gss_assist_get_unwrap(
        &minor_status,
        init_context,
        &recv_buffer,
        &buffer_length,
        &token_status,
        globus_gss_assist_token_get_fd,
        (void *) (stre),
        stderr);
    if(GSS_ERROR(major_status))
    {
        fprintf(stderr, "INITIATOR ERROR\n");
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't get encrypted message from initiator\n",
            major_status,
            minor_status,
            0);
        fprintf(stderr, "INITIATOR ERROR FINISHED\n");
        exit(1);
    }
    
    print_buffer = malloc(buffer_length + 1);
    snprintf(print_buffer, buffer_length + 1, "%s", recv_buffer);
    
    if(verbose_env)
    {
        fprintf(stdout,
                "INITIATOR: "__FILE__":%d"
                ": received: %s\n", __LINE__, print_buffer);
    }

    free(print_buffer);
    free(recv_buffer);

    major_status = gss_delete_sec_context(&minor_status,
                                          &init_context,
                                          GSS_C_NO_BUFFER);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't delete security context\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }
            
    gss_release_cred(&minor_status,
                     &init_cred);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(
            stderr,
            "INITIATOR: Couldn't delete security context\n",
            major_status,
            minor_status,
            0);
        exit(1);
    }

    if(fclose(stre) == EOF)
    {
        perror("closing stream socket");
        exit(1);
    }
    
    exit(0);
}
