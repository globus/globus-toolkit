#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file hostname.c
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"

#define BUFFER_SIZE 8192
/**
 * Create a GSS Name structure from the given hostname. This function tries to
 * resolve the given host name string to the canonical DNS name for the host.
 *
 * @param hostname
 *        The host name to resolved and transform into a GSS Name
 * @param authorization_hostname
 *        The resulting GSS Name
 * 
 * @return GLOBUS_SUCCESS on successful completion, a error object otherwise
 */
globus_result_t
globus_gss_assist_authorization_host_name(
    char *                              hostname,
    gss_name_t *                        authorization_hostname)
{
    static char *                       _function_name_ =
        "globus_gss_assist_authorization_host_name";
    char                                realhostname[128 + 5] = "host@";
    gss_buffer_desc                     name_tok;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 i;    
    globus_addrinfo_t                   hints;
    globus_addrinfo_t *                 addrinfo;

    memset(&hints, 0, sizeof(globus_addrinfo_t));
    hints.ai_flags = GLOBUS_AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    result = globus_libc_getaddrinfo(hostname, NULL, &hints, &addrinfo);

    if(result != GLOBUS_SUCCESS ||
       addrinfo == NULL ||
       addrinfo->ai_canonname == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_CANONICALIZING_HOSTNAME);
        goto error_exit;
    }    

    /* 
     * For connections to localhost, check for certificate
     * matching our real hostname, not "localhost"
     */

    if(globus_libc_addr_is_loopback(addrinfo->ai_addr) == GLOBUS_TRUE)
    {
        globus_libc_gethostname(&realhostname[5], sizeof(realhostname) - 5);
    }
    else
    {
        strncpy(&realhostname[5], addrinfo->ai_canonname, 
                sizeof(realhostname) - 5);
    }

    globus_libc_freeaddrinfo(addrinfo);
    
    /*
     * To work around the GSI GSSAPI library being case sensitive
     * convert the hostname to lower case as noone seems to
     * request uppercase name certificates.
     */
	    
    for (i = 5; realhostname[i] && (i < sizeof(realhostname)); i++)
    {
        realhostname[i] = tolower(realhostname[i]);
    }
	    
    name_tok.value = realhostname;
    name_tok.length = strlen(realhostname) + 1;
    major_status = gss_import_name(&minor_status, 
                                   &name_tok, 
                                   GSS_C_NT_HOSTBASED_SERVICE, 
                                   authorization_hostname);

    if(GSS_ERROR(major_status))
    {
        result =  minor_status;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_GSSAPI_ERROR);
        goto error_exit;
    }

 error_exit:
    return result;
}
