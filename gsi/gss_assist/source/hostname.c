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
    struct hostent *                    hp;
    struct hostent                      host_entry;
    char                                buffer[BUFFER_SIZE];
    int                                 herrno;
    char                                realhostname[128 + 5] = "host@";
    gss_buffer_desc                     name_tok;
    globus_bool_t                       is_loopback = GLOBUS_FALSE;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 i;
    
    hp = globus_libc_gethostbyname_r(
        hostname,
        &host_entry,
        buffer,
        BUFFER_SIZE,
        &herrno);
    
    if(hp == GLOBUS_NULL)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                GLOBUS_GSI_GSS_ASSIST_MODULE,
                herrno,
                GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                "gethostbyname failed"));
        goto error_exit;
    }

    if(host_entry.h_addr_list[0] != NULL)
    {
        char                            tmp_hostname[6];
        memcpy(tmp_hostname, host_entry.h_addr_list[0], host_entry.h_length);
        
        hp = globus_libc_gethostbyaddr_r(
            tmp_hostname,
            host_entry.h_length,
            host_entry.h_addrtype,
            &host_entry,
            buffer,
            BUFFER_SIZE,
            &herrno);

        if(hp == GLOBUS_NULL)
        {            
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_GSS_ASSIST_MODULE,
                    herrno,
                    GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                    __FILE__,
                    _function_name_,
                    __LINE__,
                    "gethostbyaddr failed"));
            goto error_exit;
        }
    }

    /* 
     * For connections to localhost, check for certificate
     * matching our real hostname, not "localhost"
     */

    switch(host_entry.h_addrtype)
    {
      case AF_INET:
        {
            struct in_addr address;
            
            memcpy(&address.s_addr,
                   host_entry.h_addr,
                   sizeof(address.s_addr));

            if(ntohl(address.s_addr) == INADDR_LOOPBACK)
            {
                is_loopback = GLOBUS_TRUE;
            }
        }
        break;
      case AF_INET6:
        {
            struct in6_addr address;

            memcpy(&address,
                   host_entry.h_addr,
                   sizeof(address));
            
            if(IN6_IS_ADDR_LOOPBACK(&address))
            {
                is_loopback = GLOBUS_TRUE;
            }
        }
        break;
      default:
        globus_assert(0 &&
                      "Unknown family in globus_libc_addr_is_loopback");
        break;
    }
    
    if(is_loopback == GLOBUS_TRUE)
    {
        globus_libc_gethostname(&realhostname[5], sizeof(realhostname) - 5);
    }
    else
    {
        strncpy(&realhostname[5], host_entry.h_name, 
                sizeof(realhostname) - 5);
    }

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
