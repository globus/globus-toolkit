/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_common.h"
#include "globus_gss_assist.h"

static
globus_result_t
globus_l_hostname_lookup_hostname_to_address_string(
    char *                              hostname,
    globus_list_t **                    out_list)                              
{
    globus_addrinfo_t                   hints;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t *                 ai;
    globus_result_t                     result;
    globus_list_t *                     list = NULL;
    
    memset(&hints, 0, sizeof(globus_addrinfo_t));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    result = globus_libc_getaddrinfo(hostname, NULL, &hints, &addrinfo);
    if(result != GLOBUS_SUCCESS || addrinfo == NULL || 
        addrinfo->ai_addr == NULL)
    {
        goto error_exit;
    }
    ai = addrinfo;
    while(ai != NULL)
    {
        char                            buffer[NI_MAXHOST];
        result = globus_libc_getnameinfo(
            (const globus_sockaddr_t *) ai->ai_addr,
            buffer,
            sizeof(buffer),
            NULL,
            0,
            GLOBUS_NI_NUMERICHOST);
        if(result != GLOBUS_SUCCESS)
        {
            globus_libc_freeaddrinfo(addrinfo);
            globus_list_destroy_all(list, free);
            goto error_exit;
        }
        
        globus_list_insert(&list, globus_libc_strdup(buffer));
        ai = ai->ai_next;
    }      
    globus_libc_freeaddrinfo(addrinfo);    
    
    *out_list = list;
    return GLOBUS_SUCCESS;
    
error_exit:
    return result;
}


int
main(
    int                                 argc,
    char **                             argv)
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);

    char                                realhostname[NI_MAXHOST];
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *                              hostname;
    gss_name_t                          gssname;
    char *                              numeric;
    OM_uint32                           min_stat;
    OM_uint32                           maj_stat;
    gss_buffer_desc                     subject_buf = GSS_C_EMPTY_BUFFER;
    gss_OID                             mech_type;
    globus_list_t *                     list = NULL;
    globus_list_t *                     list_p = NULL;
    char *                              hostenv;
    
    if(argc < 2)
    {
        hostname = globus_malloc(1024);
        globus_libc_gethostname(hostname, 1024);
    }
    else if(argc == 2 && *argv[1] != '-')
    {
        hostname = globus_libc_strdup(argv[1]);
    }
    else
    {
        printf("Usage: %s [hostname or numeric address]\n", argv[0]);
        return 0;
    }

    if((hostenv = globus_libc_getenv("GLOBUS_HOSTNAME")) != NULL)
    {
        printf("GLOBUS_HOSTNAME=%s\n", hostenv);
    }
    printf("Resolving address (%s)...\n", hostname);        

    result = globus_l_hostname_lookup_hostname_to_address_string(
        hostname, &list);
    if(result != GLOBUS_SUCCESS)
    {
        char *                         msg;

        msg = globus_error_print_friendly(globus_error_peek(result));
        printf("ERROR: %s\n", msg);
        globus_free(msg);
        goto error_exit;
    }    
    
    globus_free(hostname);

    list_p = list;
    while(!globus_list_empty(list_p))
    {
        numeric = (char *) globus_list_first(list_p);
        list_p = globus_list_rest(list_p);
        printf("-------------------------------\n");
        printf("Numeric address: %s\n", numeric);

        globus_gss_assist_authorization_host_name(numeric, &gssname);
        
        maj_stat = gss_display_name(
            &min_stat,
            gssname,
            &subject_buf,
            &mech_type);
        gss_release_name(&min_stat, &gssname);
        if(maj_stat != GSS_S_COMPLETE)
        {
            gss_release_buffer(&min_stat, &subject_buf);
            goto error_exit;
        }
        strncpy(realhostname, subject_buf.value, subject_buf.length);
        realhostname[subject_buf.length] = 0;
        gss_release_buffer(&min_stat, &subject_buf);
        
        printf("Expected DN suffix: %s\n", realhostname);        
    }   
    globus_list_destroy_all(list, free);
    
    printf("-------------------------------\n");
    
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return 0;

error_exit:
    globus_free(hostname);
    return 1;
}
