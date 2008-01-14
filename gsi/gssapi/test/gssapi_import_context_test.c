/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "gssapi.h"
#include "globus_gss_assist.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    OM_uint32                           init_maj_stat;
    OM_uint32                           accept_maj_stat;
    OM_uint32                           min_stat;
    OM_uint32                           ret_flags;
    OM_uint32                           req_flags;
    gss_buffer_desc                     send_tok;
    gss_buffer_desc                     recv_tok;
    gss_buffer_desc *                   token_ptr;
    gss_buffer_desc                     init_buffer;
    gss_buffer_desc                     accept_buffer;
    gss_OID				name_type;
    gss_OID                             mech_type;
    gss_name_t                          target_name;
    gss_name_t                          source_name;
    gss_ctx_id_t  			init_context;
    gss_ctx_id_t  			accept_context;
    gss_ctx_id_t  			del_init_context;
    gss_ctx_id_t  			del_accept_context;
    gss_cred_id_t                       delegated_cred;
    char *                              error_str;

    /* Initialize variables */
    
    token_ptr = GSS_C_NO_BUFFER;
    init_context = GSS_C_NO_CONTEXT;
    accept_context = GSS_C_NO_CONTEXT;
    del_init_context = GSS_C_NO_CONTEXT;
    del_accept_context = GSS_C_NO_CONTEXT;
    name_type = GSS_C_NT_USER_NAME;
    delegated_cred = GSS_C_NO_CREDENTIAL;
    accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    ret_flags = 0;
    req_flags = GSS_C_CONF_FLAG;

    /* set up the first security context */
    init_maj_stat = gss_init_sec_context(&min_stat,
                                         GSS_C_NO_CREDENTIAL,
                                         &init_context,
                                         GSS_C_NO_NAME,
                                         GSS_C_NULL_OID,
                                         req_flags,
                                         0,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         token_ptr,
                                         NULL,
                                         &send_tok,
                                         NULL,
                                         NULL);


    if(init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    while(1)
    {
        
        accept_maj_stat=gss_accept_sec_context(&min_stat,
                                               &accept_context,
                                               GSS_C_NO_CREDENTIAL,
                                               &send_tok, 
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               &source_name,
                                               &mech_type,
                                               &recv_tok,
                                               &ret_flags,
                                               /* ignore time_rec */
                                               0, 
                                               GSS_C_NO_CREDENTIAL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            exit(1);
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        init_maj_stat = gss_init_sec_context(&min_stat,
                                             GSS_C_NO_CREDENTIAL,
                                             &init_context,
                                             GSS_C_NO_NAME,
                                             GSS_C_NULL_OID,
                                             req_flags,
                                             0,
                                             GSS_C_NO_CHANNEL_BINDINGS,
                                             &recv_tok,
                                             NULL,
                                             &send_tok,
                                             NULL,
                                             NULL);
        
        
        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            exit(1);
        }
    }
    
    /* Wrap a token with the initiator context */
    send_tok.value = "hello";
    send_tok.length = 6;
    init_maj_stat = gss_wrap(&min_stat, init_context, 0, 0, &send_tok, NULL, 
                             &recv_tok);
    if (init_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                init_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    /* unwrap the token with the acceptor context */
    accept_maj_stat = gss_unwrap(&min_stat, accept_context, &recv_tok, &send_tok, 0, NULL);
    if (accept_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                accept_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    if (strcmp("hello", send_tok.value) != 0)
    {
        printf("Hello garbled\n");
        exit(1);
    }
    /* Export initiator context */
    init_maj_stat = gss_export_sec_context(
            &min_stat, &init_context,
            &init_buffer);
    if (init_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                init_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    /* Export acceptor context */
    accept_maj_stat = gss_export_sec_context(
            &min_stat, &accept_context,
            &accept_buffer);
    if (accept_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                accept_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    /* Import the init context */
    init_maj_stat = gss_import_sec_context(&min_stat,
            &init_buffer, &init_context);
    if (init_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                init_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    /* Import the accept context */
    accept_maj_stat = gss_import_sec_context(&min_stat,
            &accept_buffer, &accept_context);
    if (accept_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                init_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    /* Wrap a token with the initiator context */
    send_tok.value = "hello";
    send_tok.length = 6;
    init_maj_stat = gss_wrap(&min_stat, init_context, 0, 0, &send_tok, NULL, 
                             &recv_tok);
    if (init_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                init_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    /* unwrap the token with the acceptor context */
    accept_maj_stat = gss_unwrap(&min_stat, accept_context, &recv_tok, &send_tok, 0, NULL);
    if (accept_maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str, NULL,
                accept_maj_stat, min_stat, 0);

        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    if (strcmp("hello", send_tok.value) != 0)
    {
        printf("Hello garbled in 2nd message\n");
        exit(1);
    }

    return 0;
}
