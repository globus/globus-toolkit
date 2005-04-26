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


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_jobmanager_callout.c
 * Globus GRAM Jobmanager Callout Example
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#include "globus_common.h"
#include "gssapi.h"
#include "globus_rsl.h"
#include "globus_rsl_assist.h"
#include "globus_gram_protocol.h"
#include "globus_gram_jobmanager_callout_error.h"
#include "version.h"
#include <stdlib.h>
#include "openssl/crypto.h"
#include "openssl/x509.h"

#endif


/**
 * @mainpage Globus GRAM Jobmanager Callout Example
 */


/**
 * @defgroup globus_gram_callout_example Globus GRAM Jobmanager Callout Example
 */


/**
 * Example GRAM Authorization Callout Function
 * @ingroup globus_gram_callout_example
 */
/* @{ */
/**
 * Example GRAM Authorization Callout Function
 *
 * This function exemplifies the GRAM authorization callout usage by writing
 * some of its arguments to the file "authz_callout.txt".
 *
 * @param ap
 *        This function, like all functions using the Globus Callout API, is 
 *        passed parameter though the variable argument list facility. The
 *        actual arguments that are passed are:
 *
 *        - The GSS Security context established during job startup
 *        - The GSS Security context established for the current operation.
 *        - The job id string
 *        - The parsed RSL used for job startup
 *        - A string describing the current operation. This string is currently
 *          limited to the values: "start", "cancel", "register", "unregister",
 *          "signal", "status" and "renew"
 *
 * @return
 *        GLOBUS_SUCCESS upon success
 *        A globus result structure upon failure (needs to be defined better)
 */
globus_result_t
globus_gram_callout(
    va_list                             ap)
{
    gss_ctx_id_t                        job_initiator_ctx;
    gss_ctx_id_t                        requester_ctx;
    char *                              job_id;
    char *                              action = NULL;
    char *                              rest;
    globus_rsl_t *                      rsl;
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    STACK_OF(X509)                      cert_chain;
    unsigned char *                     tmp_ptr;
    gss_OID_desc                        cert_chain_oid =
        {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 
    gss_buffer_set_t                    cert_chain_buffers;
    X509 *                              cert;
    FILE *                              dump_file;
    int                                 i;

    job_initiator_ctx = va_arg(ap, gss_ctx_id_t);
    requester_ctx = va_arg(ap, gss_ctx_id_t);
    job_id = va_arg(ap, char *);
    rsl = va_arg(ap, globus_rsl_t *);
    action = strdup(va_arg(ap, char *));
    
    rest = strchr(action,' ');
    if (rest)
	*rest++ = '\0';

    
    dump_file = fopen("authz_callout.txt","w");

    fprintf(dump_file, "Job ID: %s\nAction: %s\n",
            job_id ? job_id : "(null)",
            action ? action : "(null)");

    major_status = gss_inquire_sec_context_by_oid(
        &minor_status,
        requester_ctx,
        &cert_chain_oid,
        &cert_chain_buffers);

    if(GSS_ERROR(major_status))
    {
        result = minor_status;
        GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR(
            result,
            GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_SYSTEM_ERROR,
            ("gss_inquire_sec_context_by_oid failed"));
        goto exit;
    }

    for(i = 0; i < cert_chain_buffers->count; i++)
    {
        tmp_ptr = cert_chain_buffers->elements[i].value;
        cert = d2i_X509(NULL, &tmp_ptr,
                        cert_chain_buffers->elements[i].length);
        if(cert == NULL)
        {
            GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR(
                result,
                GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_SYSTEM_ERROR,
                ("Failed to construct cert chain"));
            gss_release_buffer_set(&minor_status,
                                   &cert_chain_buffers);
            goto exit;
        }
        
        X509_print_fp(dump_file,
                      cert);
        X509_free(cert);
    }

    gss_release_buffer_set(&minor_status,
                           &cert_chain_buffers);

    fclose(dump_file);
    if(!(strcmp(action,"cancel") &&
         strcmp(action,"signal") &&
         strcmp(action,"status") &&
         strcmp(action,"register") &&
         strcmp(action,"renew") &&
         strcmp(action,"unregister")))
    {
        if(globus_gram_protocol_authorize_self(requester_ctx)
           != GLOBUS_TRUE)
        {
            GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR(
                result,
                GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED,
                ("Client is not authorized"));
            goto exit;
        }
    }

    
 exit:
    if(action)
    { 
        free(action);
    }
    
    return result;
}
/* @} */



