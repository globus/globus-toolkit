
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_jobmanager.c
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
#include "globus_callout.h"
#include "version.h"
#include <stdlib.h>
#include "openssl/crypto.h"
#include "openssl/x509.h"


static
globus_bool_t
globus_l_gram_callout_authorize_self(
    gss_ctx_id_t                        context);

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
    char *                              action;
    globus_rsl_t *                      rsl;
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    STACK_OF(X509)                      cert_chain;
    globus_object_t *                   error = NULL;
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
    action = va_arg(ap, char *);

    dump_file = fopen("authz_callout.txt","w");

    fprintf(dump_file, "Job ID: %s\nAction: %s\n",
            job_id ? job_id : "(null)",
            action ? action : "(null)");

    major_status = gss_inquire_sec_context_by_oid(
        &minor_status,
        job_initiator_ctx,
        &cert_chain_oid,
        &cert_chain_buffers);

    if(GSS_ERROR(major_status))
    {
        /* TODO: Need to define standard errors for authz callback */
        error = globus_error_construct_error(
            GLOBUS_CALLOUT_MODULE,
            NULL,
            GLOBUS_CALLOUT_ERROR_CALLOUT_ERROR,
            "%s: %s: %s",
            __FILE__, "globus_gram_callout", "Authorization failed");
        result = globus_error_put(error);
        error = NULL;
        goto exit;
    }

    for(i = 0; i < cert_chain_buffers->count; i++)
    {
        tmp_ptr = cert_chain_buffers->elements[i].value;
        cert = d2i_X509(NULL, &tmp_ptr,
                        cert_chain_buffers->elements[i].length);
        if(cert == NULL)
        {
            /* TODO: Need to define standard errors for authz callback */
            error = globus_error_construct_error(
                GLOBUS_CALLOUT_MODULE,
                NULL,
                GLOBUS_CALLOUT_ERROR_CALLOUT_ERROR,
                "%s: %s: %s",
                __FILE__, "globus_gram_callout", "Authorization failed");
            result = globus_error_put(error);
            error = NULL;
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
        if(globus_l_gram_callout_authorize_self(requester_ctx)
           != GLOBUS_TRUE)
        {
            /* TODO: Need to define standard errors for authz callback */
            error = globus_error_construct_error(
                GLOBUS_CALLOUT_MODULE,
                NULL,
                GLOBUS_CALLOUT_ERROR_CALLOUT_ERROR,
                "%s: %s: %s",
                __FILE__, "globus_gram_callout", "Authorization failed");
            result = globus_error_put(error);
            error = NULL;
            goto exit;
        }
    }

    
 exit:
    return result;
}
/* @} */


static
globus_bool_t
globus_l_gram_callout_authorize_self(
    gss_ctx_id_t                        context)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_name_t                          source_name;
    gss_name_t                          target_name;
    int                                 equal;
    globus_bool_t                       result = GLOBUS_FALSE;
    
    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       &source_name,
                                       &target_name,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL);
    if(GSS_ERROR(major_status))
    {
        goto exit;
    }

    major_status = gss_compare_name(&minor_status,
                                    source_name,
                                    target_name,
                                    &equal);
    if(GSS_ERROR(major_status))
    {
        goto free_names;
    }

    if(equal)
    {
        result = GLOBUS_TRUE;
    }
    
 free_names:
    gss_release_name(&minor_status,
                     &source_name);
    gss_release_name(&minor_status,
                     &target_name);
 exit:

    return result;    
}


