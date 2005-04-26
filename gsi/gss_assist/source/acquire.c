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
 * @file acquire.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include "gssapi.h"
#include <string.h>

static gss_OID_desc oids[] = {
   {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"},
   {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"},
   {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"},
   {6,  (void *)"\x2b\x06\x01\x05\x06\x02"},
   {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"},
   {6,  (void *)"\x2b\x06\x01\x05\x06\x03"},
   {6,  (void *)"\x2b\x06\x01\x05\x06\x04"},
};

static char * oid_names[] = {
 "GSS_C_NT_USER_NAME",
 "GSS_C_NT_MACHINE_UID_NAME",
 "GSS_C_NT_STRING_UID_NAME",
 "GSS_C_NT_HOSTBASED_SERVICE_X",
 "GSS_C_NT_HOSTBASED_SERVICE",
 "GSS_C_NT_ANONYMOUS",
 "GSS_C_NT_EXPORT_NAME",
  NULL};

/**
 * @name Acquire Credential
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * Called once at the start of the process, to 
 * obtain the credentials the process is running under. 
 * The 
 * 
 * @param minor_status
 *        pointer for return code 
 * @param cred_usage
 *        GSS_C_INITIATE, GSS_C_ACCEPT, or GSS_C_BOTH
 * @param output_cred_handle
 *        Pointer to the returned handle. 
 *        This needs to be passed to many gss routines. 
 *
 * @return
 *        GSS_S_COMPLETE on sucess
 *        Other GSS return codes 
 */
OM_uint32
globus_gss_assist_acquire_cred(
    OM_uint32 *		                minor_status,
    gss_cred_usage_t 	                cred_usage,
    gss_cred_id_t * 	                output_cred_handle)
{
    return (globus_gss_assist_acquire_cred_ext(
        minor_status,
        NULL, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
        cred_usage, output_cred_handle,
        NULL, NULL));
}
/* @} */

/**
 * @name Acquire Credential Extension
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * Called once at the start of the process, to 
 * obtain the credentials the process is running under. 
 * All the parameters of the gss_acquire_cred,
 * except the desired_name is a string of the form:
 * [type:]name. This will be imported with the type.
 *
 * @return 
 *         GSS_S_COMPLETE on sucess
 *         Other GSS return codes 
 *
 * @see globus_gsi_gss_acquire_cred
 */
OM_uint32
globus_gss_assist_acquire_cred_ext(
    OM_uint32 *		                minor_status,
    char *                              desired_name_char,
    OM_uint32                           time_req,
    const gss_OID_set                   desired_mechs,
    gss_cred_usage_t 	                cred_usage,
    gss_cred_id_t * 	                output_cred_handle,
    gss_OID_set *                       actual_mechs,
    OM_uint32 *                         time_rec)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status2;
    gss_name_t                          desired_name = GSS_C_NO_NAME;
    gss_OID                             desired_name_type = GSS_C_NO_OID;
    gss_buffer_desc                     tmp_buffer_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                        tmp_buffer      = &tmp_buffer_desc;
    char *                              cp, * qp;
    int                                 i, j;
    static char *                       _function_name_ =
        "globus_gss_assist_acquire_cred_ext";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;    

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
        3, (globus_i_gsi_gss_assist_debug_fstream,
            _GASL("gss_assist_acquire_cred_ext usage=%d desired_name=%s\n"),
            cred_usage, desired_name_char ? desired_name_char : "(NULL)"));

    if (desired_name_char) {
        qp = desired_name_char;
        cp = strchr(desired_name_char,':');
        if (cp) {
            j = cp - qp;
            for (i=0;oid_names[i];i++) {
                if ((j == strlen(oid_names[i])) && 
                    (!strncmp(desired_name_char,oid_names[i],j))) {
                    desired_name_type = &oids[i];
                    qp = cp + 1;
                    break;
                }
            }
        }

        tmp_buffer->value = qp;
        tmp_buffer->length = strlen(qp);

        major_status = gss_import_name(minor_status,
                                       tmp_buffer,
                                       desired_name_type,
                                       &desired_name);

        GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(3,
            (globus_i_gsi_gss_assist_debug_fstream, 
             _GASL("Imported name %s type:%p:i%d\n"), 
             (char *) tmp_buffer->value, 
             desired_name_type, i));
    }

    major_status = gss_acquire_cred(minor_status,
                                    desired_name, 
                                    time_req,	
                                    desired_mechs,
                                    cred_usage,
                                    output_cred_handle,
                                    actual_mechs,
                                    time_rec);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(3,
        (globus_i_gsi_gss_assist_debug_fstream, 
         _GASL("major=%8.8x minor=%8.8x\n"), 
         (unsigned int) major_status, 
         (unsigned int) *minor_status));

    if(GLOBUS_I_GSI_GSS_ASSIST_DEBUG(3))
    {
        globus_gss_assist_display_status(
            globus_i_gsi_gss_assist_debug_fstream, 
            "acquire", 
            major_status, 
            *minor_status, 
            0);
    }

    if (desired_name) {
        gss_release_name(&minor_status2, &desired_name); 
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return (major_status);
}
/* @} */
