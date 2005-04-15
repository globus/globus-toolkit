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
 * @file export_name.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "globus_i_gsi_gss_utils.h"
#include "gssapi_openssl.h"
#include <string.h>

/**
 * @name Export Name
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Produces a mechanism-independent exported name object.
 * See section 3.2 of RFC 2743.
 */
OM_uint32 
GSS_CALLCONV gss_export_name(
    OM_uint32 *                         minor_status,
    const gss_name_t                    input_name_P,
    gss_buffer_t                        exported_name)
{
    const gss_name_desc *               input_name = 
		                        (gss_name_desc *) input_name_P;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    char *                              oneline_name = NULL;
    char *                              ename;
    int                                 i, oneline_name_len;
    static char *                       _function_name_ = 
        "gss_export_name";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    if (!(input_name) || !(input_name->x509n) || !(exported_name)) {
        
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("The input name passed to: %s is not valid", _function_name_));
        goto exit;
    }

    oneline_name = X509_NAME_oneline(input_name->x509n, NULL, 0);
    if(oneline_name == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            ("Couldn't get the subject name of the gss_name_t"));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    oneline_name_len = strlen(oneline_name);

    exported_name->length = oneline_name_len + 10 +
        gss_mech_globus_gssapi_openssl->length;
    exported_name->value = ename = malloc(exported_name->length);

    /* token identifier */
    i=0;
    ename[i++] = 0x04;
    ename[i++] = 0x01;

    /* mechanism OID (in DER format) length (ID + length + content) */
    ename[i++] = (gss_mech_globus_gssapi_openssl->length+2) >> 8;
    ename[i++] = (gss_mech_globus_gssapi_openssl->length+2) & 0xff;

    /* mechanism OID in DER format */
    ename[i++] = 0x06; /* Identifier octet (6=OID) */
    ename[i++] = gss_mech_globus_gssapi_openssl->length & 0xff; /* length */
    memcpy(&(ename[i]),
           gss_mech_globus_gssapi_openssl->elements,
           gss_mech_globus_gssapi_openssl->length);
    i += gss_mech_globus_gssapi_openssl->length;

    /* length of exported name */
    ename[i++] = oneline_name_len >> 24;
    ename[i++] = oneline_name_len >> 16;
    ename[i++] = oneline_name_len >> 8;
    ename[i++] = oneline_name_len & 0xff;

    /* exported name */
    memcpy(&(ename[i]), oneline_name, oneline_name_len);

    OPENSSL_free(oneline_name);

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* gss_export_name */
/* @} */
