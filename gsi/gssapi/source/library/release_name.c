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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file release_name.c
 * @author Sam Meder, Sam Lang
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * @name GSS Release Name
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Release the GSS Name
 *
 * @param minor_status
 *        The minor status result - this is a globus_result_t
 *        cast to a (OM_uint32 *).
 * @param name_P
 *        The gss name to be released
 * @return
 *        The major status - GSS_S_COMPLETE or GSS_S_FAILURE
 */
OM_uint32 
GSS_CALLCONV gss_release_name(
    OM_uint32 *                         minor_status,
    gss_name_t *                        name_P)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_name_desc** name = (gss_name_desc**) name_P ;

    static char *                       _function_name_ =
        "gss_release_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if (name == NULL || *name == NULL || *name == GSS_C_NO_NAME)
    {
        goto exit;
    } 
    
    if ((*name)->x509n)
    {
        X509_NAME_free((*name)->x509n);
    }

    free(*name);
    *name = GSS_C_NO_NAME;
    
 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
    
} 
/* gss_release_name */
/* @} */
