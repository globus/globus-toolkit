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
 * @file duplicate_name.c
 * @author Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include "globus_gsi_gss_constants.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/**
 * @name Duplicate Name
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Copy a GSS name.
 *
 * @param minor_status
 * @param src_name
 * @param dest_name
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_duplicate_name(
    OM_uint32 *                         minor_status,
    const gss_name_t                    src_name,
    gss_name_t *                        dest_name)
{
    OM_uint32                           major_status;
    static char *                       _function_name_ = 
        "gss_duplicate_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if(src_name == GSS_C_NO_NAME)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("Null source name"));
        GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
        return GSS_S_BAD_NAME;
    }

    if(dest_name == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("Null destination name"));
        GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
        return GSS_S_BAD_NAME;
    }

    major_status =  globus_i_gsi_gss_copy_name_to_name(minor_status,
                                                       dest_name,
                                                       src_name);
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
