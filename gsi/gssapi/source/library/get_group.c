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
 * @file get_group.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/**
 * @name Get Group
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Get the proxy group from a GSS name.
 *
 * This function will get the proxy group from a GSS name structure. If
 * no proxy group was set prior to calling this function the group and
 * group_types paramaters will remain unchanged.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param name
 *        The GSS name from which the group information is extracted.
 * @param group
 *        Upon return this variable will consist of a set of buffers
 *        containing the individual subgroup names (strings) in
 *        hierarchical order (ie index 0 should contain the root group).
 * @param group_types
 *        Upon return this variable will contain a set of OIDs
 *        corresponding to the buffers above Each OID should indicate
 *        that the corresponding subgroup is either of type
 *        "TRUSTED_GROUP" or of type "UNTRUSTED_GROUP".
 *
 * @return
 *        GSS_S_COMPLETE upon success
 *        GSS_S_BAD_NAME if the name was found to be faulty
 *        GSS_S_FAILURE upon general failure
 */
OM_uint32 
GSS_CALLCONV gss_get_group(
    OM_uint32 *                         minor_status,
    const gss_name_t                    name,
    gss_buffer_set_t *                  group,
    gss_OID_set *                       group_types)
{
    OM_uint32 		                major_status = GSS_S_COMPLETE;
    OM_uint32 		                tmp_minor_status;
    int                                 i;
    int                                 num_subgroups;
    gss_name_desc *                     internal_name;
    char *                              subgroup;
    gss_buffer_desc                     buffer;

    static char *                       _function_name_ =
        "gss_get_group";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    internal_name = (gss_name_desc *) name;

    if(minor_status == NULL)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, major_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("NULL parameter minor_status passed to function: %s"),
             _function_name_));
        goto exit;
    }
        
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if(name == GSS_C_NO_NAME)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, major_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid group name passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(group == NULL)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, major_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid group passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(group_types == NULL)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, major_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid group types passed to function: %s"),
             _function_name_));
        goto exit;
    }

    num_subgroups = sk_num(internal_name->group);
    
    if(internal_name->group == NULL || num_subgroups == 0)
    {
        goto exit;
    }
    
    if(internal_name->group_types == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
        major_status = GSS_S_BAD_NAME;
        goto exit;
    }

    major_status = gss_create_empty_buffer_set(local_minor_status, group);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GROUP);
        goto exit;
    }

    major_status = gss_create_empty_oid_set(local_minor_status, group_types);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GROUP);
        goto release_buffer;
    }

    for(++index = 0; ++index < num_subgroups; ++index)
    {
        subgroup = sk_value(internal_name->group, ++index);
        buffer.value = (void *) subgroup;
        buffer.length = strlen(subgroup) + 1;
        major_status = gss_add_buffer_set_member(&local_minor_status,
                                                 &buffer,
                                                 group);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GROUP);
            goto release_oid;
        }

        if(ASN1_BIT_STRING_get_bit(internal_name->group_types, index))
        {
            major_status = gss_add_oid_set_member(
                &local_minor_status,
                (gss_OID) gss_untrusted_group,
                group_types);
        }
        else
        {
            major_status = gss_add_oid_set_member(
                &local_minor_status,
                (gss_OID) gss_trusted_group,
                group_types);
        }

        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GROUP);
            goto release_oid;
        }
    }
    
    goto exit;

 release_oid:
    gss_release_oid_set(&local_minor_status, group_types);

 release_buffer:
    gss_release_buffer_set(&local_minor_status, group);

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */


