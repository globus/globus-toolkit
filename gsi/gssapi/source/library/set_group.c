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

/**********************************************************************

set_group.c:
Description:
        GSSAPI routine to set the proxy group field in a gss_name_t.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/**
 * Set the proxy group in a GSS name.
 *
 * This function will set the proxy group in a GSS name structure. If
 * the proxy group was set prior to calling this function then the old
 * group information will be destroyed.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param name
 *        The GSS name to which the group information is added.
 * @param group
 *        A set of buffers containing the individual subgroup names
 *        (strings) in hierarchical order (ie index 0 should contain
 *        the root group).
 * @param group_types
 *        A set of OIDs corresponding to the buffers above Each OID
 *        should indicate that the corresponding subgroup is either of
 *        type "TRUSTED_GROUP" or of type "UNTRUSTED_GROUP". If this
 *        parameter is NULL the type "TRUSTED_GROUP" will be assumed.
 *
 * @return
 *        GSS_S_COMPLETE upon success
 *        GSS_S_FAILURE upon failure
 *
 */


OM_uint32 
GSS_CALLCONV gss_set_group(
    OM_uint32 *                         minor_status,
    gss_name_t                          name,
    const gss_buffer_set_t              group,
    const gss_OID_set                   group_types)
{
    OM_uint32 		                major_status = GSS_S_COMPLETE;
    int                                 i;
    gss_name_desc *                     internal_name;
    char *                              subgroup;
    
    *minor_status = 0;

    internal_name = (gss_name_desc *) name;
    
    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(name == GSS_C_NO_NAME)
    {
        GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(group == GSS_C_NO_BUFFER_SET ||
       group->count == 0)
    {
        return major_status;
    }

    if(group_types != GSS_C_NO_OID_SET &&
       group_types->count != group->count)
    {
        GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(internal_name->group)
    {
        sk_pop_free(internal_name->group,free);
    }

    if(internal_name->group_types)
    {
        ASN1_BIT_STRING_free(internal_name->group_types); 
    }

    internal_name->group = sk_new_null();

    if(internal_name->group == NULL)
    {
        GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;  
    }
    
    internal_name->group_types = ASN1_BIT_STRING_new();

    if(internal_name->group_types == NULL)
    {
        sk_free(internal_name->group);
        GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;  
    }
    
    if(group_types != GSS_C_NO_OID_SET)
    {
        for(i=0;i<group->count;i++)
        {
            if(group->elements[i].value == NULL ||
               &group_types->elements[i] == GSS_C_NO_OID ||
               (!g_OID_equal((gss_OID) &group_types->elements[i],
                             gss_trusted_group) &&
                !g_OID_equal((gss_OID) &group_types->elements[i],
                             gss_untrusted_group)))
            {
                GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_BAD_ARGUMENT);
                *minor_status = gsi_generate_minor_status();
                major_status = GSS_S_FAILURE;
                goto err;
            }
            else
            {
                subgroup = malloc(group->elements[i].length+1);

                if(subgroup == NULL)
                {
                    sk_pop_free(internal_name->group,free);
                    ASN1_BIT_STRING_free(internal_name->group_types); 
                    GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_OUT_OF_MEMORY);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_FAILURE;
                    goto err;  
                }

                strncpy(subgroup,
                        (char *) group->elements[i].value,
                        group->elements[i].length);

                /* make sure it's terminated */
                
                subgroup[group->elements[i].length]='\0';

                sk_insert(internal_name->group,
                          subgroup,i);

                if(g_OID_equal((gss_OID) &group_types->elements[i],
                               gss_untrusted_group))
                {
                    ASN1_BIT_STRING_set_bit(internal_name->group_types,i,1);
                }
            }
        }
    }
    else
    {
        for(i=0;i<group->count;i++)
        {
            if(group->elements[i].value == NULL)
            {
                GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_BAD_ARGUMENT);
                *minor_status = gsi_generate_minor_status();
                major_status = GSS_S_FAILURE;
                goto err;
            }
            else
            {
                subgroup = malloc(group->elements[i].length+1);

                if(subgroup == NULL)
                {
                    sk_pop_free(internal_name->group,free);
                    ASN1_BIT_STRING_free(internal_name->group_types); 
                    GSSerr(GSSERR_F_SET_GROUP,GSSERR_R_OUT_OF_MEMORY);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_FAILURE;
                    goto err;  
                }

                strncpy(subgroup,
                        (char *) group->elements[i].value,
                        group->elements[i].length);

                /* make sure it's terminated */
                
                subgroup[group->elements[i].length]='\0';

                sk_insert(internal_name->group,
                          subgroup,i);
            }
        }
    }
    
err:
    return major_status;
}



