/**********************************************************************

get_group.c:
Description:
        GSSAPI routine to get the proxy group field in a gss_name_t.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>

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
 *
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
    
    *minor_status = 0;

    internal_name = (gss_name_desc *) name;

    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_GET_GROUP,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(name == GSS_C_NO_NAME)
    {
        GSSerr(GSSERR_F_GET_GROUP,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(group == NULL)
    {
        GSSerr(GSSERR_F_GET_GROUP,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(group_types == NULL)
    {
        GSSerr(GSSERR_F_GET_GROUP,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(internal_name->group == NULL)
    {
        return major_status;
    }

    num_subgroups = sk_num(internal_name->group);
    
    if(num_subgroups == 0)
    {
        return major_status;
    }
    
    if(internal_name->group_types == NULL)
    {
        GSSerr(GSSERR_F_GET_GROUP,GSSERR_R_BAD_NAME);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_BAD_NAME;
        goto err;
    }

    major_status = gss_create_empty_buffer_set(minor_status, group);

    if(major_status != GSS_S_COMPLETE)
    {
        goto err;
    }

    major_status = gss_create_empty_oid_set(minor_status, group_types);

    if(major_status != GSS_S_COMPLETE)
    {
        gss_release_buffer_set(&tmp_minor_status, group);
        goto err;
    }

    for(i=0;i<num_subgroups;i++)
    {
        subgroup = sk_value(internal_name->group,i);
        
        buffer.value = (void *) subgroup;
        
        buffer.length = strlen(subgroup) + 1;

        major_status = gss_add_buffer_set_member(minor_status,
                                                 &buffer,
                                                 group);

        if(major_status != GSS_S_COMPLETE)
        {
            gss_release_buffer_set(&tmp_minor_status, group);
            gss_release_oid_set(&tmp_minor_status, group_types);
            goto err;
        }

        if(ASN1_BIT_STRING_get_bit(internal_name->group_types,i))
        {
            major_status = gss_add_oid_set_member(
                minor_status,
                (gss_OID) gss_untrusted_group,
                group_types);
        }
        else
        {
            major_status = gss_add_oid_set_member(
                minor_status,
                (gss_OID) gss_trusted_group,
                group_types);
        }

        if(major_status != GSS_S_COMPLETE)
        {
            gss_release_buffer_set(&tmp_minor_status, group);
            gss_release_oid_set(&tmp_minor_status, group_types);
            goto err;
        }
    }
    
err:
    return major_status;
}



