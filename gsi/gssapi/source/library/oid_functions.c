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
 * @file oid_functions.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/* we define the oid values here which are required */

static gss_OID_desc  GSS_C_NT_USER_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"};
gss_OID GSS_C_NT_USER_NAME = &GSS_C_NT_USER_NAME_desc;

static gss_OID_desc   GSS_C_NT_MACHINE_UID_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"};
gss_OID GSS_C_NT_MACHINE_UID_NAME = &GSS_C_NT_MACHINE_UID_NAME_desc;

static gss_OID_desc  GSS_C_NT_STRING_UID_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"};
gss_OID GSS_C_NT_STRING_UID_NAME = &GSS_C_NT_STRING_UID_NAME_desc;

static gss_OID_desc  GSS_C_NT_HOSTBASED_SERVICE_X_desc = 
		{6, (void *)"\x2b\x06\x01\x05\x06\x02"};
gss_OID GSS_C_NT_HOSTBASED_SERVICE_X = &GSS_C_NT_HOSTBASED_SERVICE_X_desc;

static gss_OID_desc  GSS_C_NT_HOSTBASED_SERVICE_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"};
gss_OID GSS_C_NT_HOSTBASED_SERVICE = &GSS_C_NT_HOSTBASED_SERVICE_desc;

static gss_OID_desc  GSS_C_NT_ANONYMOUS_desc = 
		{6, (void *)"\x2b\x06\01\x05\x06\x03"};
gss_OID GSS_C_NT_ANONYMOUS = &GSS_C_NT_ANONYMOUS_desc;

static gss_OID_desc  GSS_C_NT_EXPORT_NAME_desc = 
		{6, (void *)"\x2b\x06\x01\x05\x06\x04"};
gss_OID GSS_C_NT_EXPORT_NAME = &GSS_C_NT_EXPORT_NAME_desc;

/*
 * for backwards compatability, also define the V1 constant OID
 * pointing the V2 OIDs. This is done mostly for DLL compatability
 */

gss_OID gss_nt_user_name =        &GSS_C_NT_USER_NAME_desc;
gss_OID gss_nt_machine_uid_name = &GSS_C_NT_MACHINE_UID_NAME_desc;
gss_OID gss_nt_string_uid_name =  &GSS_C_NT_STRING_UID_NAME_desc;
gss_OID gss_nt_service_name = 	  &GSS_C_NT_HOSTBASED_SERVICE_desc;

/**
 * define the Globus object ids
 * This is regestered as a private enterprise
 * via IANA
 *  http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
 *
 * iso.org.dod.internet.private.enterprise (1.3.6.1.4.1)
 * globus 3536 
 * security 1
 * gssapi_openssl 1
 */

static const gss_OID_desc gss_mech_oid_globus_gssapi_openssl = 
	{9, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01"};

const gss_OID_desc * const gss_mech_globus_gssapi_openssl = 
		&gss_mech_oid_globus_gssapi_openssl;

static const gss_OID_desc gss_proxycertinfo_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x06"}; 
const gss_OID_desc * const gss_proxycertinfo_extension = 
                &gss_proxycertinfo_extension_oid;

static const gss_OID_desc grim_policy_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x07"}; 
const gss_OID_desc * const grim_policy =
                &grim_policy_oid;

static const gss_OID_desc gss_ext_x509_cert_chain_oid_desc =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 
const gss_OID_desc * const gss_ext_x509_cert_chain_oid =
                &gss_ext_x509_cert_chain_oid_desc;


/**
 * @name Add OID Set Member
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * 
 * Adds an Object Identifier to an Object Identifier set. 
 * This routine is intended for use in conjunction with 
 * GSS_Create_empty_OID_set() when constructing a set
 * of mechanism OIDs for input to GSS_Acquire_cred().
 *
 * @param minor_status
 * @param member_oid
 * @param oid_set
 *
 * @return
 *         GSS_S_COMPLETE indicates successful completion 
 *         GSS_S_FAILURE indicates that the operation failed 
 *
 */

OM_uint32
GSS_CALLCONV gss_add_oid_set_member(
    OM_uint32 *                         minor_status,
    const gss_OID                       member_oid,
    gss_OID_set *                       oid_set)
{
    int                                 new_count;
    gss_OID                             new_elements;
    gss_OID_set                         set;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ = 
        "gss_add_oid_set_member";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /* Sanity check */
    if ((minor_status == NULL) || (member_oid == NULL) || (oid_set == NULL))
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid argument passed to function")));
        goto exit;
    }
        
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    set = *oid_set;
        
    new_count = set->count + 1;
    new_elements = malloc(sizeof(gss_OID_desc) * new_count);
        
    if (new_elements == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
        
    if (set->count > 0)
    {
        /* Copy existing oids */
        memcpy(new_elements, set->elements, sizeof(gss_OID_desc) * set->count);
    }
        
    /* And append new oid */
    memcpy(&new_elements[set->count], member_oid, sizeof(gss_OID_desc));
        
 exit:

    if (set->elements)
    {
        free(set->elements);
    }
        
    set->count = new_count;
    set->elements = new_elements;

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Create Empty OID Set
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 *
 * Creates an object identifier set containing no object identifiers,
 * to which members may be subsequently added 
 * using the GSS_Add_OID_set_member()
 * routine. These routines are intended to be 
 * used to construct sets of mechanism
 * object identifiers, for input to GSS_Acquire_cred().
 *
 * @param minor_status
 * @param oid_set
 *
 * @return
 *         GSS_S_COMPLETE indicates successful completion 
 *         GSS_S_FAILURE indicates that the operation failed 
 */
OM_uint32
GSS_CALLCONV gss_create_empty_oid_set(
    OM_uint32 *                         minor_status,
    gss_OID_set *                       oid_set)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "gss_create_empty_oid_set";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /* Sanity check */
    if ((oid_set == NULL) || (minor_status == NULL))
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid argument passed to function")));
        goto exit;
    }

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    *oid_set = (gss_OID_set_desc *) malloc(sizeof(gss_OID_set_desc));
    if (!*oid_set)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
        
    (*oid_set)->count = 0;
    (*oid_set)->elements = NULL;
    
 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}


/**
 * @name Indicate Mechs
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Passes back the mech set of available mechs.
 * We only have one for now. 
 *
 * @param minor_status
 * @param mech_set
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_indicate_mechs(
    OM_uint32 *                         minor_status,
    gss_OID_set *                       mech_set)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    gss_OID_set_desc  *                 set;
    static char *                       _function_name_ =
        "gss_indicate_mechs";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    
    major_status = gss_create_empty_oid_set(&local_minor_status, 
                                            &set);
    if (GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH);
        goto exit;
    }
    
    major_status = gss_add_oid_set_member(
        &local_minor_status, 
        (const gss_OID) gss_mech_globus_gssapi_openssl,
        &set);
    if (GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OID);
        
        gss_release_oid_set(&local_minor_status, &set);
        goto exit;
    }
    
    *mech_set = set;

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Release OID Set
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 *
 * Release the OID set. 
 *
 * @param minor_status
 * @param mech_set
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_release_oid_set(
    OM_uint32 *                         minor_status,
    gss_OID_set *                       mech_set)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_OID_set                         set;
    static char *                       _function_name_ =
        "gss_release_oid_set";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    set = *mech_set;

    if (mech_set && set && set != GSS_C_NO_OID_SET) {
        
        if((*mech_set)->elements)
        {
            free((*mech_set)->elements);
        }

        free(*mech_set);
        *mech_set = GSS_C_NO_OID_SET;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Test OID Set Member
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Interrogates an Object Identifier set to determine whether a
 * specified Object Identifier is a member. This routine is
 * intended to be used with OID sets returned by
 * GSS_Indicate_mechs(), GSS_Acquire_cred(), and
 * GSS_Inquire_cred(). 
 *
 * @param minor_status
 * @param member
 * @param set
 * @param present
 *
 * @return
 *         GSS_S_COMPLETE indicates successful completion 
 *         GSS_S_FAILURE indicates that the operation failed 
 */
OM_uint32 
GSS_CALLCONV gss_test_oid_set_member(	
    OM_uint32 *		                minor_status,
    const gss_OID		        member,
    const gss_OID_set	                set,
    int *			        present)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    int			                index;
    static char *                       _function_name_ =
        "gss_test_oid_set_member";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    /* Sanity check arguments */
    if ((minor_status == NULL) ||
        (member == NULL) ||
        (member->elements == NULL) ||
        (set == NULL) ||
        (present == NULL))
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid argument passed to function")));
        goto exit;
    }
	
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    *present = 0;

    for (index = 0; index < set->count; index++)
    {
        /* Sanity check */
        if (set->elements[index].elements == NULL)
        {
            continue;
        }
        
        if ((set->elements[index].length == member->length) &&
            (memcmp(set->elements[index].elements,
                    member->elements,
                    member->length) == 0))
        {
            *present = 1;
            break;
        }
    }
    
 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */
