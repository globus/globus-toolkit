
/**********************************************************************

oid_functions.c

Description:

	GSSAPI oid manipulation functions.

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi.h"
#include "gssapi_ssleay.h"
#include <string.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

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

/*
 * define the Globus object ids
 * This is regestered as a private enterprise
 * via IANA
 *  http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
 *
 * iso.org.dod.internet.private.enterprise (1.3.6.1.4.1)
 * globus 3536 
 * security 1
 * gssapi_ssleay 1
 */

static const gss_OID_desc gss_mech_oid_globus_gssapi_ssleay = 
	{9, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01"};
const gss_OID_desc * const gss_mech_globus_gssapi_ssleay = 
		&gss_mech_oid_globus_gssapi_ssleay;

static const gss_OID_desc gss_restrictions_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x03"}; 
const gss_OID_desc * const gss_restrictions_extension = 
                &gss_restrictions_extension_oid;

static const gss_OID_desc gss_trusted_group_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x04"}; 
const gss_OID_desc * const gss_trusted_group = 
                &gss_trusted_group_oid;

static const gss_OID_desc gss_untrusted_group_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x05"}; 
const gss_OID_desc * const gss_untrusted_group = 
                &gss_untrusted_group_oid;

static const gss_OID_desc gss_cas_policy_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x06"}; 
const gss_OID_desc * const gss_cas_policy_extension = 
                &gss_cas_policy_extension_oid;


/**********************************************************************
Function:   gss_add_oid_set_member()

Description:

Adds an Object Identifier to an Object Identifier set. This routine is intended
for use in conjunction with GSS_Create_empty_OID_set() when constructing a set
of mechanism OIDs for input to GSS_Acquire_cred().

Returns:

GSS_S_COMPLETE indicates successful completion 
GSS_S_FAILURE indicates that the operation failed 

**********************************************************************/

OM_uint32
GSS_CALLCONV gss_add_oid_set_member(
    OM_uint32 *                         minor_status ,
    const gss_OID                       member_oid ,
    gss_OID_set *                       oid_set)
{
    int                                 new_count;
    gss_OID                             new_elements;
    gss_OID_set                         set;
        
    /* Sanity check */
    if ((minor_status == NULL) ||
        (member_oid == NULL) ||
        (oid_set == NULL))
    {
        GSSerr(GSSERR_F_ADD_OID_SET_MEMBER,
               GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
        
    set = *oid_set;
        
    new_count = set->count + 1;
    new_elements = malloc(sizeof(gss_OID_desc) * new_count);
        
    if (new_elements == NULL)
    {
        GSSerr(GSSERR_F_ADD_OID_SET_MEMBER,
               GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
        
    if (set->count > 0)
    {
        /* Copy existing oids */
        memcpy(new_elements, set->elements,
               sizeof(gss_OID_desc) * set->count);
    }
        
    /* And append new oid */
    memcpy(&new_elements[set->count],
           member_oid,
           sizeof(gss_OID_desc));
        
    if (set->elements != NULL)
    {
        free(set->elements);
    }
        
    set->count = new_count;
    set->elements = new_elements;
        
    return GSS_S_COMPLETE;
}


/**********************************************************************
Function:   gss_create_empty_oid_set()

Description:

Creates an object identifier set containing no object identifiers,
to which members may be subsequently added using the GSS_Add_OID_set_member()
routine. These routines are intended to be used to construct sets of mechanism
object identifiers, for input to GSS_Acquire_cred().


Returns:

GSS_S_COMPLETE indicates successful completion 
GSS_S_FAILURE indicates that the operation failed 

**********************************************************************/

OM_uint32
GSS_CALLCONV gss_create_empty_oid_set(
    OM_uint32 *                         minor_status ,
    gss_OID_set *                       oid_set)
{
    *minor_status = 0;

    /* Sanity check */
    if ((oid_set == NULL) ||
        (minor_status == NULL))
    {
        GSSerr(GSSERR_F_CREATE_EMPTY_OID_SET,
               GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }

    *oid_set = (gss_OID_set_desc *)malloc(sizeof(gss_OID_set_desc));
    if (!*oid_set)
    {
        GSSerr(GSSERR_F_CREATE_EMPTY_OID_SET,
               GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
        
    (*oid_set)->count = 0;
    (*oid_set)->elements = NULL;
    
    return GSS_S_COMPLETE;
}


/**********************************************************************
Function:   gss_indicate_mech()

Description:
	Passes back the mech set of available mechs.
	We only have one for now. 

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_indicate_mechs(
    OM_uint32 *                         minor_status,
    gss_OID_set *                       mech_set)
{
    gss_OID_set_desc  *                 set;
    
    *minor_status = 0;
    
    if (gss_create_empty_oid_set(minor_status, &set) == GSS_S_FAILURE)
    {
        return GSS_S_FAILURE;
    }
    
    if (gss_add_oid_set_member(minor_status, 
                               gss_mech_globus_gssapi_ssleay,
                               &set) == GSS_S_FAILURE)
    {
        OM_uint32       tmp_minor_status;
        
        gss_release_oid_set(&tmp_minor_status, &set);
        return GSS_S_FAILURE;
    }
    
    *mech_set = set;
    return GSS_S_COMPLETE;
}

/**********************************************************************
Function:   gss_release_oid_set()

Description:
	Release the OID set. 

Returns:
**********************************************************************/
OM_uint32 
GSS_CALLCONV gss_release_oid_set
(OM_uint32 *              minor_status ,
 gss_OID_set *             mech_set
)
{

	*minor_status = 0;
	if (mech_set && *mech_set && *mech_set != GSS_C_NO_OID_SET) {
		free(*mech_set);
		*mech_set = GSS_C_NO_OID_SET;
	}
	return GSS_S_COMPLETE;
}
/**********************************************************************
Function:   gss_testoid_set_member()

Description:
	Interrogates an Object Identifier set to determine whether a
	specified Object Identifier is a member. This routine is
	intended to be used with OID sets returned by
	GSS_Indicate_mechs(), GSS_Acquire_cred(), and
	GSS_Inquire_cred(). 

Returns:
	GSS_S_COMPLETE indicates successful completion 
	GSS_S_FAILURE indicates that the operation failed 
	
**********************************************************************/
OM_uint32 
GSS_CALLCONV gss_test_oid_set_member
(	OM_uint32 *		minor_status,
	const gss_OID		member,
	const gss_OID_set	set,
	int *			present)
{
	int			index;
	
	/* Sanity check arguments */
	if ((minor_status == NULL) ||
	    (member == NULL) ||
	    (member->elements == NULL) ||
	    (set == NULL) ||
	    (present == NULL))
	{
            GSSerr(GSSERR_F_TEST_OID_SET_MEMBER,
                   GSSERR_R_BAD_ARGUMENT);
            *minor_status = gsi_generate_minor_status();
            return GSS_S_FAILURE;
	}
	
	*minor_status = 0;
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
	
	return GSS_S_COMPLETE;
}
