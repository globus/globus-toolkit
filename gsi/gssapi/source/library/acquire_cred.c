/**********************************************************************

acquire_cred.c:

Description:
	GSSAPI routine to acquire the local credential
	See: <draft-ietf-cat-gssv2-cbind-04.txt>

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
#include <stdlib.h>
#include <sys/stat.h>

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

/*
 * DEE? Need to add the callback using this: 
 * user can override this to point to thier routines  
 * we will provide it to SSL for its password prompt
 * callback 
 */
char * (*tis_gss_user_supplied_getpass)(char *);

/**********************************************************************
Function:   gss_indicate_mech()

Description:
	Passes back the mech set of available mechs.
	We only have one for now. 

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_indicate_mechs
(OM_uint32 *              minor_status ,
 gss_OID_set *             mech_set
)
{
	gss_OID_set_desc  * set;

	*minor_status = 0;
	set = (gss_OID_set_desc *)malloc(sizeof(gss_OID_set_desc));
	if (!set) {
		return GSS_S_FAILURE;
	}
	set->count = 1;
		/* problems with const, so cast to a non-const */
	set->elements = (gss_OID) gss_mech_globus_gssapi_ssleay;

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
Function:   gss_acquire_cred()

Description:
	Gets the local credentials.  The proxy_init_cred does most of the
	work of setting up the SSL_ctx, getting the user's cert, key, etc. 

	The globusid will be obtained from the certificate. (Minus
	and /CN=proxy entries.)

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_acquire_cred
(OM_uint32 *               minor_status ,
 const gss_name_t          desired_name_P ,
 OM_uint32                 time_req ,
 const gss_OID_set         desired_mechs ,
 gss_cred_usage_t          cred_usage ,
 gss_cred_id_t *           output_cred_handle_P ,
 gss_OID_set *             actual_mechs ,
 OM_uint32 *               time_rec 
) 
{
	gss_cred_id_desc** output_cred_handle = 
		(gss_cred_id_desc**) output_cred_handle_P ;
  
	OM_uint32 major_status = GSS_S_NO_CRED;
	gss_cred_id_desc* newcred ;
	int status;

#ifdef DEBUG
	fprintf(stderr,"acquire_cred:usage=%d\n",cred_usage);
	fprintf(stderr,"uid=%d, pid=%d$HOME=%s\n",getuid(),getpid(),
		getenv("HOME")?getenv("HOME"):"NO_HOME");
#endif /* DEBUG */
  
	/* 
	 * We are going to use the SSL error routines, get them
	 * initilized early. They may be called more then once. 
	 */

	ERR_load_gsserr_strings(0);  /* load our gss ones as well */

	*minor_status = 0;
  
	if (actual_mechs != NULL) {
		major_status = gss_indicate_mechs(minor_status,
						actual_mechs);
		if (major_status != GSS_S_COMPLETE) {
			return  major_status;
		}
	}

	if (time_rec != NULL) {
		*time_rec = GSS_C_INDEFINITE ;
	}


major_status = gss_create_and_fill_cred(minor_status,
                    output_cred_handle_P,
                    cred_usage,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
#ifdef DEBUG
	fprintf(stderr,"acquire_cred:major_status:%08x\n",major_status);
#endif
	return major_status;
}
