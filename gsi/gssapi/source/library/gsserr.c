/**********************************************************************

gsserr.c

Description:
	Error messages to be used with the SSLeay error message
    routines. 
	

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

#include "gssapi_ssleay.h"

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/* BEGIN ERROR CODES */
static ERR_STRING_DATA gsserr_str_functs[]=
{
 {ERR_PACK(0,GSSERR_F_ACCEPT_SEC,0),"gss_accept_sec_context"},
 {ERR_PACK(0,GSSERR_F_ACQUIRE_CRED,0),"gss_acquire_cred"},
 {ERR_PACK(0,GSSERR_F_COMPARE_NAME,0),"gss_compare_name"},
 {ERR_PACK(0,GSSERR_F_DELETE_SEC,0),"gss_delete_sec_context"},
 {ERR_PACK(0,GSSERR_F_EXPORT_NAME,0),"gss_export_name"},
 {ERR_PACK(0,GSSERR_F_GLOBUSFILE,0),"retrieve_globusid"},
 {ERR_PACK(0,GSSERR_F_IMPORT_NAME,0),"gss_import_name"},
 {ERR_PACK(0,GSSERR_F_INIT_SEC,0),"gss_init_sec_context"},
 {ERR_PACK(0,GSSERR_F_RELEASE_BUFFER,0),"gss_release_buffer"},
 {ERR_PACK(0,GSSERR_F_RELEASE_CRED,0),"gss_release_cred"},
 {ERR_PACK(0,GSSERR_F_RELEASE_NAME,0),"gss_release_name"},
 {ERR_PACK(0,GSSERR_F_NAME_TO_NAME,0),"gss_copy_name_to_name"},
 {ERR_PACK(0,GSSERR_F_CREATE_FILL,0),"gss_create_and_fill_context"},
 {ERR_PACK(0,GSSERR_F_GS_HANDSHAKE,0),"gs_handshake"},
 {ERR_PACK(0,GSSERR_F_GS_RETRIVE_PEER,0),"gs_retrieve_peer"},
 {ERR_PACK(0,GSSERR_F_WRAP,0),"gss_warp"},
 {ERR_PACK(0,GSSERR_F_UNWRAP,0),"gss_unwrap"},
 {ERR_PACK(0,GSSERR_F_GET_MIC,0),"gss_get_mic"},
 {ERR_PACK(0,GSSERR_F_VERIFY_MIC,0),"gss_verify_mic"},
 {ERR_PACK(0,GSSERR_F_IMPORT_SEC,0),"gss_import_sec_context"},
 {ERR_PACK(0,GSSERR_F_EXPORT_SEC,0),"gss_export_sec_context"},
 {ERR_PACK(0,GSSERR_F_IMPORT_CRED,0),"gss_import_cred"},
 {ERR_PACK(0,GSSERR_F_EXPORT_CRED,0),"gss_export_cred"},
 {ERR_PACK(0,GSSERR_F_INIT_DELEGATION,0),"gss_init_delegation"},
 {ERR_PACK(0,GSSERR_F_ACCEPT_DELEGATION,0),"gss_accept_delegation"},
 {ERR_PACK(0,GSSERR_F_INQUIRE_BY_OID,0),"gss_inquire_sec_context_by_oid"},
 {ERR_PACK(0,GSSERR_F_READ,0),"gs_read"},
 {ERR_PACK(0,GSSERR_F_WRITE,0),"gs_write"},
 {0,NULL},
};

static ERR_STRING_DATA gsserr_str_reasons[]= 
{
 {GSSERR_R_HANDSHAKE, "SSLv3 handshake problems"},
 {GSSERR_R_NO_GLOBUSID, "globusid not found"},
 {GSSERR_R_PROCESS_CERT, "getting cert subject name"},
 {GSSERR_R_MUTUAL_AUTH, "Mutual authentication failed"},
 {GSSERR_R_WRAP_BIO, "internal problem with SSL BIO"},
 {GSSERR_R_PROXY_VIOLATION, "Peer is using (limited) proxy"},
 {GSSERR_R_PROXY_NOT_RECEIVED, "Failed to receive proxy request"},
 {GSSERR_R_IMPEXP_BAD_PARMS, "Bad parameters"},
 {GSSERR_R_IMPEXP_BIO_SSL, "Internal SSL problem"},
 {GSSERR_R_IMPEXP_NO_CIPHER, "Cipher not available"},
 {GSSERR_R_IMPEXP_BAD_LEN, "Token is wrong length"},
 {GSSERR_R_CLASS_ADD_EXT, "Unable to add Class Add extension"},
 {GSSERR_R_ADD_EXT, "Unable to add extension"},
 {GSSERR_R_EXPORT_FAIL, "Unable to marshal credential for export"},
 {GSSERR_R_IMPORT_FAIL, "Unable to read credential for import"},
 {GSSERR_R_READ_BIO, "Input Error"},
 {GSSERR_R_WRITE_BIO, "Output Error"},
 {GSSERR_R_PASSED_NULL_PARAMETER, "NULL was passed as a parameter"},
 {GSSERR_R_UNEXPECTED_FORMAT, "Not in expected Format"},
 {GSSERR_R_BAD_DATE, "Cannot verify message date"},
 {GSSERR_R_BAD_MECH, "Requested mechanism not supported"},
 {GSSERR_R_REMOTE_CERT_VERIFY_FAILED, "remote side did not "
    "like my creds for unknown reason\n     check server logs for details"},
 {0,NULL},
};


/**********************************************************************
Function: ERR_load_gsserr_strings()

Description:
	Sets up the error tables used by SSL and adds ours
	using the ERR_LIB_USER
	Only the first call does anything.

Parameters:
    i should be zero to the first call of any of the ERR_load_.*_strings functions and non-zero
    for the rest.   
Returns:
**********************************************************************/


int
ERR_load_gsserr_strings(int i)
{
	static int init=1;

	if (init) {
        init=0;
		i = ERR_load_prxyerr_strings(i);
		ERR_load_strings(ERR_USER_LIB_GSSERR_NUMBER, gsserr_str_functs);
		ERR_load_strings(ERR_USER_LIB_GSSERR_NUMBER, gsserr_str_reasons);
		i++;
	}
	return i;
}

/**********************************************************************
Function: convert_minor_codes()

Description:
    converts error codes created in various libraries into gss minor codes
    The top two bytes are the library the bottom two are the reason code

Parameters:
    lib -  The number of the error library that
    the error code was defined under it can be obtained using
    ERR_GET_LIB(ERR_peek_error()) or passed a constant if the library 
    the error is under is known.

    reason - The number of the error reason, it can be obtained using
    ERR_GET_REASON(ERR_peek_error())

Returns:
    an unsigned long suitable for use as a GSS minor code
**********************************************************************/


OM_uint32
convert_minor_codes(const int lib, const int reason)
{
    OM_uint32 ul_lib = (OM_uint32)lib;
    OM_uint32 ul_reason = (OM_uint32)reason; 
#ifdef DEBUG
    fprintf(stderr,"lib: %i, reason: %i, result: %lu\n",
            lib,reason, ((ul_lib << 16) | ul_reason));
#endif
    return ((ul_lib << 16)  |  ul_reason);
}
