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
 {0,NULL},
};

/* GSSERR_R_PROXY_EXPIRED and PRXYERR_R_CERT_EXPIRE reason strings are
   defined under PRXYERR_R_PROXY_EXPIRE and PRXYERR_R_CERT_EXPIRE in
   sslutils.c
*/

static int ERR_user_lib_gsserr_number;

/**********************************************************************
Function: ERR_load_gsserr_strings()

Description:
	Sets up the error tables used by SSL and adds ours
	using the ERR_LIB_USER
	Only the first call does anything.

Parameters:
   
Returns:
**********************************************************************/


int
ERR_load_gsserr_strings(int i)
{
	static int init=1;

	if (init) {
		init=0;
		i = ERR_load_prxyerr_strings(i);
		ERR_load_strings(ERR_LIB_USER+i,gsserr_str_functs);
		ERR_load_strings(ERR_LIB_USER+i,gsserr_str_reasons);
		ERR_user_lib_gsserr_number = ERR_LIB_USER+i;
		i++;
	}
	return i;
}

int
ERR_user_lib_gsserr_num()
{
	return ERR_user_lib_gsserr_number;
}

/**********************************************************************
Function: convert_minor_codes()

Description:
    converts error codes created in various libraries into gss minor codes
    currently it is only implemented to convert SSL minor codes from
    sslutils.h

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
    unsigned long retval = 0;

#ifdef DEBUG
    fprintf(stderr,"lib: %i, reason: %i, ssl_lib: %i\n",
            lib,reason,ERR_user_lib_prxyerr_num());
#endif

    if (lib == ERR_user_lib_prxyerr_num()) 
    {
        switch (reason)
        {
            case PRXYERR_R_USER_CERT_EXPIRED:            
                 retval =  GSSERR_PRXY_R_USER_CERT_EXPIRED;
            break;
            case PRXYERR_R_SERVER_CERT_EXPIRED:            
                 retval =  GSSERR_PRXY_R_SERVER_CERT_EXPIRED;
            break;
            case PRXYERR_R_NO_PROXY:
                 retval = GSSERR_PRXY_R_NO_PROXY;
            break;
            case PRXYERR_R_PROXY_EXPIRED:
                 retval = GSSERR_PRXY_R_PROXY_EXPIRED;
            break;
            case PRXYERR_R_BAD_PROXY_ISSUER:
                 retval = GSSERR_PRXY_R_BAD_PROXY_ISSUER;
            break;
            case PRXYERR_R_LPROXY_MISSED_USED:
                 retval = GSSERR_PRXY_R_LPROXY_MISSED_USED;
            break;
            case PRXYERR_R_CRL_SIGNATURE_FAILURE:
                 retval = GSSERR_PRXY_R_CRL_SIGNATURE_FAILURE;
            break;
            case PRXYERR_R_CRL_NEXT_UPDATE_FIELD:
                 retval = GSSERR_PRXY_R_CRL_NEXT_UPDATE_FIELD;
            break;
            case PRXYERR_R_CRL_HAS_EXPIRED:
                 retval = GSSERR_PRXY_R_CRL_HAS_EXPIRED;
            break;
            case PRXYERR_R_CERT_REVOKED:
                 retval = GSSERR_PRXY_R_CERT_REVOKED;
            break;
            case PRXYERR_R_CA_NOPATH:
                 retval = GSSERR_PRXY_R_CA_NOPATH;
            break;
            case PRXYERR_R_CA_NOFILE:
                 retval = GSSERR_PRXY_R_CA_NOFILE;
            break;
            case PRXYERR_R_CA_POLICY_RETRIEVE:
                 retval = GSSERR_PRXY_R_CA_POLICY_RETRIEVE;
            break;
            case PRXYERR_R_CA_POLICY_PARSE:
                 retval = GSSERR_PRXY_R_CA_POLICY_PARSE;
            break;
            case PRXYERR_R_CA_POLICY_ERR:
                 retval = GSSERR_PRXY_R_CA_POLICY_ERR;
            break;
            case PRXYERR_R_CA_POLICY_VIOLATION:
                 retval = GSSERR_PRXY_R_CA_POLICY_VIOLATION;
            break;
            case PRXYERR_R_CA_UNKNOWN:
                 retval = GSSERR_PRXY_R_CA_UNKNOWN;
            break;
            case PRXYERR_R_CB_CALLED_WITH_ERROR:
                 retval = GSSERR_PRXY_R_CB_CALLED_WITH_ERROR;
            break;

            case PRXYERR_R_PROCESS_PROXY_KEY:
                 retval = GSSERR_PRXY_R_PROCESS_PROXY_KEY;
            break;
            case PRXYERR_R_PROCESS_REQ:
                 retval = GSSERR_PRXY_R_PROCESS_REQ;
            break;
            case PRXYERR_R_PROCESS_SIGN:
                retval = GSSERR_PRXY_R_PROCESS_SIGN;
            break; 
            case PRXYERR_R_MALFORM_REQ:
                 retval = GSSERR_PRXY_R_MALFORM_REQ;
            break;
            case PRXYERR_R_SIG_VERIFY:
                 retval = GSSERR_PRXY_R_SIG_VERIFY;
            break;
            case PRXYERR_R_SIG_BAD:
                 retval = GSSERR_PRXY_R_SIG_BAD;
            break;
            case PRXYERR_R_PROCESS_PROXY:
                 retval = GSSERR_PRXY_R_PROCESS_PROXY;
            break;
            case PRXYERR_R_PROXY_NAME_BAD:
                 retval = GSSERR_PRXY_R_PROXY_NAME_BAD;
            break;
            case PRXYERR_R_PROCESS_SIGNC:
                 retval = GSSERR_PRXY_R_PROCESS_SIGNC;
            break;
            case PRXYERR_R_PROBLEM_PROXY_FILE:
                 retval = GSSERR_PRXY_R_PROBLEM_PROXY_FILE;
            break;
            case PRXYERR_R_SIGN_NOT_CA:
                 retval = GSSERR_PRXY_R_SIGN_NOT_CA;
            break;
            case PRXYERR_R_PROCESS_KEY:
                 retval = GSSERR_PRXY_R_PROCESS_KEY;
            break;
            case PRXYERR_R_PROCESS_CERT:
                 retval = GSSERR_PRXY_R_PROCESS_CERT;
            break;
            case PRXYERR_R_PROCESS_CERTS:
                 retval = GSSERR_PRXY_R_PROCESS_CERTS;
            break;
            case PRXYERR_R_NO_TRUSTED_CERTS:
                 retval = GSSERR_PRXY_R_NO_TRUSTED_CERTS;
            break;
            case PRXYERR_R_PROBLEM_KEY_FILE:
                 retval = GSSERR_PRXY_R_PROBLEM_KEY_FILE;
            break;
            case PRXYERR_R_PROBLEM_NOCERT_FILE:
                 retval = GSSERR_PRXY_R_PROBLEM_NOCERT_FILE;
            break;
            case PRXYERR_R_PROBLEM_NOKEY_FILE:
                 retval = GSSERR_PRXY_R_PROBLEM_NOKEY_FILE;
            break;
            case PRXYERR_R_ZERO_LENGTH_KEY_FILE:
                 retval = GSSERR_PRXY_R_ZERO_LENGTH_KEY_FILE;
            break;
            case PRXYERR_R_ZERO_LENGTH_CERT_FILE:
                 retval = GSSERR_PRXY_R_ZERO_LENGTH_CERT_FILE;
            break;
            case PRXYERR_R_NO_HOME:
                 retval = GSSERR_PRXY_R_NO_HOME;
            break;
            case PRXYERR_R_LPROXY_REJECTED:
                 retval = GSSERR_PRXY_R_LPROXY_REJECTED;
            break;
            case PRXYERR_R_KEY_CERT_MISMATCH:
                 retval = GSSERR_PRXY_R_KEY_CERT_MISMATCH;
            break;
            case PRXYERR_R_WRONG_PASSPHRASE:
                 retval = GSSERR_PRXY_R_WRONG_PASSPHRASE;
            break;
            case PRXYERR_R_PROBLEM_CLIENT_CA:
                 retval = GSSERR_PRXY_R_PROBLEM_CLIENT_CA;
            break;
            case PRXYERR_R_CB_NO_PW:
                 retval = GSSERR_PRXY_R_CB_NO_PW;
            break;
            case PRXYERR_R_CLASS_ADD_OID:
                 retval = GSSERR_PRXY_R_CLASS_ADD_OID;
            break;
            case PRXYERR_R_CLASS_ADD_EXT:
                 retval = GSSERR_PRXY_R_CLASS_ADD_EXT;
            break;
            case PRXYERR_R_DELEGATE_VERIFY:
                 retval = GSSERR_PRXY_R_DELEGATE_VERIFY;
            break;
            case PRXYERR_R_EXT_ADD:
                 retval = GSSERR_PRXY_R_EXT_ADD;
            break;
            case PRXYERR_R_DELEGATE_COPY:
                 retval = GSSERR_PRXY_R_DELEGATE_COPY;
            break;
            case PRXYERR_R_DELEGATE_CREATE:
                 retval = GSSERR_PRXY_R_DELEGATE_CREATE;
            break;
            case PRXYERR_R_BUFFER_TOO_SMALL:
                 retval = GSSERR_PRXY_R_BUFFER_TOO_SMALL;
            break;
        }
    }
    else if (lib ==  ERR_user_lib_gsserr_number)
             retval = (unsigned long) reason;
    else if (reason == ERR_R_MALLOC_FAILURE)
             retval = (unsigned long) GSSERR_PRXY_R_MALLOC_FAILURE;
            return retval;
}
