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

#include "gssapi_ssleay.h"


static ERR_STRING_DATA gsserr_str_reasons[]= 
{
 {GSSERR_R_HANDSHAKE, "SSLv3 handshake problems"},
 {GSSERR_R_NO_GLOBUSID, "globusid not found"},
 {GSSERR_R_PROCESS_CERT, "getting cert subject name"},
 {GSSERR_R_MUTUAL_AUTH, "Mutual authentication failed"},
 {GSSERR_R_WRAP_BIO, "internal problem with SSL BIO"},
 {GSSERR_R_PROXY_VIOLATION, "Peer is using (limited) proxy"},
 {GSSERR_R_PROXY_NOT_RECEIVED, "Failed to receive proxy request"},
 {GSSERR_R_BAD_ARGUMENT, "Bad argument"},
 {GSSERR_R_BAD_NAME, "Bad GSS name"},
 {GSSERR_R_IMPEXP_BIO_SSL, "Internal SSL problem"},
 {GSSERR_R_IMPEXP_NO_CIPHER, "Cipher not available"},
 {GSSERR_R_IMPEXP_BAD_LEN, "Token is wrong length"},
 {GSSERR_R_ADD_EXT, "Unable to add extension"},
 {GSSERR_R_EXPORT_FAIL, "Unable to marshal credential for export"},
 {GSSERR_R_IMPORT_FAIL, "Unable to read credential for import"},
 {GSSERR_R_READ_BIO, "Input Error"},
 {GSSERR_R_WRITE_BIO, "Output Error"},
 {GSSERR_R_UNEXPECTED_FORMAT, "Not in expected Format"},
 {GSSERR_R_BAD_DATE, "Cannot verify message date"},
 {GSSERR_R_BAD_MECH, "Requested mechanism not supported"},
 {GSSERR_R_REMOTE_CERT_VERIFY_FAILED, "remote side did not "
  "like my creds for unknown reason\n     check server logs for details"},
 {GSSERR_R_OUT_OF_MEMORY, "Out of memory"},
 {GSSERR_R_UNORDERED_CHAIN, "Cert chain not in signing order"},
 {0,NULL}
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
    i = ERR_load_prxyerr_strings(i);
    ERR_load_strings(ERR_USER_LIB_GSSERR_NUMBER, gsserr_str_functs);
    ERR_load_strings(ERR_USER_LIB_GSSERR_NUMBER, gsserr_str_reasons);
	return i;
}


/**********************************************************************
Function: gsi_generate_minor_status()

Description:
    Get the last error put into the openssl error routines and
    generate a minor status code for returning from a GSSAPI
    function.

    If the error was from one of our libraries (i.e. gssapi, sslutils,
    or scutils) then we know the reason is unique and we can just
    return it.

    If the error was not from one of our libraries (i.e. from an
    underlying openssl library), then set the top bit to 1 (to make
    sure it doesn't conflict with any of the error codes from
    our libraries and return it as is.

Parameters:
    None.

Returns:
    Minor status.
**********************************************************************/

OM_uint32
gsi_generate_minor_status()
{
    unsigned long                       error;
    int                                 lib;
    int                                 reason;
    OM_uint32                           minor_status;


    /* Get last error reported to openssl error handler */
    error = ERR_peek_error();
    
    /* Break it down and get library it came from and reason code */
    lib = ERR_GET_LIB(error);

    reason = ERR_GET_REASON(error);

    /* Libraries less than ERR_LIB_USER are openssl libraries */
    if (lib < ERR_LIB_USER)
    {
        /*
         * Error from a openssl library, flag it
         */
        minor_status = error | GSI_SSL_ERROR_FLAG;
    }
    else
    {
        /*
         * Error from one of our libraries, return reason code.
         */
        minor_status = reason;
    }
    
    return minor_status;
}
