/**********************************************************************

display_status.c

Description:
    GSSAPI routine to display the error messages

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
#include "gssutils.h"
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

/**********************************************************************
Function:   gss_display_status

Description:
    Calls the SSLeay error ptint routines to produce a printable
	message. This may need some work, as the SSLeay error messages 
	are more of a trace, and my not be the best for the user. 
	Also don't take advantage of being called in a loop. 

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_display_status
(OM_uint32 *          minor_status,
 OM_uint32            status_value,
 int                  status_type,
 const gss_OID        mech_type,
 OM_uint32 *          message_context,
 gss_buffer_t   	  status_string)
{
	char * reason;
	unsigned long err;
	const char * fs;
	const char * rs;
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
    const char *file;
#else
    char *file;
#endif
	char * data;
#ifdef DEBUG
	char format[] = "Function:%s  Reason:%s %s\n        Source:%s:%d";
#else
	char format[] = "Function:%s  Reason:%s %s";
#endif
	int line;
	char fbuf[1024];
	char rbuf[1024];

	status_string->length = 0;
	status_string->value = NULL;
	*message_context = 0;
	*minor_status = 0;
 
	if (status_type == GSS_C_GSS_CODE) {
		if (status_value == GSS_S_COMPLETE) {
			reason = "GSS COMPLETE";
		}
		else switch (GSS_ERROR(status_value)) {
			case GSS_S_FAILURE:
				reason = "GSS_S_FAILURE - general failure";
				break;
			case GSS_S_DEFECTIVE_TOKEN:
				reason = "GSS_S_DEFECTIVE_TOKEN";
				break;
			case GSS_S_DEFECTIVE_CREDENTIAL:
				reason = "GSS_S_DEFECTIVE_CREDENTIAL - sslv3 handshake";
				break;
			case GSS_S_CREDENTIALS_EXPIRED:
				reason = "GSS_S_CREDENTIALS_EXPIRED";
				break;
			case GSS_S_BAD_NAME:
				reason = "GSS_S_BAD_NAME - globusid malformed";
				break;
			case GSS_S_UNAUTHORIZED:
				reason = "GSS_S_UNAUTHORIZED - wrong gatekeeper or service";
				break;
			case GSS_S_NO_CRED:
				reason = "GSS_S_NO_CRED - No credentials";			
				break;
			default:
				reason = "Some Other GSS failure";
				break;
		} 
		status_string->value = strdup(reason);
		status_string->length = strlen(status_string->value);
		return GSS_S_COMPLETE;
	}
		/* WIN32 does not have the ERR_get_error_line_data */ 
		/* exported, so simulate it till it is fixed */
		/* in SSLeay-0.9.0 so simulate it */
	else if (status_type == GSS_C_MECH_CODE) {
		if ((ERR_peek_error()) != 0)
		{
			int i;
			ERR_STATE *es;
			es = ERR_get_state();
			i=(es->bottom+1)%ERR_NUM_ERRORS;

			if (es->err_data[i] == NULL) {
				data = "";
			} else {
				data = es->err_data[i];
			}

            err = ERR_get_error_line(&file,&line);
			fs=ERR_func_error_string(err);
			if (fs == NULL) {
				sprintf(fbuf,"func(%u)",ERR_GET_FUNC(err));
				fs = fbuf;
			}

			rs=ERR_reason_error_string(err);
			if (rs == NULL) {
				sprintf(rbuf,"reason(%u)",ERR_GET_REASON(err));
				rs = rbuf;
			}

			status_string->length = 64 + strlen(format) + 
				strlen(fs) + strlen(rs) + strlen(data) + 
				strlen(file);
			status_string->value = 
					(char *)malloc(status_string->length);
			if (status_string->value == NULL) {
				return GSS_S_FAILURE;
			}
			
#ifdef DEBUG
			sprintf(status_string->value, format, fs, rs, data,
								 file, line);
#else
			sprintf(status_string->value, format, fs, rs, data);
#endif

			*message_context = 1;
		} else {
			status_string->value = strdup("");
			*message_context = 0;
		}

		if (status_string->value == NULL) {
			return GSS_S_FAILURE;
		}
		
		status_string->length = strlen(status_string->value);
		return GSS_S_COMPLETE;
		
	} else {
		return GSS_S_BAD_STATUS;
	}
}
