 /******************************************************************************
init.c

Description:
    Globus GSSAPI Assist routine for the gss_init_sec_context


CVS Information:
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "assist_config.h"
#include "globus_gss_assist.h"
#include <stdio.h>
#include <gssapi.h>
#include <string.h>
/******************************************************************************
                               Type definitions
******************************************************************************/

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
/******************************************************************************
                       Define module specific variables
******************************************************************************/


/******************************************************************************
Function:   globus_gss_assist_strcatr()
Description:
	concat the four messages, and realloc if needed.

Parameters:
	str  - char * to string or null (realloacted if needed)
	pre  - char * to first string or null
	msg  - char * (may not be null terminated) to first string or null
	msglen - length of msgring or null
	post - char * to last string or null

Returns:
	char * to reallocated string.  NULL on error

******************************************************************************/

static char *
globus_gss_assist_strcatr
(char *             str,
 char *             pre,
 char *             msg,
 int                msglen,
 char *             post)
{
	char * new;
	int len;

	len = 1 + (str ? strlen(str) : 0)
			+ (pre ? strlen(pre) : 0)
			+ (msg ? msglen : 0)
			+ (post ? strlen(post) : 0);
			
	if (str)
		new = (char *)realloc(str,len);
	else 
	{
		new = (char *)malloc(len);
		if (new) 
			*new = '\0';
	}
	if (new)
	{
		if (pre)
			strcat(new,pre);
		if (msg)
			strncat(new,msg,msglen);
		if (post)
			strcat(new,post);
	}
 	return new;
}

/******************************************************************************
Function:   globus_gss_assist_display_status()
Description:
	Display the messages for the major and minor status
	on the file pointed at by fp.
	Takes care of the overloaded major_status if there
	was a problem with the get_token or send_token routines.

Parameters:
	fp - a file pointer 
	comment - String to print out before other error messages. 
	major_status
	minor_status

Returns:
	0 

******************************************************************************/

OM_uint32
globus_gss_assist_display_status
(FILE * 			fp,
 char *				comment,
 OM_uint32 			major_status,
 OM_uint32 			minor_status,
 int                token_status)
{
	OM_uint32	ret;
	char *		msg = NULL;
	
	ret = globus_gss_assist_display_status_str(&msg,
								comment,
								major_status,
								minor_status,
								token_status);
	if (ret == 0)
		fprintf(fp,"%s",msg);
	free(msg);
	return ret;
}

/******************************************************************************
Function:   globus_gss_assist_display_status_str()
Description:
	Display the messages for the major and minor status
	and return a string with the messages. 
	Takes care of the overloaded major_status if there
	was a problem with the get_token or send_token routines.

Parameters:
	str - pointer to char * for returned string. Must be freed
	comment - String to print out before other error messages. 
	major_status
	minor_status

Returns:
	0 

******************************************************************************/

OM_uint32
globus_gss_assist_display_status_str
(char ** 			str,
 char *				comment,
 OM_uint32 			major_status,
 OM_uint32 			minor_status,
 int                token_status)
{
 OM_uint32	minor_status2;
 OM_uint32  message_context;
 gss_buffer_desc status_string_desc = GSS_C_EMPTY_BUFFER;
 gss_buffer_t  status_string = &status_string_desc;
 char *reason1=(char *) 0;
 char *reason2=(char *) 0;
 char buf[1024];

 char * msg = NULL;

 if (!str)
	return GSS_S_FAILURE;

	msg = globus_gss_assist_strcatr(msg,
						comment ? comment : "GSS failure: ",
						NULL,0,
						"\n");

	sprintf(buf,
			"    GSS status: major:%8.8x minor: %8.8x token: %8.8x\n",
			major_status, minor_status, token_status);
	msg = globus_gss_assist_strcatr(msg,buf,NULL,0,NULL);

	if (major_status) {
		message_context = 0;
		do {

			if (gss_display_status(&minor_status2,
                           major_status,
                           GSS_C_GSS_CODE,
                           GSS_C_NO_OID,
                           &message_context,
                           status_string) == GSS_S_COMPLETE) {
				if (status_string->length) {
					msg = globus_gss_assist_strcatr(msg,
						"    ",
						(char *) status_string->value,
						status_string->length,
						"\n");
				}
			}
			gss_release_buffer(&minor_status2, status_string);
		} while (message_context != 0);
	}

	/* make no assumptions about minor status */

	message_context = 0;
	do {

		if (gss_display_status(&minor_status2,
                            minor_status,
                            GSS_C_MECH_CODE,
                            GSS_C_NO_OID,
                            &message_context,
                            status_string) == GSS_S_COMPLETE) {
			if (status_string->length) {
				msg = globus_gss_assist_strcatr(msg,
						"    ",
						(char *) status_string->value,
						status_string->length,
						"\n");
			}
		}
		gss_release_buffer(&minor_status2, status_string);
	} while (message_context != 0);

	if (token_status != 0) {
		if (GSS_CALLING_ERROR(major_status) ==
				GSS_S_CALL_INACCESSIBLE_READ) {
			reason1 = "read failure:";
	    } else if (GSS_CALLING_ERROR(major_status) == 
				GSS_S_CALL_INACCESSIBLE_WRITE) {
			reason1 = "write failure:";
		} else {
			reason1 = "failure:";
		}
		if (token_status > 0) {
			switch (token_status) {
				case GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC:
					reason2 = "malloc failed";
					break;
				case GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE:
					reason2 = "token length invalid";
					break;
				case GLOBUS_GSS_ASSIST_TOKEN_EOF:
					reason2 = "Connection closed";
					break;
				default:
					reason2 = "unknown";
					break;
			}
		} else {
#                       if defined(HAVE_STRERROR)
			{
			    reason2 = strerror(-token_status);
			}
#			endif
			if (reason2 == NULL) {
				reason2 = "unknown";
			}
		}
		sprintf(buf,"    globus_gss_assist token :%d: %s %s\n",
							token_status,  reason1, reason2);
			msg = globus_gss_assist_strcatr(msg,
						buf,
						NULL,0,
						NULL);

	}

	*str = msg;
	return 0;
}
