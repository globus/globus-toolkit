#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file display.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include <stdio.h>
#include "gssapi.h"
#include <string.h>
#include <stdlib.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @name globus_gss_assist_strcatr
 * @ingroup globus_i_gsi_gss_assist
 */
/* @{ */
/**
 * Concatenate the four message strings, realloc if needed.
 *
 *
 * @param str  
 *        char * to string or null (realloacted if needed)
 * @param pre
 *        char * to first string or null
 * @param msg
 *        char * (may not be null terminated) to first string or null
 * @param msglen
 *        length of msgring or null
 * @param post
 *        char * to last string or null
 *
 * @return
 *        char * to reallocated string.  NULL on error
 */
static char *
globus_gss_assist_strcatr(
    char *                              str,
    char *                              pre,
    char *                              msg,
    int                                 msglen,
    char *                              post)
{
    char *                              new;
    int                                 len;
    static char *                       _function_name_ =
        "globus_gss_assist_strcatr";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    len = 1 + (str ? strlen(str) : 0)
        + (pre ? strlen(pre) : 0)
        + (msg ? msglen : 0)
        + (post ? strlen(post) : 0);

    if (str)
    { 
        new = (char *)realloc(str,len);
        if(!new)
        {
            new = malloc(len);
            if(new)
            {
                *new = '\0';
                strcat(new, str);
                free(str);
            }
        }
    }
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

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return new;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * @name Display Status
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * Display the messages for the major and minor status
 * on the file pointed at by fp.
 * Takes care of the overloaded major_status if there
 * was a problem with the get_token or send_token routines.
 *
 * @param fp
 *        a file pointer
 * @param comment
 *        String to print out before other error messages.
 * @param major_status
 *        The major status to display
 * @param minor_status
 *        The minor status to display
 * @return 
 *        0
 */
OM_uint32
globus_gss_assist_display_status(
    FILE * 			        fp,
    char *				comment,
    OM_uint32                           major_status,
    OM_uint32 			        minor_status,
    int                                 token_status)
{
    OM_uint32	                        ret;
    char *		                msg = NULL;
    static char *                       _function_name_ =
        "globus_gss_assist_display_status";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    ret = globus_gss_assist_display_status_str(&msg,
                                               comment,
                                               major_status,
                                               minor_status,
                                               token_status);
    if (ret == 0)
        fprintf(fp, "%s", msg);
    free(msg);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return ret;
}
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @name Display Status String
 * @ingroup globus_i_gsi_gss_assist
 */
/* @{ */
/**
 * Display the messages for the major and minor status
 * and return a string with the messages.
 * Takes care of the overloaded major_status if there
 * was a problem with the get_token or send_token routines.
 *
 * @param str
 *        pointer to char * for returned string. Must be freed
 * @param comment
 *        String to print out before other error messages.
 * @param major_status
 *        The major status to display
 * @param minor_status
 *        The minor status to display
 *
 * @return
 *        0
 */
OM_uint32
globus_gss_assist_display_status_str(
    char ** 			        str,
    char *				comment,
    OM_uint32 			        major_status,
    OM_uint32 			        minor_status,
    int                                 token_status)
{
    OM_uint32	                        minor_status2;
    OM_uint32                           message_context;
    gss_buffer_desc                     status_string_desc 
        = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                        status_string = &status_string_desc;
    char *                              reason1 = (char *) 0;
    char *                              reason2 = (char *) 0;
    char                                buf[1024];
    char *                              msg = NULL;
    char *                              tmp;
    static char *                       _function_name_ =
        "globus_gss_assist_display_status_str";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    if (!str)
    { 
	return GSS_S_FAILURE;
    }

    *str = NULL;
    
    msg = globus_gss_assist_strcatr(msg,
                                    comment ? comment : "GSS failure: ",
                                    NULL,0,
                                    "\n");
    if(!msg)
    {
        return GSS_S_FAILURE;
    }
    
    if(token_status == 0)
    { 
        message_context = 0;
        do {
            if (gss_display_status(&minor_status2,
                                   major_status,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NO_OID,
                                   &message_context,
                                   status_string) == GSS_S_COMPLETE)
            {
                if (status_string->length)
                {
                    tmp = globus_gss_assist_strcatr(
                        msg, "",
                        (char *) status_string->value,
                        status_string->length, "");
                    if(!tmp)
                    {
                        free(msg);
                        return GSS_S_FAILURE;
                    }
                    msg = tmp;
                }
                gss_release_buffer(&minor_status2, status_string);
            }
        }
        while (message_context != 0);

        /* make no assumptions about minor status */

        message_context = 0;
        do {
            if (gss_display_status(&minor_status2,
                                   minor_status,
                                   GSS_C_MECH_CODE,
                                   GSS_C_NO_OID,
                                   &message_context,
                                   status_string) == GSS_S_COMPLETE)
            {
                if (status_string->length)
                {
                    tmp = globus_gss_assist_strcatr(
                        msg, "",
                        (char *) status_string->value,
                        status_string->length, "");
                    if(!tmp)
                    {
                        free(msg);
                        return GSS_S_FAILURE;
                    }
                    msg = tmp;
                }
                gss_release_buffer(&minor_status2, status_string);            
            }
        }
        while (message_context != 0);
    }
    else
    {
        if (GSS_CALLING_ERROR(major_status) ==
            GSS_S_CALL_INACCESSIBLE_READ)
        {
            reason1 = "read failure:";
        }
        else if (GSS_CALLING_ERROR(major_status) ==
                   GSS_S_CALL_INACCESSIBLE_WRITE)
        {
            reason1 = "write failure:";
        }
        else
        {
            reason1 = "failure:";
        }

        if (token_status > 0)
        {
            switch (token_status)
            {
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
        }
        else
        {
#ifdef HAVE_STRERROR
            {
                reason2 = strerror(-token_status);
            }
#endif
            if (reason2 == NULL)
            {
                reason2 = "unknown";
            }
        }
        sprintf(buf,"    globus_gss_assist token :%d: %s %s\n",
                token_status,  reason1, reason2);
        tmp = globus_gss_assist_strcatr(msg,
                                        buf,
                                        NULL,0,
                                        NULL);
        if(!tmp)
        {
            free(msg);
            return GSS_S_FAILURE;
        }
        msg = tmp;
    }
    
    *str = msg;

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return 0;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
