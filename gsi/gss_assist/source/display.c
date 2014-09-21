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
 * @file display.c
 * @author Sam Lang, Sam Meder
 */
#endif

#include "gssapi.h"
#include "globus_i_gss_assist.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @ingroup globus_gss_assist_display
 * Concatenate the four message strings, realloc if needed.
 *
 * @param str  
 *        char * to string or NULL (reallocated if needed)
 * @param pre
 *        char * to first string or NULL
 * @param msg
 *        char * (may not be null terminated) to first string or NULL
 * @param msglen
 *        length of msg
 * @param post
 *        char * to last string or NULL
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
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * @ingroup globus_gss_assist_display
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
 * @param token_status
 *        token status to display
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
/* globus_gss_assist_display_status() */

/**
 * @ingroup globus_gss_assist_display
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
 * @param token_status
 *        token status to display
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
                                    comment ? comment : _GASL("GSS failure: "),
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
            reason1 = _GASL("read failure:");
        }
        else if (GSS_CALLING_ERROR(major_status) ==
                   GSS_S_CALL_INACCESSIBLE_WRITE)
        {
            reason1 = _GASL("write failure:");
        }
        else
        {
            reason1 = _GASL("failure:");
        }

        if (token_status > 0)
        {
            switch (token_status)
            {
              case GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC:
                reason2 = _GASL("malloc failed");
                break;
              case GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE:
                reason2 = _GASL("token length invalid");
                break;
              case GLOBUS_GSS_ASSIST_TOKEN_EOF:
                reason2 = _GASL("Connection closed");
                break;
              default:
                reason2 = _GASL("unknown");
                break;
            }
        }
        else
        {
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) && !defined(__MINGW32__)
            char errbuf[80] = {0};

            strerror_r(-token_status, errbuf, sizeof(errbuf));
            reason2 = errbuf;
#else
            reason2 = strerror(-token_status);
#endif
            if (reason2 == NULL)
            {
                reason2 = _GASL("unknown");
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
/* globus_gss_assist_display_status_str() */
