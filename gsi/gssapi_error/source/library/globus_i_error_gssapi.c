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
 * @file globus_i_error_gssapi.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "globus_i_error_gssapi.h"
#include <string.h>
#include "globus_gss_assist.h"

/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus GSSAPI Error object.
 * @ingroup globus_gssapi_error_object 
 * 
 * @param src
 *        The source instance data
 * @param dst
 *        The destination instance data
 * @return
 *        void
 */
static
void
globus_l_error_copy_gssapi(
    void *                              src,
    void **                             dst)
{
    globus_l_gssapi_error_data_t *      copy;
    globus_l_gssapi_error_data_t *      data;
    
    if(src == NULL || dst == NULL) return;
    
    data = (globus_l_gssapi_error_data_t *) src;
    copy = (globus_l_gssapi_error_data_t *)
        globus_malloc(sizeof(globus_l_gssapi_error_data_t));
    if(copy)
    {
        copy->major_status = data->major_status;
        copy->minor_status = data->minor_status;
        copy->is_globus_gsi = data->is_globus_gsi;
    }
    
    *dst = copy;
}/* globus_l_error_copy_gssapi */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus GSSAPI Error object.
 * @ingroup globus_gssapi_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_gssapi(
    void *                              data)
{
    globus_libc_free(data);
}/* globus_l_error_free_gssapi */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_gssapi_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_error_gssapi_printable(
    globus_object_t *                   error)
{
    OM_uint32	                        minor_status;
    OM_uint32                           message_context;
    gss_buffer_desc                     status_string_desc 
        = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                        status_string = &status_string_desc;
    char *                              msg = NULL;
    char *                              tmp;
    int                                 len = 0;
    globus_l_gssapi_error_data_t *      data;
    
    data = (globus_l_gssapi_error_data_t *)
         globus_object_get_local_instance_data(error);
    
    if(data->is_globus_gsi)
    {
        message_context = 0;
        do
        {
            if(gss_display_status(&minor_status,
                                   data->major_status,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NO_OID,
                                   &message_context,
                                   status_string) == GSS_S_COMPLETE)
            {
                if(status_string->length)
                {
                    if(msg)
                    {
                        tmp = globus_realloc(
                            msg,
                            sizeof(char) * (len + status_string->length + 1));
                    }
                    else
                    {
                        tmp = globus_malloc(
                            sizeof(char) * (status_string->length + 1));
                    }
                    if(tmp)
                    {
                        memcpy(
                            tmp + len,
                            status_string->value,
                            status_string->length);
                        msg = tmp;
                        len += status_string->length;
                    }
                }
                gss_release_buffer(&minor_status, status_string);
            }
        } while(message_context != 0);
        
        if(msg)
        {
            if(msg[len - 1] == '\n')
            {
                len--;
            }
            msg[len] = '\0';
        }
    }
    else
    {
        globus_gss_assist_display_status_str(
            &msg, NULL, data->major_status, data->minor_status, 0);
    }
    
    return msg;
}/* globus_l_error_gssapi_printable */
/*@}*/

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_GSSAPI_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_gssapi,
    globus_l_error_free_gssapi,
    globus_l_error_gssapi_printable);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */




