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
 * @file globus_i_error_errno.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 * 
 * @author Sam Lang
 */

#include "globus_common.h"
#include "globus_i_error_openssl.h"
#include <string.h>


/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus OpenSSL Error object.
 * @ingroup globus_openssl_error_object 
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
globus_l_error_copy_openssl(
    void *                              src,
    void **                             dst)
{
    globus_i_openssl_error_handle_t *   i_src;
    globus_i_openssl_error_handle_t *   i_dst;
    
    if(src == NULL || dst == NULL) return;

    i_src = (globus_i_openssl_error_handle_t *) src;
    i_dst = malloc(sizeof(globus_i_openssl_error_handle_t));
    
    *i_dst = *i_src;
    
    if(i_src->data && 
        (i_src->flags & ERR_TXT_MALLOCED) && 
        (i_src->flags & ERR_TXT_STRING))
    {
        i_dst->data = strdup(i_src->data);
        assert(i_dst->data);
    }
    
    *dst = i_dst;
            
    return;
}/* globus_l_error_copy_openssl */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus OpenSSL Error object.
 * @ingroup globus_openssl_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_openssl(
    void *                              data)
{
    globus_i_openssl_error_handle_destroy((globus_openssl_error_handle_t)data);
}/* globus_l_error_free_openssl */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return an allocated string of the openssl error from the instance data
 * @ingroup globus_openssl_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the openssl error if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_error_openssl_printable(
    globus_object_t *                   error)
{
    globus_openssl_error_handle_t       handle;
    char *                              error_string;
    static char *                       _function_name_ =
        "globus_l_error_openssl_printable";

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER;

    if(!error)
    {
        error_string = NULL;
        goto done;
    }

    handle = (globus_openssl_error_handle_t)
             globus_object_get_local_instance_data(error);

    if(globus_openssl_error_handle_get_data_flags(handle) & ERR_TXT_STRING)
    {
        error_string = globus_common_create_string(
            _GOESL("OpenSSL Error: %s:%d: in library: %s, function %s: %s %s"),
            globus_openssl_error_handle_get_filename(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_filename(handle),
            globus_openssl_error_handle_get_linenumber(handle),
            globus_openssl_error_handle_get_library(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_library(handle),
            globus_openssl_error_handle_get_function(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_function(handle),
            globus_openssl_error_handle_get_reason(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_reason(handle),
            globus_openssl_error_handle_get_data(handle));
    }
    else
    {
        error_string = globus_common_create_string(
            _GOESL("OpenSSL Error: %s:%d: in library: %s, function %s: %s"),
            globus_openssl_error_handle_get_filename(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_filename(handle),
            globus_openssl_error_handle_get_linenumber(handle),
            globus_openssl_error_handle_get_library(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_library(handle),
            globus_openssl_error_handle_get_function(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_function(handle),
            globus_openssl_error_handle_get_reason(handle) == NULL ? "(null)" :
            globus_openssl_error_handle_get_reason(handle));        
    }

 done:

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT;
    return error_string;
}/* globus_l_error_openssl_printable */
/*@}*/


/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_OPENSSL_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_openssl,
    globus_l_error_free_openssl,
    globus_l_error_openssl_printable);


/**
 * Initialize OpenSSL Error Handle
 * @ingroup globus_openssl_error_object
 */
/* @{ */
/**
 * Initialize an OpenSSL error handle 
 *
 * @return
 *         A newly allocated openssl error handle
 */
globus_openssl_error_handle_t
globus_i_openssl_error_handle_init()
{
    globus_openssl_error_handle_t       new_handle;
    static char *                       _function_name_ =
        "globus_openssl_error_handle_init";
    
    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER;

    new_handle = malloc(sizeof(globus_i_openssl_error_handle_t));

    assert(new_handle);
    
    memset(new_handle, (int)NULL, sizeof(globus_i_openssl_error_handle_t));

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT;

    return new_handle;
}
/* @} */

/**
 * Destroy OpenSSL Error Handle
 * @ingroup globus_openssl_error_object
 */
/* @{ */
/**
 * Destroy an OpenSSL error handle object
 *
 * @param handle
 *        The handle to destroy
 */
void
globus_i_openssl_error_handle_destroy(
    globus_openssl_error_handle_t       handle)
{
    static char *                       _function_name_ =
        "globus_openssl_error_handle_init";

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER;

    if(handle != NULL)
    {
        if(handle->data && 
           (handle->flags & ERR_TXT_MALLOCED) && 
           (handle->flags & ERR_TXT_STRING))
               
        {
            free(handle->data);
        }
        
        free(handle);
    }

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
