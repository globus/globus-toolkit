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
    if(src == NULL || dst == NULL) return;
    (*dst) = (void *) malloc(sizeof(globus_i_openssl_error_handle_t));
    *((globus_openssl_error_handle_t) *dst) 
        = *((globus_openssl_error_handle_t) src);
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

    error_string = globus_error_openssl_create_error_string(
        "OpenSSL Error: %s:%d: in library: %s, function %s: %s",
        globus_openssl_error_handle_get_filename(handle) == NULL ? "(null)" :
        globus_openssl_error_handle_get_filename(handle),
        globus_openssl_error_handle_get_linenumber(handle),
        globus_openssl_error_handle_get_library(handle) == NULL ? "(null)" :
        globus_openssl_error_handle_get_library(handle),
        globus_openssl_error_handle_get_function(handle) == NULL ? "(null)" :
        globus_openssl_error_handle_get_function(handle),
        globus_openssl_error_handle_get_reason(handle) == NULL ? "(null)" :
        globus_openssl_error_handle_get_reason(handle));

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
        free(handle);
    }

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

char *
globus_error_openssl_create_error_string(
    const char *                        format,
    ...)
{
    int                                 len;
    va_list                             ap;
    char *                              error_string;
    static char *                       _function_name_ =
        "globus_error_openssl_create_string";

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER;

    va_start(ap, format);

    len = globus_libc_vprintf_length(format,ap);

    va_end(ap);

    len++;

    if((error_string = malloc(len)) == NULL)
    {
        return NULL;
    }

    va_start(ap, format);
    
    globus_libc_vsnprintf(error_string,
                          len,
                          format,
                          ap);
    va_end(ap);

    GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT;
    return error_string;
}
