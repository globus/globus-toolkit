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
    if(src == NULL || dst == NULL) return;
    (*dst) = (void *) malloc(sizeof(globus_l_gssapi_error_data_t));
    ((globus_l_gssapi_error_data_t *) *dst)->major_status =
        ((globus_l_gssapi_error_data_t *) src)->major_status;
    ((globus_l_gssapi_error_data_t *) *dst)->minor_status =
        ((globus_l_gssapi_error_data_t *) src)->minor_status;
    return;
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
    char *                              error_string = NULL;

    globus_gss_assist_display_status_str(
        &error_string,
        NULL,
        ((globus_l_gssapi_error_data_t *)
         globus_object_get_local_instance_data(error))->major_status,
        ((globus_l_gssapi_error_data_t *)
         globus_object_get_local_instance_data(error))->minor_status,
        0);
        
    return error_string;
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




