#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_error_errno.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "globus_i_error_errno.h"
#include "globus_libc.h"
#include "globus_object.h"
#include "globus_error.h"

/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus Errno Error object.
 * @ingroup globus_errno_error_object 
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
globus_l_error_copy_errno(
    void *                              src,
    void **                             dst)
{
    if(src == NULL || dst == NULL) return;
    (*dst) = (void *) malloc(sizeof(int));
    *((int *) *dst) = *((int *) src);
    return;
}/* globus_l_error_copy_errno */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus Errno Error object.
 * @ingroup globus_errno_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_errno(
    void *                              data)
{
    globus_libc_free(data);
}/* globus_l_error_free_errno */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_errno_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_error_errno_printable(
    globus_object_t *                   error)
{
    /* strerror is not necessarily threadsafe, may need to provide
       some sort of threadsafe platform dependant wrapper for
       this. Not sure how important this is.
    */
    return globus_libc_strdup(
        strerror(*((int *)
                   globus_object_get_local_instance_data(error))));
}/* globus_l_error_errno_printable */
/*@}*/

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_ERRNO_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_errno,
    globus_l_error_free_errno,
    globus_l_error_errno_printable);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

