#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_error_generic.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "globus_i_error_generic.h"
#include "globus_libc.h"
#include "globus_object.h"
#include "globus_error.h"

/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus Generic Error object.
 * @ingroup globus_generic_error_object 
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
globus_l_error_copy_globus(
    void *                              src,
    void **                             dst)
{
    if(src == NULL || dst == NULL) return;
    (*dst) = (void *) malloc(sizeof(globus_l_error_data_t));
    ((globus_l_error_data_t *) *dst)->type =
        ((globus_l_error_data_t *) src)->type;

    memset(*dst,0,sizeof(globus_l_error_data_t));

    ((globus_l_error_data_t *) *dst)->short_desc =
            globus_libc_strdup(((globus_l_error_data_t *) src)->short_desc);

    ((globus_l_error_data_t *) *dst)->short_desc =
        globus_libc_strdup(((globus_l_error_data_t *) src)->long_desc);
}/* globus_l_error_copy_globus */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus Generic Error object.
 * @ingroup globus_generic_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_globus(
    void *                              data)
{
    if(((globus_l_error_data_t *) data)->short_desc)
    {
        globus_libc_free(((globus_l_error_data_t *) data)->short_desc);
    }

    if(((globus_l_error_data_t *) data)->long_desc)
    {
        globus_libc_free(((globus_l_error_data_t *) data)->long_desc);
    }
    
    globus_libc_free(data);
}/* globus_l_error_free_globus */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_generic_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_error_globus_printable(
    globus_object_t *                   error)
{
    return globus_libc_strdup(
        ((globus_l_error_data_t *)
         globus_object_get_local_instance_data(error))->short_desc);
}/* globus_l_error_globus_printable */
/*@}*/

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_GLOBUS_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_globus,
    globus_l_error_free_globus,
    globus_l_error_globus_printable);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

