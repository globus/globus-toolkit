#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_error_gssapi.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_error_gssapi.h"
#include <string.h>

/**
 * @name Construct Error
 */
/*@{*/
/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_GSSAPI
 * @ingroup globus_gssapi_error_object
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error, this paramater may be NULL.
 * @param major_status
 *        The GSSAPI major status
 * @param minor_status
 *        The GSSAPI minor status
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_error_construct_gssapi_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const OM_uint32                      major_status,
    const OM_uint32                      minor_status)
{
    globus_object_t *                   error;
    globus_object_t *                   newerror;

    newerror = globus_object_construct(GLOBUS_ERROR_TYPE_GSSAPI);
    error = globus_error_initialize_gssapi_error(
        newerror,
        base_source,
        base_cause,
        major_status,
        minor_status);

    if (error == NULL)
    {
        globus_object_free(newerror);
    }

    return error;
}/* globus_error_construct_gssapi_error() */
/*@}*/

/**
 * @name Initialize Error
 */
/*@{*/
/**
 * Initialize a previously allocated error of type
 * GLOBUS_ERROR_TYPE_GSSAPI
 * @ingroup globus_gssapi_error_object 
 *
 * @param error
 *        The previously allocated error object.
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this paramater may be NULL.
 * @param major_status
 *        The GSSAPI major status
 * @param minor_status
 *        The GSSAPI minor status
 * @return
 *        The resulting error object. You may have to call
 *        globus_error_put() on this object before passing it on.
 */
globus_object_t *
globus_error_initialize_gssapi_error(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const OM_uint32                     major_status,
    const OM_uint32                     minor_status)
{
    globus_l_gssapi_error_data_t *      instance_data;

    instance_data = (globus_l_gssapi_error_data_t *)
        malloc(sizeof(globus_l_gssapi_error_data_t));

    instance_data->major_status = major_status;

    instance_data->minor_status = minor_status;

    globus_object_set_local_instance_data(error, (void *) instance_data);

    return globus_error_initialize_base(error,
                                        base_source,
                                        base_cause);
}/* globus_error_initialize_gssapi_error() */
/*@}*/

/**
 * @name Get Major Status
 */
/*@{*/
/**
 * Retrieve the major status from a gssapi error object.
 * @ingroup globus_gssapi_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the major status
 * @return
 *        The major status stored in the object
 */
OM_uint32
globus_error_gssapi_get_major_status(
    globus_object_t *                   error)
{
    return ((globus_l_gssapi_error_data_t *)
            globus_object_get_local_instance_data(error))->major_status;
}/* globus_error_gssapi_get_major_status */
/*@}*/

/**
 * @name Set Major Status
 */
/*@{*/
/**
 * Set the major status in a gssapi error object.
 * @ingroup globus_gssapi_error_accessor  
 *
 * @param error
 *        The error object for which to set the major status
 * @param major_status
 *        The major status
 * @return
 *        void
 */
void
globus_error_gssapi_set_major_status(
    globus_object_t *                   error,
    const OM_uint32                     major_status)
{
    ((globus_l_gssapi_error_data_t *)
     globus_object_get_local_instance_data(error))->major_status = major_status;
}/* globus_error_gssapi_set_major_status */
/*@}*/

/**
 * @name Get Minor Status
 */
/*@{*/
/**
 * Retrieve the minor status from a gssapi error object.
 * @ingroup globus_gssapi_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the minor status
 * @return
 *        The minor status stored in the object
 */
OM_uint32
globus_error_gssapi_get_minor_status(
    globus_object_t *                   error)
{
    return ((globus_l_gssapi_error_data_t *)
            globus_object_get_local_instance_data(error))->minor_status;
}/* globus_error_gssapi_get_minor_status */
/*@}*/

/**
 * @name Set Minor Status
 */
/*@{*/
/**
 * Set the minor status in a gssapi error object.
 * @ingroup globus_gssapi_error_accessor  
 *
 * @param error
 *        The error object for which to set the minor status
 * @param minor_status
 *        The minor status
 * @return
 *        void
 */
void
globus_error_gssapi_set_minor_status(
    globus_object_t *                   error,
    const OM_uint32                     minor_status)
{
    ((globus_l_gssapi_error_data_t *)
     globus_object_get_local_instance_data(error))->minor_status = minor_status;
}/* globus_error_gssapi_set_minor_status */
/*@}*/

/**
 * @name Error Match
 */
/*@{*/
/**
 * Check whether the error originated from a specific module and
 * matches a specific major status.
 * @ingroup globus_gssapi_error_utility  
 *
 * This function checks whether the error or any of it's causative
 * errors originated from a specific module and contains a specific
 * major status. If the module descriptor is left unspecified this
 * function  will check for any error of the specified major_status
 * and vice versa. 
 *
 * @param error
 *        The error object for which to perform the check
 * @param module
 *        The module descriptor to check for
 * @param major_status
 *        The major status to check for
 * @return
 *        GLOBUS_TRUE - the error matched the module and major status
 *        GLOBUS_FALSE - the error failed to match the module and
 *        major status
 */
globus_bool_t
globus_error_gssapi_match(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    const OM_uint32                     major_status)
{
    globus_module_descriptor_t *        source_module;
    int                                 current_major_status;
    
    if(error == NULL)
    {
        return GLOBUS_FALSE;
    }

    if(globus_object_get_type(error) != GLOBUS_ERROR_TYPE_GSSAPI)
    {
        /* not our type, skip it */
        return globus_error_gssapi_match(
            globus_error_get_cause(error),
            module,
            major_status);
    }

    source_module = globus_error_get_source(error);
    current_major_status = globus_error_gssapi_get_major_status(error);
    
    if(source_module == module && current_major_status == major_status)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return globus_error_gssapi_match(
            globus_error_get_cause(error),
            module,
            major_status);
    }
}/* globus_error_gssapi_match */
/*@}*/


/**
 * @name Wrap GSSAPI Error
 */
/*@{*/
/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_GLOBUS
 * which contains a causal error of type GLOBUS_ERROR_TYPE_GSSAPI.
 * @ingroup globus_gssapi_error_utility  
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param major_status
 *        The major status to use when generating the causal error.
 * @param minor_status
 *        The minor status to use when generating the causal error.
 * @param type
 *        The error type. We may reserve part of this namespace for
 *        common errors. Errors not in this space are assumed to be
 *        local to the originating module.
 * @param short_desc
 *        Short context sensitive string giving a succinct description
 *        of the error. To be passed on to the user.
 * @param long_desc
 *        Longer context sensitive string giving a more detailed
 *        explanation of the error.
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_error_wrap_gssapi_error(
    globus_module_descriptor_t *        base_source,
    const OM_uint32                     major_status,
    const OM_uint32                     minor_status,
    const int                           type,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   causal_error;

    causal_error = globus_error_construct_gssapi_error(
        base_source,
        NULL,
        major_status,
        minor_status);

    if(!causal_error)
    {
        return GLOBUS_NULL;
    }

    return globus_error_construct_error(
        base_source,
        causal_error,
        type,
        short_desc,
        long_desc);
    
}/* globus_error_wrap_gssapi_error */
/*@}*/




