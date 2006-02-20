/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_error_errno.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_error_errno.h"
#include "globus_i_error_generic.h"
#include "globus_object.h"
#include "globus_module.h"
#include "globus_error.h"
#include "globus_error_generic.h"
#include "globus_libc.h"
#include <string.h>

/**
 * @name Construct Error
 */
/*@{*/
/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_ERRNO
 * @ingroup globus_errno_error_object
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error, this paramater may be NULL.
 * @param system_errno
 *        The system errno.
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_error_construct_errno_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           system_errno)
{
    globus_object_t *                   error;
    globus_object_t *                   newerror;

    newerror = globus_object_construct(GLOBUS_ERROR_TYPE_ERRNO);
    error = globus_error_initialize_errno_error(
        newerror,
        base_source,
        base_cause,
        system_errno);

    if (error == NULL)
    {
        globus_object_free(newerror);
    }

    return error;
}/* globus_error_construct_errno_error() */
/*@}*/

/**
 * @name Initialize Error
 */
/*@{*/
/**
 * Initialize a previously allocated error of type
 * GLOBUS_ERROR_TYPE_ERRNO
 * @ingroup globus_errno_error_object 
 *
 * @param error
 *        The previously allocated error object.
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this paramater may be NULL.
 * @param system_errno
 *        The system errno.
 * @return
 *        The resulting error object. You may have to call
 *        globus_error_put() on this object before passing it on.
 */
globus_object_t *
globus_error_initialize_errno_error(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           system_errno)
{
    int *                               instance_data;

    instance_data = (int *) globus_malloc(sizeof(int));

    *instance_data = system_errno;

    globus_object_set_local_instance_data(error, (void *) instance_data);

    return globus_error_initialize_base(error,
                                        base_source,
                                        base_cause);
}/* globus_error_initialize_errno_error() */
/*@}*/

/**
 * @name Get Errno
 */
/*@{*/
/**
 * Retrieve the system errno from a errno error object.
 * @ingroup globus_errno_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the errno
 * @return
 *        The errno stored in the object
 */
int
globus_error_errno_get_errno(
    globus_object_t *                   error)
{
    return *((int *) globus_object_get_local_instance_data(error));
}/* globus_error_errno_get_errno */
/*@}*/

/**
 * @name Set Errno
 */
/*@{*/
/**
 * Set the errno in a errno error object.
 * @ingroup globus_errno_error_accessor  
 *
 * @param error
 *        The error object for which to set the errno
 * @param system_errno
 *        The system errno
 * @return
 *        void
 */
void
globus_error_errno_set_errno(
    globus_object_t *                   error,
    const int                           system_errno)
{
    *((int *) globus_object_get_local_instance_data(error)) = system_errno;
}/* globus_error_errno_set_errno */
/*@}*/

/**
 * @name Error Match
 */
/*@{*/
/**
 * Check whether the error originated from a specific module and
 * matches a specific errno.
 * @ingroup globus_errno_error_utility  
 *
 * This function checks whether the error or any of it's causative
 * errors originated from a specific module and contains a specific
 * errno. If the module descriptor is left unspecified this function
 * will check for any error of the specified errno and vice versa.
 *
 * @param error
 *        The error object for which to perform the check
 * @param module
 *        The module descriptor to check for
 * @param system_errno
 *        The errno to check for
 * @return
 *        GLOBUS_TRUE - the error matched the module and errno
 *        GLOBUS_FALSE - the error failed to match the module and errno
 */
globus_bool_t
globus_error_errno_match(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    int                                 system_errno)
{
    globus_module_descriptor_t *        source_module;
    int                                 current_errno;
    
    if(error == NULL)
    {
        return GLOBUS_FALSE;
    }

    if(globus_object_get_type(error) != GLOBUS_ERROR_TYPE_ERRNO)
    {
        /* not our type, skip it */
        return globus_error_errno_match(
            globus_error_get_cause(error),
            module,
            system_errno);
    }

    source_module = globus_error_get_source(error);
    current_errno = globus_error_errno_get_errno(error);
    
    if(source_module == module && current_errno == system_errno)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return globus_error_errno_match(
            globus_error_get_cause(error),
            module,
            system_errno);
    }
}/* globus_error_errno_match */
/*@}*/


/**
 * @name Wrap Errno Error
 */
/*@{*/
/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_GLOBUS
 * which contains a causal error of type GLOBUS_ERROR_TYPE_ERRNO.
 * @ingroup globus_errno_error_utility  
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param system_errno
 *        The errno to use when generating the causal error.
 * @param type
 *        The error type. We may reserve part of this namespace for
 *        common errors. Errors not in this space are assumed to be
 *        local to the originating module.
 * @param source_file
 *        Name of file.  Use __FILE__
 * @param source_func
 *        Name of function.  Use _globus_func_name and declare your func with
 *        GlobusFuncName(<name>)
 * @param source_line
 *        Line number.  Use __LINE__
 * @param short_desc_format
 *        Short format string giving a succinct description
 *        of the error. To be passed on to the user.
 * @param ...
 *        Arguments for the format string.
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_error_wrap_errno_error(
    globus_module_descriptor_t *        base_source,
    int                                 system_errno,
    int                                 type,
    const char *                        source_file,
    const char *                        source_func,
    int                                 source_line,
    const char *                        short_desc_format,
    ...)
{
    globus_object_t *                   causal_error;
    globus_object_t *                   error;
    va_list                             ap;

    causal_error = globus_error_construct_errno_error(
        base_source,
        NULL,
        system_errno);

    if(!causal_error)
    {
        return GLOBUS_NULL;
    }
    
    va_start(ap, short_desc_format);
    
    error = globus_error_v_construct_error(
        base_source,
        causal_error,
        type,
        source_file,
        source_func,
        source_line,
        short_desc_format,
        ap);

    va_end(ap);
    
    if(error == GLOBUS_NULL)
    {
        globus_object_free(causal_error);
    }
    
    return error;
    
}/* globus_error_wrap_errno_error */
/*@}*/




