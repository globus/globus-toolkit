#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_error_generic.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_object.h"
#include "globus_module.h"
#include "globus_error_generic.h"
#include "globus_i_error_generic.h"
#include "globus_error.h"
#include "globus_libc.h"
#include <string.h>

/**
 * @name Construct Error
 */
/*@{*/
/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_GLOBUS
 * @ingroup globus_generic_error_object
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this paramater may be NULL.
 * @param type
 *        The error type. We may reserve part of this namespace for
 *        common errors. Errors not in this space are assumed to be
 *        local to the originating module.
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
globus_error_construct_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           type,
    const char *                        short_desc_format,
    ...)
{
    globus_object_t *                   error;
    globus_object_t *                   newerror;
    va_list                             ap;

    va_start(ap, short_desc_format);

    newerror = globus_object_construct(GLOBUS_ERROR_TYPE_GLOBUS);
    error = globus_error_initialize_error(
        newerror,
        base_source,
        base_cause,
        type,
        short_desc_format,
        ap);

    va_end(ap);
    if (error == NULL)
    {
        globus_object_free(newerror);
    }

    return error;
}/* globus_error_construct_error() */

/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_GLOBUS
 * @ingroup globus_generic_error_object
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this paramater may be NULL.
 * @param type
 *        The error type. We may reserve part of this namespace for
 *        common errors. Errors not in this space are assumed to be
 *        local to the originating module.
 * @param short_desc_format
 *        Short format string giving a succinct description
 *        of the error. To be passed on to the user.
 * @param ap
 *        Arguments for the format string.
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_error_v_construct_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           type,
    const char *                        short_desc_format,
    va_list                             ap)
{
    globus_object_t *                   error;
    globus_object_t *                   newerror;

    newerror = globus_object_construct(GLOBUS_ERROR_TYPE_GLOBUS);
    error = globus_error_initialize_error(
        newerror,
        base_source,
        base_cause,
        type,
        short_desc_format,
        ap);

    if (error == NULL)
    {
        globus_object_free(newerror);
    }

    return error;
}/* globus_error_v_construct_error() */
/*@}*/

/**
 * @name Initialize Error
 */
/*@{*/
/**
 * Initialize a previously allocated error of type
 * GLOBUS_ERROR_TYPE_GLOBUS
 * @ingroup globus_generic_error_object 
 *
 * @param error
 *        The previously allocated error object.
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this paramater may be NULL.
 * @param type
 *        The error type. We may reserve part of this namespace for
 *        common errors. Errors not in this space are assumed to be
 *        local to the originating module.
 * @param short_desc_format
 *        Short format string giving a succinct description
 *        of the error. To be passed on to the user.
 * @param ap
 *        Arguments for the format string.
 * @return
 *        The resulting error object. You may have to call
 *        globus_error_put() on this object before passing it on.
 */
globus_object_t *
globus_error_initialize_error(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           type,
    const char *                        short_desc_format,
    va_list                             ap)
{
    globus_l_error_data_t *             instance_data;
    int                                 size;
    va_list                             ap_copy;
    
    instance_data = (globus_l_error_data_t *)
        malloc(sizeof(globus_l_error_data_t));

    if(instance_data == NULL)
    {
        return NULL;
    }
    
    memset((void *) instance_data,0,sizeof(globus_l_error_data_t));

    instance_data->type = type;

    if(short_desc_format != NULL)
    {
        globus_libc_va_copy(ap_copy,ap);
        size = globus_libc_vprintf_length(short_desc_format,ap_copy);
        va_end(ap_copy);

        size++;
        
        if ((instance_data->short_desc = malloc (size)) == NULL)
        {
            return NULL;
        }
        
        globus_libc_vsnprintf(instance_data->short_desc,
                              size,
                              short_desc_format,
                              ap);
    }

    globus_object_set_local_instance_data(error, instance_data);

    return globus_error_initialize_base(error,
                                        base_source,
                                        base_cause);
}/* globus_error_initialize_error() */
/*@}*/

/**
 * @name Get Source
 */
/*@{*/
/**
 * Retrieve the originating module descriptor from a error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the module descriptor
 * @return
 *        The originating module descriptor.
 */
globus_module_descriptor_t *
globus_error_get_source(
    globus_object_t *                   error)
{
    return globus_error_base_get_source(error);
}/* globus_error_get_source */
/*@}*/

/**
 * @name Set Source
 */
/*@{*/
/**
 * Set the originating module descriptor in a error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error object for which to set the causative error
 * @param source_module
 *        The originating module descriptor
 * @return
 *        void
 */
void
globus_error_set_source(
    globus_object_t *                   error,
    globus_module_descriptor_t *        source_module)
{
    globus_error_base_set_source(error,source_module);
}/* globus_error_set_source */
/*@}*/

/**
 * @name Get Cause
 */
/*@{*/
/**
 * Retrieve the underlying error from a error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the causative error.
 * @return
 *        The underlying error object if it exists, NULL if it
 *        doesn't.
 */
globus_object_t *
globus_error_get_cause (
    globus_object_t *                   error)
{
    return globus_error_base_get_cause(error);
}/* globus_error_get_cause */
/*@}*/


/**
 * @name Set Cause
 */
/*@{*/
/**
 * Set the causative error in a error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error object for which to set the causative error.
 * @param causal_error
 *        The causative error.
 * @return
 *        void
 */
void
globus_error_set_cause (
    globus_object_t *                   error,
    globus_object_t *                   causal_error)
{
    globus_error_base_set_cause(error,causal_error);
}/* globus_error_set_cause */
/*@}*/


/**
 * @name Get Type
 */
/*@{*/
/**
 * Retrieve the error type from a generic globus error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the error type
 * @return
 *        The error type of the object
 */
int
globus_error_get_type(
    globus_object_t *                   error)
{
    return     ((globus_l_error_data_t *)
                globus_object_get_local_instance_data(error))->type;
}/* globus_error_get_type */
/*@}*/

/**
 * @name Set Type
 */
/*@{*/
/**
 * Set the error type in a generic globus error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error object for which to set the error type
 * @param type
 *        The error type
 * @return
 *        void
 */
void
globus_error_set_type(
    globus_object_t *                   error,
    const int                           type)
{
    ((globus_l_error_data_t *)
     globus_object_get_local_instance_data(error))->type = type;
}/* globus_error_set_type */
/*@}*/


/**
 * @name Get Short Description
 */
/*@{*/
/**
 * Retrieve the short error description from a generic globus error
 * object. 
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the description
 * @return
 *        The short error description of the object
 */
char *
globus_error_get_short_desc(
    globus_object_t *                   error)
{
    return globus_libc_strdup(
        ((globus_l_error_data_t *)
         globus_object_get_local_instance_data(error))->short_desc);
}/* globus_error_get_short_desc */
/*@}*/

/**
 * @name Set Short Description
 */
/*@{*/
/**
 * Set the short error description in a generic globus error object. 
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error object for which to set the description
 * @param short_desc_format
 *        Short format string giving a succinct description
 *        of the error. To be passed on to the user.
 * @param ...
 *        Arguments for the format string.
 * @return
 *        void
 */
void
globus_error_set_short_desc(
    globus_object_t *                   error,
    const char *                        short_desc_format,
    ...)
{
    char **                             instance_short_desc;
    va_list                             ap;
    int                                 size;
    
    instance_short_desc =
        &((globus_l_error_data_t *)
          globus_object_get_local_instance_data(error))->short_desc;
    
    if(*instance_short_desc != NULL)
    {
        globus_libc_free(*instance_short_desc);
    }

    *instance_short_desc = NULL;

    va_start(ap, short_desc_format);

    size = globus_libc_vprintf_length(short_desc_format,ap);

    va_end(ap);
    
    size++;

    if ((*instance_short_desc = malloc (size)) == NULL)
    {
        return;
    }

    va_start(ap, short_desc_format);
    
    globus_libc_vsnprintf(*instance_short_desc,
                          size,
                          short_desc_format,
                          ap);

    va_end(ap);
    
    return;
}/* globus_error_set_short_desc */
/*@}*/


/**
 * @name Get Long Description
 */
/*@{*/
/**
 * Retrieve the long error description from a generic globus error
 * object. 
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error from which to retrieve the description
 * @return
 *        The long error description of the object
 */
char *
globus_error_get_long_desc(
    globus_object_t *                   error)
{
    return globus_libc_strdup(
        ((globus_l_error_data_t *)
         globus_object_get_local_instance_data(error))->long_desc);
}/* globus_error_get_long_desc */
/*@}*/

/**
 * @name Set Long Description
 */
/*@{*/
/**
 * Set the long error description in a generic globus error object.
 * @ingroup globus_generic_error_accessor  
 *
 * @param error
 *        The error object for which to set the description
 * @param long_desc_format
 *        Longer format string giving a more detailed explanation of
 *        the error. 
 * @return
 *        void
 */
void
globus_error_set_long_desc(
    globus_object_t *                   error,
    const char *                        long_desc_format,
    ...)
{
    char **                             instance_long_desc;
    va_list                             ap;
    int                                 size;
    
    instance_long_desc =
        &((globus_l_error_data_t *)
          globus_object_get_local_instance_data(error))->long_desc;
    
    if(*instance_long_desc != NULL)
    {
        globus_libc_free(*instance_long_desc);
    }

    *instance_long_desc = NULL;

    va_start(ap, long_desc_format);

    size = globus_libc_vprintf_length(long_desc_format,ap);

    va_end(ap);

    size++;

    if ((*instance_long_desc = malloc (size)) == NULL)
    {
        return;
    }

    va_start(ap, long_desc_format);

    globus_libc_vsnprintf(*instance_long_desc,
                          size,
                          long_desc_format,
                          ap);
    va_end(ap);
    
    return;
}/* globus_error_set_long_desc */
/*@}*/


/**
 * @name Error Match
 */
/*@{*/
/**
 * Check whether the error originated from a specific module and is of
 * a specific type.
 * @ingroup globus_generic_error_utility  
 *
 * This function checks whether the error or any of it's causative
 * errors originated from a specific module and is of a specific
 * type. If the module descriptor is left unspecified this function
 * will check for any error of the specified type and vice versa.
 *
 * @param error
 *        The error object for which to perform the check
 * @param module
 *        The module descriptor to check for
 * @param type
 *        The type to check for
 * @return
 *        GLOBUS_TRUE - the error matched the module and type
 *        GLOBUS_FALSE - the error failed to match the module and type
 */
globus_bool_t
globus_error_match(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    int                                 type)
{
    globus_module_descriptor_t *        source_module;
    int                                 error_type;
    
    if(error == NULL)
    {
        return GLOBUS_FALSE;
    }

    if(globus_object_get_type(error) != GLOBUS_ERROR_TYPE_GLOBUS)
    {
        /* not our type, skip it */
        return globus_error_match(
            globus_error_get_cause(error),
            module,
            type);
    }

    source_module = globus_error_get_source(error);
    error_type = globus_error_get_type(error);
    
    if(source_module == module && error_type == type)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return globus_error_match(
            globus_error_get_cause(error),
            module,
            type);
    }
}/* globus_error_match */
/*@}*/


/**
 * @name Print Error Chain
 */
/*@{*/
/**
 * Return a string containing all printable errors found in a error
 * object and it's causative error chain.
 * @ingroup globus_generic_error_utility  
 *
 * @param error
 *        The error to print
 * @return
 *        A string containing all printable errors. This string needs
 *        to be freed by the user of this function.
 */
char *
globus_error_print_chain(
    globus_object_t *                   error)
{
    char *                              error_string;
    char *                              tmp;
    int                                 length = 1;
    globus_object_t *                   current_error;

    current_error = error;

    error_string = globus_libc_malloc(1);

    error_string[0] = '\0';
    
    do
    {
        tmp = globus_object_printable_to_string(current_error);
        
        if(tmp != NULL)
        {
            length += 1 + strlen(tmp);
            error_string = (char *) globus_libc_realloc(
                error_string, length);
            strcat(error_string,"\n");
            strcat(error_string,tmp);
            globus_libc_free(tmp);
        }
    }
    while(current_error = globus_error_get_cause(current_error));
    
    if(!strlen(error_string))
    {
        globus_libc_free(error_string);
        error_string = NULL;
    }

    return error_string;
}/* globus_error_print_chain */
/*@}*/
















