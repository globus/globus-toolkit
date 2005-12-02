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


#ifndef GLOBUS_ERROR_H
#define GLOBUS_ERROR_H

#include "globus_common_include.h"
#include "globus_object.h"
#include "globus_module.h"

#if defined(HAVE_INTTYPES_H) && !defined(TARGET_ARCH_CYGWIN)
#include <inttypes.h>  
#endif

#if defined(UINT_LEAST32_MAX)
typedef uint_least32_t globus_uint_t;
#elif SIZEOF_LONG == 4
typedef unsigned long globus_uint_t;
#elif SIZEOF_SHORT == 4
typedef unsigned short globus_uint_t;
#else
typedef unsigned int globus_uint_t;
#endif

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
 
EXTERN_C_BEGIN

/**********************************************************************
 * Error API Types
 *   globus_result_t          --   used as error object handle
 **********************************************************************/

/**********************************************************************
 * Error Creation API
 **********************************************************************/

extern globus_object_t *
globus_error_initialize_base (
    globus_object_t *                   error,
    globus_module_descriptor_t *        source_module,
    globus_object_t *                   causal_error);

extern globus_object_t *
globus_error_construct_base (
    globus_module_descriptor_t *        source_module,
    globus_object_t *                   causal_error);

#define globus_error_type_static_initializer(parent_type,                   \
                                             copy_func,                     \
                                             destructor,                    \
                                             string_func)                   \
        globus_object_type_static_initializer ((parent_type),               \
                                               (copy_func),                 \
                                               (destructor),                \
                                               ((void *) string_func))


/**********************************************************************
 * Standard Error Type
 *    ERROR_TYPE_BASE
 **********************************************************************/

extern const globus_object_type_t GLOBUS_ERROR_TYPE_BASE_DEFINITION;
#define GLOBUS_ERROR_TYPE_BASE (&GLOBUS_ERROR_TYPE_BASE_DEFINITION)

/**********************************************************************
 * Standard Error Prototype
 *    ERROR_NO_INFO  (type GLOBUS_ERROR_TYPE_BASE)
 **********************************************************************/

extern globus_object_t GLOBUS_ERROR_BASE_STATIC_PROTOTYPE;
#define GLOBUS_ERROR_BASE_PROTOTYPE (&GLOBUS_ERROR_BASE_STATIC_PROTOTYPE)

#define GLOBUS_ERROR_NO_INFO GLOBUS_ERROR_BASE_PROTOTYPE

/**********************************************************************
 * Error Management API
 **********************************************************************/

extern globus_object_t *
globus_error_get(
    globus_result_t                     result);
/* returns corresponding object for result,
 * may return GLOBUS_ERROR_NO_INFO */

extern globus_object_t *
globus_error_peek(
    globus_result_t                     result);
/* returns pointer to object for result DOES NOT REMOVE object.
 * This pointer is only valid for the current thread and until another call to
 * globus_error_peek is made
 * may return GLOBUS_ERROR_NO_INFO
 */

extern globus_result_t
globus_error_put(
    globus_object_t *                   error);
/* does nothing if error is NULL */

/**********************************************************************
 * Error Manipulation API
 **********************************************************************/

extern globus_module_descriptor_t *
globus_error_base_get_source (
    globus_object_t *                   error);

extern void
globus_error_base_set_source (
    globus_object_t *                   error,
    globus_module_descriptor_t *        source_module);

extern globus_object_t *
globus_error_base_get_cause (
    globus_object_t *                   error);

extern void
globus_error_base_set_cause (
    globus_object_t *                   error,
    globus_object_t *                   causal_error);



#if 0
/**********************************************************************
 * Error Callback API
 **********************************************************************/

typedef void
(*globus_error_callback_func_t)(
    globus_module_descriptor_t *        source,
    globus_object_t *                   error,
    void *                              user_data);

extern void
globus_error_callback_register(
    globus_module_descriptor_t *        source,
    globus_error_callback_func_t        callback,
    void *                              user_data,
    long *                              registered_id);

extern void
globus_error_callback_unregister(
    long                                registered_id);

extern void
globus_error_signal_fault (
    globus_module_descriptor_t *        source,
    globus_object_t *                   error);
#endif /* 0 */

#include GLOBUS_THREAD_INCLUDE
extern globus_bool_t globus_i_error_verbose;
extern globus_thread_key_t globus_i_error_verbose_key;

/**********************************************************************
 * Module definition
 **********************************************************************/

extern globus_module_descriptor_t globus_i_error_module;

#define GLOBUS_ERROR_MODULE (&globus_i_error_module)



EXTERN_C_END

#endif /* GLOBUS_ERROR_H */



