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



