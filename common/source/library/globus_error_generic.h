#ifndef GLOBUS_INCLUDE_GENERIC_ERROR_H
#define GLOBUS_INCLUDE_GENERIC_ERROR_H


/**
 * @anchor globus_generic_error_api
 * @mainpage Globus Generic Error API
 *
 * These globus_error functions are motivated by the desire to provide
 * a easier way of generating new error types, while at the same time
 * preserving all features (e.g. memory management, chaining) of the
 * current error handling framework. It does this by defining a
 * generic error type for globus which in turn contains a integer in
 * it's instance data which is used for carrying the actual error type
 * information.
 *
 * Any program that uses Globus Generic Error functions must include
 * "globus_common.h". 
 *
 * @htmlonly
 * <a href="main.html" target="_top">View documentation without frames</a><br>
 * <a href="index.html" target="_top">View documentation with frames</a><br>
 * @endhtmlonly
 */

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

/**
 * @defgroup globus_generic_error_object Error Construction
 *
 * Create and initialize a Globus Generic Error object.
 *
 * This section defines operations to create and initialize Globus
 * Generic Error objects.
 */


/** Error type definition
 * @ingroup globus_generic_error_object
 * @hideinitializer
 */
#define GLOBUS_ERROR_TYPE_GLOBUS (&GLOBUS_ERROR_TYPE_GLOBUS_DEFINITION)

extern const globus_object_type_t GLOBUS_ERROR_TYPE_GLOBUS_DEFINITION;

#ifndef DOXYGEN

globus_object_t *
globus_error_construct_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           type,
    const char *                        short_desc,
    const char *                        long_desc);

globus_object_t *
globus_error_initialize_error(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           type,
    const char *                        short_desc,
    const char *                        long_desc);

#endif

/**
 * @defgroup globus_generic_error_accessor Error Data Accessors and Modifiers
 *
 * Get and set data in a Globus Generic Error object.
 *
 * This section defines operations for accessing and modifying data in a Globus
 * Generic Error object.
 */

#ifndef DOXYGEN

globus_module_descriptor_t *
globus_error_get_source(
    globus_object_t *                   error);

void
globus_error_set_source(
    globus_object_t *                   error,
    globus_module_descriptor_t *        source_module);

globus_object_t *
globus_error_get_cause (
    globus_object_t *                   error);

void
globus_error_set_cause (
    globus_object_t *                   error,
    globus_object_t *                   causal_error);

int
globus_error_get_type(
    globus_object_t *                   error);

void
globus_error_set_type(
    globus_object_t *                   error,
    const int                           type);

char *
globus_error_get_short_desc(
    globus_object_t *                   error);

void
globus_error_set_short_desc(
    globus_object_t *                   error,
    const char *                        short_desc);

char *
globus_error_get_long_desc(
    globus_object_t *                   error);

void
globus_error_set_long_desc(
    globus_object_t *                   error,
    const char *                        long_desc);

#endif

/**
 * @defgroup globus_generic_error_utility Error Handling Helpers
 *
 * Helper functions for dealing with Globus Generic Error objects.
 *
 * This section defines utility functions for dealing with Globus
 * Generic Error objects.
 */

#ifndef DOXYGEN

globus_bool_t
globus_error_match(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    int                                 type);

char *
globus_error_print_chain(
    globus_object_t *                   error);

#endif

EXTERN_C_END
#endif /* GLOBUS_INCLUDE_GENERIC_ERROR_H */






