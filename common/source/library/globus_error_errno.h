#ifndef GLOBUS_INCLUDE_ERRNO_ERROR_H
#define GLOBUS_INCLUDE_ERRNO_ERROR_H


/**
 * @anchor globus_errno_error_api
 * @mainpage Globus Errno Error API
 *
 * These globus_error functions are motivated by the desire to provide
 * a easier way of generating new error types, while at the same time
 * preserving all features (e.g. memory management, chaining) of the
 * current error handling framework. It does this by defining a
 * errno error type for globus which in turn contains a integer in
 * it's instance data which is used for carrying the actual error type
 * information.
 *
 * Any program that uses Globus Errno Error functions must include
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
 * @defgroup globus_errno_error_object Error Construction
 *
 * Create and initialize a Globus Errno Error object.
 *
 * This section defines operations to create and initialize Globus
 * Errno Error objects.
 */


/** Error type definition
 * @ingroup globus_errno_error_object
 * @hideinitializer
 */
#define GLOBUS_ERROR_TYPE_ERRNO (&GLOBUS_ERROR_TYPE_ERRNO_DEFINITION)

extern const globus_object_type_t GLOBUS_ERROR_TYPE_ERRNO_DEFINITION;

#ifndef DOXYGEN

globus_object_t *
globus_error_construct_errno_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           system_errno);

globus_object_t *
globus_error_initialize_errno_error(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    const int                           system_errno);

#endif

/**
 * @defgroup globus_errno_error_accessor Error Data Accessors and Modifiers
 *
 * Get and set data in a Globus Errno Error object.
 *
 * This section defines operations for accessing and modifying data in a Globus
 * Errno Error object.
 */

#ifndef DOXYGEN

int
globus_error_errno_get_errno(
    globus_object_t *                   error);

void
globus_error_errno_set_errno(
    globus_object_t *                   error,
    const int                           system_errno);

#endif

/**
 * @defgroup globus_errno_error_utility Error Handling Helpers
 *
 * Helper functions for dealing with Globus Errno Error objects.
 *
 * This section defines utility functions for dealing with Globus
 * Errno Error objects.
 */

#ifndef DOXYGEN

globus_bool_t
globus_error_errno_match(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    int                                 system_errno);

#endif

EXTERN_C_END
#endif /* GLOBUS_INCLUDE_ERRNO_ERROR_H */






