#ifndef GLOBUS_INCLUDE_OPENSSL_ERROR_H
#define GLOBUS_INCLUDE_OPENSSL_ERROR_H


/**
 * @anchor globus_openssl_error_api
 * @defgroup globus_openssl_error_api Globus OPENSSL Error API
 * @ingroup globus_error_api
 *
 * These globus_openssl_error functions provide a wrapper to error
 * types defined by OpenSSL
 *
 * Any program that uses Globus OpenSSL Error functions must include
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
 * @defgroup globus_openssl_error_object Error Construction
 * @ingroup globus_openssl_error_api
 *
 * Create and initialize a Globus OpenSSL Error object.
 *
 * This section defines operations to create and initialize Globus
 * OpenSSLError objects.
 */


/**
 * @defgroup globus_gsi_openssl_error_activation Activation
 *
 * Globus GSI OpenSSL Error uses standard Globus module activation and
 * deactivation. Before any Globus GSI OpenSSL Error functions are called, the
 * following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus GSI OpenSSL Error was
 * successfully initialized, and you are therefore allowed to
 * subsequently call Globus GSI OpenSSL Error functions.  Otherwise, an error
 * code is returned, and Globus GSI OpenSSL Error functions should not be
 * subsequently called. This function may be called multiple times.
 *
 * To deactivate Globus GSI OpenSSL Error, the 
 * following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GSI OpenSSL Error
 * was activated. 
 *
 */

/** Module descriptor
 * @ingroup globus_gsi_openssl_error_activation
 * @hideinitializer
 */
#define GLOBUS_GSI_OPENSSL_ERROR_MODULE (&globus_i_gsi_openssl_error_module)

extern
globus_module_descriptor_t		globus_i_gsi_openssl_error_module;


#ifndef DOXYGEN

globus_object_t *
globus_error_wrap_openssl_error(
    globus_module_descriptor_t *        base_source,
    char *                              openssl_error_string,
    int                                 error_type,
    char *                              error_description);

#endif

EXTERN_C_END
#endif /* GLOBUS_INCLUDE_OPENSSL_ERROR_H */
