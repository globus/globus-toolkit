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


#ifndef DOXYGEN

globus_object_t *
globus_error_get_openssl_error(
    globus_module_descriptor_t *        base_source,
    char *                              openssl_error,
    int                                 error_type,
    char *                              error_description);

globus_object_t *
globus_error_wrap_openssl_error(
    globus_module_descriptor_t *        base_source,
    const unsigned long                 error_code,
    const char *                        filename,
    const int                           linenumber,
    char *                              openssl_error,
    int                                 error_type,
    char *                              error_description);

#endif

EXTERN_C_END
#endif /* GLOBUS_INCLUDE_OPENSSL_ERROR_H */
