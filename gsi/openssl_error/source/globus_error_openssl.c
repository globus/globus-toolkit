#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_error_openssl.c
 * @author Sam Lang
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 *
 */
#endif

#include "globus_error_openssl.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_gsi_openssl_error_activate(void);
static int globus_l_gsi_openssl_error_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t              globus_i_gsi_openssl_error_module =
{
    "globus_gsi_openssl_error",
    globus_l_gsi_openssl_error_activate,
    globus_l_gsi_openssl_error_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_openssl_error_activate(void)
{
    /* initializes arrays for the error handling library with
     * messages specific to the ERR library.
     */
    ERR_load_ERR_strings();

    /* loads the error strings for all parts of the crypto library */
    ERR_load_crypto_strings();

    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 */
static
int
globus_l_gsi_openssl_error_deactivate(void)
{
    /* frees all error strings loaded into the static error table
     * that maps library/function/reason codes to text strings
     */
    ERR_free_strings();
    return GLOBUS_SUCCESS;
}

#endif

/**
 * @name Wrap OpenSSL Error
 */
/* @{ */
/**
 * Wrap the OpenSSL error and create a
 * wrapped globus error object from
 * the error.  This function gets all the openssl errors
 * from the error list, and chains them using the globus
 * error string object.  The resulting globus error object
 * is a wrapper to the openssl error at the end of the chain.
 *
 * @param base_source
 *        The module that the error was generated from
 * @param openssl_error_string
 *        The error string constaining the line number and filename
 *        where the error occurred
 * @param error_type
 *        The type of error encapsulating the openssl error
 * @param error_description
 *        A description of the error entry point where the
 *        openssl error occurred
 * @return The globus error object.  A globus_result_t
 *         object can be created using the globus_error_put
 *         function
 *
 * @see globus_error_put()
 */
globus_object_t *
globus_error_wrap_openssl_error(
    globus_module_descriptor_t *        base_source,
    char *                              openssl_error_string,
    int                                 error_type,
    char *                              error_description)
{
    unsigned long                       error_code;
    char *                              filename;
    int                                 linenumber;
    globus_object_t *                   temp_openssl_error = NULL;

    error_code = ERR_get_error_line(&filename, &linenumber);

    if(error_code == 0)
    {
        return globus_error_construct_error(
            base_source,
            NULL,
            error_type,
            openssl_error,
            "Expected an OpenSSL error.  OpenSSL Error NOT FOUND");
    }

    /* loop for chaining openssl errors together */
    while(error_code != 0)
    {
        temp_openssl_error = globus_error_construct_string(
            base_source,
            temp_openssl_error,
            "OpenSSL Error: %s:%s: %s in %s:%d",
            ERR_lib_error_string(error_code),
            ERR_func_error_string(error_code),
            ERR_reason_error_string(error_code),
            filename,
            linenumber);

        if(!temp_openssl_error)
        {
            return GLOBUS_NULL;
        }

        error_code = ERR_get_error_line(&filename, &linenumber);
    }

    /* there shouldn't be any more errors in the 
     * static stack, but just in case...
     */
    ERR_clear_error();

    return globus_error_construct_error(
        base_source,
        temp_openssl_error, 
        error_type,
        openssl_error,
        error_description);
}
