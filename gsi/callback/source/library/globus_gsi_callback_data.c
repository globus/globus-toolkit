#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_callback_data.c
 * Globus GSI Callback Data
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif


#include "globus_i_gsi_callback.h"
#include "globus_gsi_callback_constants.h"
#include <openssl/x509.h>

globus_result_t
globus_gsi_callback_data_init(
    globus_gsi_callback_data_t *        callback_data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_init";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(callback_data == NULL)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL pointer to callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    *callback_data = malloc(sizeof(globus_i_gsi_callback_data_t));
    if(*callback_data == NULL)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                GLOBUS_GSI_CALLBACK_MODULE,
                errno,
                GLOBUS_GSI_CALLBACK_ERROR_ERRNO,
                "Error allocating space (malloc) for callback data"));
        goto exit;
    }

    memset(*callback_data, (int) NULL, sizeof(globus_i_gsi_callback_data_t));

    (*callback_data)->max_proxy_depth = -1;
    
    (*callback_data)->cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_EEC;

    (*callback_data)->cert_chain = sk_X509_new_null();

    (*callback_data)->error = GLOBUS_SUCCESS;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_data_destroy(
    globus_gsi_callback_data_t          callback_data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_destroy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        goto exit;
    }

    if(callback_data->cert_chain)
    { 
        sk_X509_pop_free(callback_data->cert_chain, X509_free); 
    } 
    
    if(callback_data->cert_dir)
    {
        globus_libc_free(callback_data->cert_dir);
    }

    /* extension_oids have to be free independantly */

    globus_object_free(globus_error_get(callback_data->error));

    globus_libc_free(callback_data);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}   

globus_result_t
globus_gsi_callback_data_copy(
    globus_gsi_callback_data_t     source,
    globus_gsi_callback_data_t *   dest)
{
    int                                 index;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_copy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!source)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL callback data source parameter passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!dest)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL callback data dest parameter passed to function: %s",
             _function_name_));
        goto exit;
    }        

    globus_gsi_callback_data_init(dest);

    (*dest)->cert_depth = source->cert_depth;
    (*dest)->proxy_depth = source->proxy_depth;
    (*dest)->cert_type = source->cert_type;
    (*dest)->cert_chain = sk_X509_new_null();

    for(index = 0; index < sk_X509_num(source->cert_chain); ++index)
    {
        if(!sk_X509_insert((*dest)->cert_chain,
                           X509_dup(sk_X509_value(source->cert_chain, index)),
                           index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CERT_CHAIN,
                ("Couldn't copy cert chain from callback data"));
            goto exit;
        }
    }

    (*dest)->multiple_limited_proxy_ok = source->multiple_limited_proxy_ok;
    (*dest)->cert_dir = strdup(source->cert_dir);
    (*dest)->extension_cb = source->extension_cb;

    /* just copy the pointer location - these get created
     * and destroyed in gss code
     */
    (*dest)->extension_oids = source->extension_oids;

    (*dest)->error = source->error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

int globus_gsi_callback_openssl_new(
    void *                              parent, 
    void *                              ptr, 
    CRYPTO_EX_DATA *                    ad,
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_new";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* init app specific data (callback data)
     * since we can't allocate the ptr here
     * this function isn't particularly useful
     */
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

int globus_gsi_callback_openssl_free(
    void *                              parent, 
    void *                              ptr, 
    CRYPTO_EX_DATA *                    ad,
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_free";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* free the callback data - currently not used*/

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

int globus_gsi_callback_openssl_dup(
    CRYPTO_EX_DATA *                    to, 
    CRYPTO_EX_DATA *                    from, 
    void *                              from_d,                   
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_dup";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* copy the callback data - currenlty not used by OpenSSL */

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_cert_depth(
    globus_gsi_callback_data_t          callback_data,
    int *                               cert_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_depth";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!cert_depth)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter cert_depth passed to function: %s",
             _function_name_));
        goto exit;
    }

    *cert_depth = callback_data->cert_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_cert_depth(
    globus_gsi_callback_data_t          callback_data,
    int                                 cert_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_depth";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->cert_depth = cert_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_proxy_depth(
    globus_gsi_callback_data_t          callback_data,
    int *                               proxy_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_proxy_depth";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!proxy_depth)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter proxy_depth passed to function: %s",
             _function_name_));
        goto exit;
    }

    *proxy_depth = callback_data->proxy_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_proxy_depth(
    globus_gsi_callback_data_t          callback_data,
    int                                 proxy_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_proxy_depth";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->proxy_depth = proxy_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
    
globus_result_t
globus_gsi_callback_get_cert_type(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_cert_utils_cert_type_t * cert_type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_limited_proxy";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!cert_type)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter cert_type passed to function: %s",
             _function_name_));
        goto exit;
    }

    *cert_type = callback_data->cert_type;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_cert_type(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_cert_utils_cert_type_t   cert_type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_type";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->cert_type = cert_type;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_cert_chain(
    globus_gsi_callback_data_t          callback_data,
    STACK_OF(X509) **                   cert_chain)
{
    int                                 index;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_chain";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!cert_chain)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter cert_chain passed to function: %s",
             _function_name_));
        goto exit;
    }

    *cert_chain = sk_X509_new_null();

    for(index = 0; index < sk_X509_num(callback_data->cert_chain); ++index)
    {
        if(!sk_X509_insert(
            *cert_chain,
            X509_dup(sk_X509_value(callback_data->cert_chain, index)),
            index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
                ("Couldn't copy cert chain in callback data"));
            goto exit;
        }
    }

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
        
globus_result_t
globus_gsi_callback_set_cert_chain(
    globus_gsi_callback_data_t          callback_data,
    STACK_OF(X509) *                    cert_chain)
{
    int                                 index;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_chain";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }
    
    if(callback_data->cert_chain) 
    { 
        sk_X509_pop_free(callback_data->cert_chain, X509_free); 
        callback_data->cert_chain = NULL; 
    } 

    callback_data->cert_chain = sk_X509_new_null();
    
    for(index = 0; index < sk_X509_num(cert_chain); ++index)
    {
        if(!sk_X509_insert(callback_data->cert_chain,
                           X509_dup(sk_X509_value(cert_chain, index)),
                           index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
                ("Couldn't set the cert chain in the callback_data"));
            goto exit;
        }
    }

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_multiple_limited_proxy_ok(
    globus_gsi_callback_data_t          callback_data,
    int *                               multiple_limited_proxy_ok)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_multiple_limited_proxy_ok";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!multiple_limited_proxy_ok)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter peer_cert_chain passed to function: %s",
             _function_name_));
        goto exit;
    }

    *multiple_limited_proxy_ok = callback_data->multiple_limited_proxy_ok;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_multiple_limited_proxy_ok(
    globus_gsi_callback_data_t          callback_data,
    int                                 multiple_limited_proxy_ok)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_multiple_limited_proxy_ok";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->multiple_limited_proxy_ok = multiple_limited_proxy_ok;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_extension_oids(
    globus_gsi_callback_data_t          callback_data,
    void **                             extension_oids)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_extension_oids";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!extension_oids)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter extension_oids passed to function: %s",
             _function_name_));
        goto exit;
    }

    *extension_oids = callback_data->extension_oids;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_extension_oids(
    globus_gsi_callback_data_t          callback_data,
    void *                              extension_oids)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_extension_oids";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->extension_oids = extension_oids;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_cert_dir(
    globus_gsi_callback_data_t          callback_data,
    char **                             cert_dir)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_dir";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!cert_dir)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter cert_dir passed to function: %s",
             _function_name_));
        goto exit;
    }

    *cert_dir = strdup(callback_data->cert_dir);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_cert_dir(
    globus_gsi_callback_data_t          callback_data,
    char *                              cert_dir)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_dir";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->cert_dir = strdup(cert_dir);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_extension_cb(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_extension_callback_t *   extension_cb)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_goodtill";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    if(!extension_cb)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter extension_cb passed to function: %s",
             _function_name_));
        goto exit;
    }

    *extension_cb = callback_data->extension_cb;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_extension_cb(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_extension_callback_t     extension_cb)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_extension_cb";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->extension_cb = extension_cb;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_get_error(
    globus_gsi_callback_data_t          callback_data,
    globus_result_t *                   error)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_error";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    *error = callback_data->error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_callback_set_error(
    globus_gsi_callback_data_t          callback_data,
    globus_result_t                     error)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_error";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            ("NULL parameter callback_data passed to function: %s",
             _function_name_));
        goto exit;
    }

    callback_data->error = error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
