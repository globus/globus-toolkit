
#include "globus_i_gsi_credential.h"
#include "globus_gsi_cred_system_config.h"
#include "globus_error_generic.h"
#include "globus_gsi_proxy.h"
#include <openssl/pem.h>
#include <openssl/x509.h>

/**
 * Initialize Credential Handle Attributes
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Initializes the immutable Credential Handle Attributes
 * The handle attributes are initialized as follows:
 * 
 * ca_cert_dir - The directory containing trusted CA certificates
 * is set by first checking the environment variable X509_CERT_DIR, 
 * if that isn't, it then checks 
 * @param handle_attrs
 *        the attributes to be initialized
 * @return
 *        GLOBUS_SUCESS if initialization was successful,
 *        otherwise an error is returned
 */
globus_result_t 
globus_gsi_cred_handle_attrs_init(
    globus_gsi_cred_handle_attrs_t *    handle_attrs)
{
    char *                              error_string = NULL;
    globus_result_t                     result;

    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_init";


    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }

    if((*handle_attrs = (globus_gsi_cred_handle_attrs_t)
        globus_malloc(sizeof(globus_i_gsi_cred_handle_attrs_t))) == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS);
    }

    /* initialize all the handle attributes to NULL */
    memset(*handle_attrs, 
           (int) NULL, 
           sizeof(globus_i_gsi_cred_handle_attrs_t));
    
    result = globus_gsi_cred_get_cert_dir(
        &(*handle_attrs)->ca_cert_dir);
    if(result != GLOBUS_SUCCESS)
    {
        error_string = __FILE__":""__LINE__"
            ": error in cred_handle_attrs_init";
        goto error_exit;
    }

    /* default init is always to read a proxy */
    result = globus_gsi_cred_get_proxy_filename(&(*handle_attrs)->proxy_file,
                                                1);
    if(result != GLOBUS_SUCCESS)
    {
        error_string = __FILE__":""__LINE__"
            ": error in cred_handle_attrs_init";
        goto error_exit;
    }

    /* always sets the cert and key filenames to the user's cert and key
     * as the default.
     */
    result = globus_gsi_cred_get_user_cert_filename(
        &(*handle_attrs)->cert_file,
        &(*handle_attrs)->key_file);
    if(result != GLOBUS_SUCCESS)
    {
        error_string = __FILE__":""__LINE__"
            ": error in cred_handle_attrs_init";
        goto error_exit;
    }

    (*handle_attrs)->search_order = 
        (globus_gsi_cred_type_t *) 
        globus_malloc(sizeof(globus_gsi_cred_type_t) * 3);

    (*handle_attrs)->search_order[0] = GLOBUS_HOST;
    (*handle_attrs)->search_order[1] = GLOBUS_PROXY;
    (*handle_attrs)->search_order[2] = GLOBUS_USER;

    return GLOBUS_SUCCESS;

 error_exit:

    globus_gsi_cred_handle_attrs_destroy(*handle_attrs);

    return globus_error_put(globus_error_construct_error(
        GLOBUS_GSI_CREDENTIAL_MODULE,
        globus_error_get(result),
        GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
        globus_l_gsi_cred_error_strings[
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS],
        error_string));
}
/* globus_gsi_cred_handle_attrs_init */
/* @} */


/**
 * Destroy Credential Handle Attributes
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Destroy the Credential Handle Attributes.  This function
 * does some cleanup and deallocation of the handle attributes.
 * The attributes should be set to NULL after this function is called.
 * 
 * @param handle_attrs
 *        The handle attributes to destroy
 *
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t globus_gsi_cred_handle_attrs_destroy(
    globus_gsi_cred_handle_attrs_t     handle_attrs)
{
    if(handle_attrs != NULL)
    {
        if(handle_attrs->ca_cert_dir != NULL)
        {
            globus_free(handle_attrs->ca_cert_dir);
        }
        if(handle_attrs->proxy_file != NULL)
        {
            globus_free(handle_attrs->proxy_file);
        }
        if(handle_attrs->cert_file != NULL)
        {
            globus_free(handle_attrs->cert_file);
        }
        if(handle_attrs->key_file != NULL)
        {
            globus_free(handle_attrs->key_file);
        }
        if(handle_attrs->search_order != NULL)
        {
            globus_free(handle_attrs->search_order);
        }

        globus_free(handle_attrs);
    }
    
    return GLOBUS_SUCCESS;
}

/**
 * Copy Credential Handle Attributes
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Copy the Credential Handle Attributes. 
 *
 * @param a 
 *        The handle attribute to be copied
 * @param b
 *        The copy
 * @return
 *        GLOBUS_SUCESS unless there was an error, in which
 *        case an error object is returned.
 */
globus_result_t 
globus_gsi_cred_handle_attrs_copy(
    globus_gsi_cred_handle_attrs_t      a,
    globus_gsi_cred_handle_attrs_t *    b)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_copy";

    if(a == NULL || b == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(((*b)->ca_cert_dir = strdup(a->ca_cert_dir)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    if(((*b)->proxy_file = strdup(a->proxy_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    if(((*b)->cert_file = strdup(a->cert_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    if(((*b)->key_file = strdup(a->key_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }

    if(memcpy((*b)->search_order, 
              a->search_order) == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS);
    }

    return GLOBUS_SUCCESS;
}
/* globus_gsi_cred_handle_attrs_copy */
/* @} */
    
/** 
 * Set CA Cert Dir
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Set the Trusted CA Certificate Directory Location
 *
 * @param handle_attrs
 *        the credential handle attributes to set
 * @param ca_cert_dir
 *        the trusted ca certificates directory
 * @return
 *        GLOBUS_SUCCESS if no errors occurred.  In case of
 *        a null handle_attrs, an error object id is returned
 */
globus_result_t globus_gsi_cred_handle_attrs_set_ca_cert_dir(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              ca_cert_dir)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_set_ca_cert_dir";
    
    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if((handle_attrs->ca_cert_dir = strdup(ca_cert_dir)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get CA Cert Dir
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/** 
 * Get the trusted ca cert directory
 *
 * @param handle_attrs
 *        the credential handle attributes to get the trusted ca cert 
 *        directory from
 * @param ca_cert_dir
 *        the trusted ca certificates directory
 * @return
 *        GLOBUS_SUCCESS if no errors occurred.  In case of
 *        a null handle_attrs or pointer to ca_cert_dir, 
 *        an error object id is returned
 */
globus_result_t globus_gsi_cred_handle_attrs_get_ca_cert_dir(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             ca_cert_dir)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_get_ca_cert_dir";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if(ca_cert_dir == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    if((*ca_cert_dir = strdup(handle_attrs->ca_cert_dir)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}

/**
 * Set Proxy File
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Set the Proxy Filename of the handle attributes
 *
 * @param handle_attrs
 *        handle attributes containing the proxy filename to be set
 * @param proxy_file
 *        the proxy filename to set it to
 * @return 
 *        GLOBUS_SUCCESS if no errors occurred.  In case of
 *        a null handle_attrs, 
 *        an error object id is returned
 */
globus_result_t globus_gsi_cred_handle_attrs_set_proxy_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              proxy_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_set_proxy_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if((handle_attrs->proxy_file = strdup(proxy_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get Proxy Filename
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Get the Proxy Filename of the Credential Handle Attributes
 *
 * @param handle_attrs
 *        The handle attributes to get the proxy filename from
 * @param proxy_file
 *        The proxy filename to get
 * @return
 *        GLOBUS_SUCCESS if no error.  In case of a null handle_attrs
 *        or proxy_file is null, return an error object id
 */
globus_result_t globus_gsi_cred_handle_attrs_get_proxy_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             proxy_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_get_proxy_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if(proxy_file == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    if(*proxy_file = strdup(handle_attrs->proxy_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Set Cert File
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Set the certificate filename of the credential handle attributes
 *
 * @param handle_attrs
 *        the handle attributes holding the cert filename to be set
 * @param cert_file
 *        the new cert filename value
 * @return
 *        GLOBUS_SUCCESS if no error.  If the handle_attrs is null,
 *        an error object id is returned.
 */
globus_result_t globus_gsi_cred_handle_attrs_set_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              cert_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_set_cert_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if(handle_attrs->cert_file = strdup(cert_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get Cert File
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Get the certificate filename from the credential handle attributes
 *
 * @param handle_attrs
 *        the handle attributes to get the user certificate filename from
 * @param cert_file
 *        the filename from the handle attributes
 * @return
 *        GLOBUS_SUCCESS unless the handle_attrs or cert_file is null
 */ 
globus_result_t globus_gsi_cred_handle_attrs_get_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             cert_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_get_cert_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if(cert_file == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    if(*cert_file = strdup(handle_attrs->cert_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Set Key File
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Set the User's Key Filename
 *
 * @param handle_attrs
 *        the handle attributes to set the key filename of
 * @param key_filename
 *        the value to set it to
 * @return
 *        GLOBUS_SUCCESS unless handle_attrs is null
 */
globus_result_t globus_gsi_cred_handle_attrs_set_key_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              key_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_set_key_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if((handle_attrs->key_file = strdup(key_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get Key File
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Get the User's Key Filename
 *
 * @param handle_attrs
 *        The handle attributes containing the value of the user's key filename
 * @param key_file
 *        The resulting key filename to be set
 * @return 
 *        GLOBUS_SUCCESS unless handle_attrs or key_file is null
 */
globus_result_t globus_gsi_cred_handle_attrs_get_key_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             key_file)
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_get_key_file";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }
    
    if(key_file == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    if((*key_file = strdup(handle_attrs->key_file)) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Set Search Order
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Set the search order for finding a user certificate.  The
 * default value is {PROXY, USER, HOST}
 *
 *
 * @param handle_attrs
 *        The handle attributes to set the search order of
 * @param search_order
 *        The search order.  Should be a three element array containing
 *        in some order PROXY, USER, HOST
 * @return 
 *        GLOBUS_SUCCESS unless handle_attrs is null
 */
globus_result_t globus_gsi_cred_handle_attrs_set_search_order(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    globus_gsi_cred_type_t              search_order[])
{
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_set_search_order";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }


    size = -1;
    while(search_order[++size]);

    if((handle_attrs->search_order = 
        (globus_gsi_cred_type_t *) malloc(sizeof(globus_gsi_cred_type_t) 
                                          * (size + 1))) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }        

    for(index = 0; index <= size; ++index)
    {
        handle_attrs->search_order[index] = search_order[index];
    }

    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get Search Order
 */
/* @{ */
/**
 * Get the search order of the handle attributes
 *
 * @param handle_attrs
 *        The handle attributes to get the search order from
 * @param search_order
 *        The search_order of the handle attributes
 * @return
 *        GLOBUS_SUCCESS unless handle_attrs is null
 */
globus_result_t globus_gsi_cred_handle_attrs_get_search_order(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    globus_gsi_cred_type_t **           search_order)
{
    int                                 size;
    int                                 index;
    const char *                        _FUNCTION_NAME_ =
        "globus_gsi_cred_handle_attrs_get_search_order";

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE_ATTRS);
    }

    if(handle_attrs->search_order == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS);
    }

    size = -1;
    while(handle->search_order[++size]);

    if((*search_order = 
        (globus_gsi_cred_type_t *) malloc(sizeof(globus_gsi_cred_type_t) 
                                          * (size + 1))) == NULL)
    {
        return globus_error_wrap_errno_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            errno,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__":__LINE__:%s:%s",
            _function_name_,
            globus_l_gsi_cred_error_strings[
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS]);
    }        

    for(index = 0; index <= size; ++index)
    {
        search_order[index] = handle->search_order[index];
    }

    return GLOBUS_SUCCESS;
}
/* @} */
