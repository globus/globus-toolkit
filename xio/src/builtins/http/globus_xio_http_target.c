#include "globus_i_xio_http.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @defgroup globus_i_xio_http_target Internal Target Implementation
 */
#endif

/**
 * Allocate a new target
 * @ingroup globus_i_xio_http_target
 */
globus_i_xio_http_target_t *
globus_i_xio_http_target_new(void)
{
    return globus_libc_calloc(1, sizeof(globus_i_xio_http_target_t));
}
/* globus_l_xio_http_target_new() */

/**
 * Allocate and initialize an HTTP target
 * @ingroup globus_i_xio_http_target
 *
 * Creates a new target with default values. The new target will be used for
 * client operations. This is called by the XIO driver via
 * globus_xio_target_init().
 * 
 * @param out_driver_target
 *     Pointer value will be set to point to a
 *     newly allocated and initilized #globus_i_xio_http_target_t
 *     structure.
 * @param target_op
 *     Operation to pass the target initialization request to drivers
 *     below us in the stack.
 * @param contact_info
 *     Contact information used for this new target (ignored by this driver).
 * @param driver_attr
 *     Attributes used to create this target (ignored by this driver).
 *
 * @returns
 *     This function returns one of the following error types. Underlying
 *     drivers may generate other error types.
 * @retval GLOBUS_SUCCESS
 *     Target successfully initialized.
 * @retval GLOBUS_XIO_ERROR_MEMORY
 *     Initialization failed due to memory constraints.
 */
globus_result_t
globus_i_xio_http_target_init(
    void **                             out_driver_target,
    globus_xio_operation_t              target_op,
    const globus_xio_contact_t *        contact_info,
    void *                              driver_attr)
{
    globus_result_t                     res;
    globus_i_xio_http_target_t *        target;
    globus_xio_contact_t                new_contact_info;
    GlobusXIOName(globus_l_xio_http_target_init);

    target = globus_i_xio_http_target_new();

    if (target == NULL)
    {
        res = GlobusXIOErrorMemory("target");

        goto error_exit;
    }
    target->is_client = GLOBUS_TRUE;

    if (contact_info->host == NULL)
    {
        res = GlobusXIOErrorParameter("contact_info");

        goto free_target_exit;
    }

    target->host = globus_libc_strdup(contact_info->host);

    if (target->host == NULL)
    {
        res = GlobusXIOErrorMemory("host");

        goto free_target_exit;
    }

    if (contact_info->resource == NULL)
    {
        target->uri = globus_libc_strdup("/");
    }
    else
    {
        target->uri = globus_libc_strdup(contact_info->resource);
    }

    if (target->uri == NULL)
    {
        goto free_target_exit;
    }

    memcpy(&new_contact_info, contact_info, sizeof(globus_xio_contact_t));
    if (new_contact_info.port == 0
            && (strcmp(new_contact_info.scheme, "http")==0))
    {
        new_contact_info.port = "80";
    }
    else if (new_contact_info.port == 0
            && (strcmp(new_contact_info.scheme, "https")==0))
    {
        new_contact_info.port = "443";
    }
    res = globus_xio_driver_client_target_pass(target_op, &new_contact_info);

    if (res != GLOBUS_SUCCESS)
    {
        goto free_target_exit;
    }

    *out_driver_target = target;

    return res;

free_target_exit:
    globus_i_xio_http_target_destroy(target);
error_exit:
    return res;
}
/* globus_i_xio_http_target_init() */

/**
 * Copy the contents of an HTTP target
 * @ingroup globus_i_xio_http_target
 *
 * All values associated with the @a src target will be copied into the
 * corresponding fields of the @a dest target. If this function returns
 * a failure, then the @a dest target should be considered uninitialized.
 *
 * @param dest
 *     Target to be initialized with the values form src. This should not
 *     be initialized before this is called, or memory may be leaked.
 * @param src
 *     Target containing defined values.
 *
 * @retval GLOBUS_SUCCESS
 *     Copy successful.
 * @retval GLOBUS_XIO_ERROR_MEMORY
 *     Copy failed due to memory constraints.
 */
globus_result_t
globus_i_xio_http_target_copy(
    globus_i_xio_http_target_t *        dest,
    const globus_i_xio_http_target_t *  src)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_i_xio_http_target_copy);

    dest->is_client = src->is_client;

    if (src->host != NULL)
    {
        dest->host = globus_libc_strdup(src->host);

        if (dest->host == NULL)
        {
            res = GlobusXIOErrorMemory("host");

            goto error_exit;
        }
    }

    if (src->uri != NULL)
    {
        dest->uri = globus_libc_strdup(src->uri);

        if (dest->uri == NULL)
        {
            res = GlobusXIOErrorMemory("uri");

            goto free_host_exit;
        }
    }

    return res;

free_host_exit:
    globus_libc_free(dest->host);
    dest->host = NULL;
error_exit:
    return res;
}
/* globus_i_xio_http_target_copy() */

/**
 * Destroy an HTTP target
 * @ingroup globus_i_xio_http_target
 *
 * Frees all storage associated with an HTTP target. No further opens may
 * be alled with this target. This is called by the XIO driver via
 * globus_xio_target_destroy().
 *
 * @param driver_target
 *     Void pointer to a #globus_i_xio_http_target_t structure to be
 *     destroyed.
 *
 * @return This function always returns GLOBUS_SUCCESS.
 */
globus_result_t
globus_i_xio_http_target_destroy(
    void *                              driver_target)
{

    globus_i_xio_http_target_destroy_internal(driver_target);
    globus_libc_free(driver_target);

    return GLOBUS_SUCCESS;
}
/* globus_i_xio_http_target_destroy() */

extern
globus_result_t
globus_i_xio_http_target_destroy_internal(
    globus_i_xio_http_target_t *        target)
{
    globus_i_xio_http_target_t *        http_target = target;

    if (http_target->host != NULL)
    {
        globus_libc_free(http_target->host);
    }

    if (http_target->uri != NULL)
    {
        globus_libc_free(http_target->uri);
    }

    return GLOBUS_SUCCESS;
}
/* globus_i_xio_http_target_destroy_internal() */
