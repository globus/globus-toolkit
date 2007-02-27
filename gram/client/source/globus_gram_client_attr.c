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

/*
globus_gram_client_attr.h

CVS Information:
    $Source$
    $Date$
    $Revision$
    $Author$
*/

#include "globus_i_gram_client.h"

/**
 * Initialize a GRAM client attribute.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     Pointer to attribute to initialize.
 *
 * @retval GLOBUS_SUCCESS
 *     Attribute was initialized successfully.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     Null value was passed in for attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Unable to allocate memory to initialize attribute.
 *
 * @see globus_gram_client_attr_destroy()
 */
int
globus_gram_client_attr_init(
    globus_gram_client_attr_t *     attr)
{
    globus_i_gram_client_attr_t *   iattr;

    if (attr == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
    }
    iattr = globus_libc_calloc(1, sizeof(globus_i_gram_client_attr_t));

    if(iattr == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    iattr->delegation_mode = GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY;

    *attr = (void*) iattr;

    return GLOBUS_SUCCESS;
}

/**
 * Destroy a GRAM client attribute.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     Pointer to attribute to destroy.
 *
 * @retval GLOBUS_SUCCESS
 *     Attribute was initialized successfully.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     Null value was passed in for attribute.
 *
 * @see globus_gram_client_attr_init()
 */
int
globus_gram_client_attr_destroy(
    globus_gram_client_attr_t *     attr)
{
    int                             rc = GLOBUS_SUCCESS;
    globus_i_gram_client_attr_t *   iattr;

    if (attr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
        goto out;
    }

    iattr = (globus_i_gram_client_attr_t *) *attr;
    if (iattr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
        goto out;
    }

    globus_libc_free(iattr);
    *attr = NULL;

out:
    return rc;
}

/**
 * Associate a credential with an attribute set.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     The attribute set to associate the credential with.
 * @param credential
 *     The credential to use.
 *
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     An invalid attribute set was passed to this function.
 *
 * @see globus_gram_client_attr_get_credential()
 */
int
globus_gram_client_attr_set_credential(
    globus_gram_client_attr_t           attr,
    gss_cred_id_t                       credential)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_i_gram_client_attr_t *       iattr;

    if (attr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
        goto out;
    }
    iattr = (globus_i_gram_client_attr_t *) attr;
    iattr->credential = credential;
out:
    return rc;
}

/**
 * Get the credential associated with an attribute set.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     The attribute set associated with the credential.
 * @param credential
 *     A pointer to a GSSAPI credential handle which will be
 *     set to the value of the credential currently associated
 *     with the attribute set.
 *
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     An invalid attribute set was passed to this function.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER
 *     A null credential pointer was passed to this function.
 *
 * @see globus_gram_client_attr_set_credential()
 */
int
globus_gram_client_attr_get_credential(
    globus_gram_client_attr_t           attr,
    gss_cred_id_t *                     credential)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_i_gram_client_attr_t *       iattr;

    iattr = (globus_i_gram_client_attr_t *) attr;

    if (iattr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;

        goto out;
    }
    if (credential == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto out;
    }
    *credential = iattr->credential;

out:
    return rc;
}

/**
 * Set the delegation mode associated with an attribute set.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     The attribute set to update.
 * @param credential
 *     The new value of the delegation mode.
 *
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     An invalid attribute set was passed to this function.
 *
 * @see globus_gram_client_attr_get_delegation_mode()
 */
int
globus_gram_client_attr_set_delegation_mode(
    globus_gram_client_attr_t           attr,
    globus_io_secure_delegation_mode_t  mode)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_i_gram_client_attr_t *       iattr;

    if (attr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
        goto out;
    }
    if (mode != GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY &&
        mode != GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;
        goto out;
    }
    iattr = (globus_i_gram_client_attr_t *) attr;
    iattr->delegation_mode = mode;
out:
    return rc;
}

/**
 * Get the delegation mode associated with an attribute set.
 * @ingroup globus_gram_client_attr
 *
 * @param attr
 *     The attribute set to query.
 * @param credential
 *     Pointer to a location to set to the value of the delegation mode.
 *
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
 *     An invalid attribute set was passed to this function.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER
 *     An null @a mode pointer was passed to this function.
 *
 * @see globus_gram_client_attr_get_delegation_mode()
 */
int
globus_gram_client_attr_get_delegation_mode(
    globus_gram_client_attr_t           attr,
    globus_io_secure_delegation_mode_t *mode)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_i_gram_client_attr_t *       iattr;

    iattr = (globus_i_gram_client_attr_t *) attr;

    if (iattr == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR;

        goto out;
    }
    if (mode == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto out;
    }
    *mode = iattr->delegation_mode;

out:
    return rc;
}
/* globus_gram_client_attr_get_delegation_mode() */
