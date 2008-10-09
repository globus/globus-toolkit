/*
 * Copyright 1999-2008 University of Chicago
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

#include "xacml_i.h"

#include <dlfcn.h>
#include <iterator>

/**
 * @defgroup xacml_request Request
 * @ingroup xacml_common
 */

/**
 * Initialize an XACML query request
 * @ingroup xacml_request
 *
 * Creates an XACML request structure which can be used to generate an
 * authorization query and send it to an SAML / XACML server. After the request
 * is no longer needed, the caller must destroy it by calling
 * xacml_request_destroy().
 *
 * @param request
 *     Request to initialize. The value pointed to by this can be passed
 *     to other xacml_request_* functions.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_request_destroy().
 */
xacml_result_t
xacml_request_init(
    xacml_request_t *             request)
{
    if (request == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *request = new xacml_request_s;
    (*request)->endpoint = "";
    (*request)->subject = "";
    (*request)->return_context = false;
    (*request)->io_module = NULL;
    (*request)->io_arg = NULL;
    (*request)->connect_func = NULL;
    (*request)->close_func = NULL;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_init() */


/**
 * Destroy an XACML query request
 * @ingroup xacml_request
 *
 * Frees resources associated with an XACML request structure. After
 * calling this, the @a request value must not be used by the caller.
 *
 * @param request
 *     Request to destroy.
 *
 * @return void
 *
 * @see xacml_request_init().
 */
void
xacml_request_destroy(
    xacml_request_t               request)
{
    if (request)
    {
        if (request->io_module)
        {
            dlclose(request->io_module);
        }
        delete request;
    }
}

/**
 * Add a subject attribute to an XACML query request
 * @ingroup xacml_request
 *
 * @param request
 *     XACML query request to add the attribute to.
 * @param subject_category
 *     String defining the access subject category of this attribute. See
 *     @ref xacml_common_subject_categories for standard subject categories.
 * @param attribute_id
 *     String defining the identifier of this attribute. See
 *     @ref xacml_common_subject_attributes for standard attribute IDs.
 * @param data_type
 *     String defining the data type of the attribute's value. See
 *     @ref xacml_common_datatypes for standard XACML data type names.
 * @param issuer
 *     String defining the issuer of the attribute.
 * @param value
 *     String defining the attribute value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 */
xacml_result_t
xacml_request_add_subject_attribute(
    xacml_request_t                     request,
    const char *                        subject_category,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{

    if (request == NULL || subject_category == NULL || attribute_id == NULL ||
        data_type == NULL || value == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    xacml::attribute_set &              set = request->subjects[subject_category];
    xacml::attributes &                 attributes = set[issuer ? issuer : ""];
    xacml::attribute                    attr;

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    attributes.push_back(attr);

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_add_subject_attribute() */

/**
 * Count the number of subject attributes in XACML request
 * @ingroup xacml_request
 * Modifies the value pointed to by @a count to contain the number of
 * subject attribute in @a request. Values from 0 to the value returned
 * in @a count can be passed to xacml_request_get_subject_attribute() to
 * iterate through the set of subject attributes in a request.
 *
 * @param request
 *     XACML query request to inspect.
 * @param count
 *     Pointer to be set to the number of subject attributes.
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_get_subject_attribute()
 */
xacml_result_t
xacml_request_get_subject_attribute_count(
    const xacml_request_t               request,
    size_t *                            count)
{
    size_t                              c = 0;

    if (request == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        for (xacml::attribute_set::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            for (xacml::attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                c++;
            }
        }
    }
    *count = c;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_get_subject_attribute_count() */

/**
 * Get the value of a subject attribute
 * @ingroup xacml_request
 * Retrieves the information related to a subject attribute, based on the
 * attribute's index. The total number of subject attributes can be determined
 * by calling xacml_request_get_subject_attribute_count(). 
 * 
 * @param request
 *     The XACML query request to inspect.
 * @param num
 *     Attribute index.
 * @param subject_category
 *     Pointer to be set to the subject category of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_subject_categories for standard values this may be
 *     set to.
 * @param attribute_id
 *     Pointer to be set to the id of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_subject_attributes for standard values this may be
 *     set to.
 * @param data_type
 *     Pointer to be set to the data type of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_datatypes for standard values this may be
 *     set to.
 * @param issuer
 *     Pointer to be set to the issuer of the attribute. The caller
 *     must not modify or free this value.
 * @param value
 *     Pointer to be set to the value of the attribute. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_add_subject_attribute(),
 *      xacml_request_get_subject_attribute_count()
 */
xacml_result_t
xacml_request_get_subject_attribute(
    const xacml_request_t               request,
    size_t                              num,
    const char **                       subject_category,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value)
{
    size_t c = 0;
    
    if (request == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        for (xacml::attribute_set::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            for (xacml::attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                if (c == num)
                {
                    if (subject_category)
                    {
                        *subject_category = i->first.c_str();
                    }
                    if (issuer)
                    {
                        *issuer = j->first == "" ? NULL : j->first.c_str();
                    }
                    if (attribute_id)
                    {
                        *attribute_id = k->attribute_id.c_str();
                    }
                    if (data_type)
                    {
                        *data_type = k->data_type.c_str();
                    }
                    if (value)
                    {
                        *value = k->value.c_str();
                    }

                    return XACML_RESULT_SUCCESS;
                }
                c++;
            }
        }
    }

    if (subject_category)
    {
        *subject_category = NULL;
    }
    if (issuer)
    {
        *issuer = NULL;
    }
    if (attribute_id)
    {
        *attribute_id = NULL;
    }
    if (data_type)
    {
        *data_type = NULL;
    }
    if (value)
    {
        *value = NULL;
    }

    return XACML_RESULT_INVALID_PARAMETER;
}
/* xacml_request_get_subject_attribute() */

/**
 * Add a resource attribute set to an XACML query request
 * @ingroup xacml_request
 *
 * @param request
 *     XACML query request to add the attribute to.
 * @param resource_attribute
 *     Attribute set containing the attributes pertaining to a single resource.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_resource_attribute_init(),
 *      xacml_resource_attribute_destroy(),
 *      xacml_resource_attribute_add()
 */
xacml_result_t
xacml_request_add_resource_attribute(
    xacml_request_t                     request,
    const xacml_resource_attribute_t    resource_attribute)
{
    if (request == NULL || resource_attribute == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    request->resource_attributes.push_back(*resource_attribute);

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_add_resource_attribute() */

/**
 * Count the number of resources in XACML request
 * @ingroup xacml_request
 * Modifies the value pointed to by @a count to contain the number of
 * resource attribute sets in @a request. Values from 0 to the value returned
 * in @a count can be passed to xacml_request_get_resource_attribute() to
 * iterate through the set of resources attribute sets in a request.
 *
 * @param request
 *     XACML query request to inspect.
 * @param count
 *     Pointer to be set to the number of resource attributes attributes.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_get_resource_attribute()
 */
xacml_result_t
xacml_request_get_resource_attribute_count(
    xacml_request_t                     request,
    size_t *                            count)
{
    if (request == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *count = request->resource_attributes.size();

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_resource_attribute_get_count() */

xacml_result_t
xacml_request_get_resource_attribute(
    const xacml_request_t               request,
    size_t                              num,
    xacml_resource_attribute_t *        attribute)
{
    size_t                              c = 0;
    if (request == NULL || attribute == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::resource::iterator i = request->resource_attributes.begin();
         i != request->resource_attributes.end();
         i++)
    {
        if (c == num)
        {
            *attribute = &(*i);

            return XACML_RESULT_SUCCESS;
        }
        c++;
    }

    return XACML_RESULT_INVALID_PARAMETER;
}
/* xacml_request_get_resource_attribute() */


/**
 * Add an action attribute to an XACML query request
 * @ingroup xacml_request
 * Adds an action attribute in the XACML query request.
 *
 * @param request
 *     XACML query request to add the attribute to.
 * @param attribute_id
 *     String defining the identifier of the attribute.
 *     See @ref xacml_common_action_attributes for standard
 *     attribute IDs.
 * @param data_type
 *     String defining the data type of the attribute's value. See
 *     @ref xacml_common_datatypes for standard XACML data type names.
 * @param issuer
 *     String defining the issuer of the environment
 *     attribute.
 * @param value
 *     String defining the attribute value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 */
xacml_result_t
xacml_request_add_action_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute                    attr;

    if (request == NULL || attribute_id == NULL ||
        data_type == NULL || value == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    request->action_attributes[issuer ? issuer : ""].push_back(attr);

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_add_action_attribute() */

/**
 * Count the number of action attributes in XACML request
 * @ingroup xacml_request
 * Modifies the value pointed to by @a count to contain the number of
 * action attribute in @a request. Values from 0 to the value returned
 * in @a count can be passed to xacml_request_get_action_attribute() to
 * iterate through the set of action attributes in a request.
 *
 * @param request
 *     XACML query request to inspect.
 * @param count
 *     Pointer to be set to the number of action attributes.
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_get_action_attribute()
 */
xacml_result_t
xacml_request_get_action_attribute_count(
    const xacml_request_t               request,
    size_t *                            count)
{
    size_t                              c = 0;

    if (request == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::attribute_set::iterator i = request->action_attributes.begin();
         i != request->action_attributes.end();
         i++)
    {
        for (xacml::attributes::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            c++;
        }
    }
    *count = c;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_get_action_attribute_count() */

/**
 * Get the value of a action attribute
 * @ingroup xacml_request
 * Retrieves the information related to a action attribute, based on the
 * attribute's index. The total number of action attributes can be determined
 * by calling xacml_request_get_action_attribute_count(). 
 * 
 * @param request
 *     The XACML query request to inspect.
 * @param num
 *     Attribute index.
 * @param attribute_id
 *     Pointer to be set to the id of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_action_attributes for standard values this may be
 *     set to.
 * @param data_type
 *     Pointer to be set to the data type of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_datatypes for standard values this may be
 *     set to.
 * @param issuer
 *     Pointer to be set to the issuer of the attribute. The caller
 *     must not modify or free this value.
 * @param value
 *     Pointer to be set to the value of the attribute. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_add_subject_attribute(),
 *      xacml_request_get_subject_attribute_count()
 */
xacml_result_t
xacml_request_get_action_attribute(
    const xacml_request_t               request,
    size_t                              num,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value)
{
    size_t c = 0;

    if (request == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::attribute_set::iterator j = request->action_attributes.begin();
         j != request->action_attributes.end();
         j++)
    {
        for (xacml::attributes::iterator k = j->second.begin();
             k != j->second.end();
             k++)
        {
            if (c == num)
            {
                if (issuer)
                {
                    *issuer = j->first == "" ? NULL : j->first.c_str();
                }
                if (attribute_id)
                {
                    *attribute_id = k->attribute_id.c_str();
                }
                if (data_type)
                {
                    *data_type = k->data_type.c_str();
                }
                if (value)
                {
                    *value = k->value.c_str();
                }
                return XACML_RESULT_SUCCESS;
            }
            c++;
        }
    }

    if (issuer)
    {
        *issuer = NULL;
    }
    if (attribute_id)
    {
        *attribute_id = NULL;
    }
    if (data_type)
    {
        *data_type = NULL;
    }
    if (value)
    {
        *value = NULL;
    }
    return XACML_RESULT_INVALID_PARAMETER;
}
/* xacml_request_get_action_attribute() */

/**
 * Add an environment attribute to an XACML query request
 * @ingroup xacml_request
 * Adds an environment attribute in the XACML query request.
 *
 * @param request
 *     XACML query request to add the attribute to.
 * @param attribute_id
 *     String defining the identifier of the attribute.
 *     See @ref xacml_common_environment_attributes for standard
 *     attribute IDs.
 * @param data_type
 *     String defining the data type of the attribute's value. See
 *     @ref xacml_common_datatypes for standard XACML data type names.
 * @param issuer
 *     String defining the issuer of the environment
 *     attribute.
 * @param value
 *     String defining the attribute value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 */
xacml_result_t
xacml_request_add_environment_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute                    attr;

    if (request == NULL || attribute_id == NULL || data_type == NULL ||
        value == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    request->environment_attributes[issuer ? issuer : ""].push_back(attr);

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_add_environment_attribute() */

/**
 * Count the number of environment attributes in XACML request
 * @ingroup xacml_request
 * Modifies the value pointed to by @a count to contain the number of
 * environment attribute in @a request. Values from 0 to the value returned
 * in @a count can be passed to xacml_request_get_environment_attribute() to
 * iterate through the set of environment attributes in a request.
 *
 * @param request
 *     XACML query request to inspect.
 * @param count
 *     Pointer to be set to the number of environment attributes.
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_get_environment_attribute()
 */
xacml_result_t
xacml_request_get_environment_attribute_count(
    const xacml_request_t               request,
    size_t *                            count)
{
    size_t                              c = 0;

    if (request == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::attribute_set::iterator i =
                request->environment_attributes.begin();
         i != request->environment_attributes.end();
         i++)
    {
        for (xacml::attributes::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            c++;
        }
    }
    *count = c;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_get_environment_attribute_count() */

/**
 * Get the value of an environment attribute
 * @ingroup xacml_request
 * Retrieves the information related to a environment attribute, based on the
 * attribute's index. The total number of environment attributes can be
 * determined by calling xacml_request_get_environment_attribute_count(). 
 * 
 * @param request
 *     The XACML query request to inspect.
 * @param num
 *     Attribute index.
 * @param attribute_id
 *     Pointer to be set to the id of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_environment_attributes for standard values this may be
 *     set to.
 * @param data_type
 *     Pointer to be set to the data type of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_datatypes for standard values this may be
 *     set to.
 * @param issuer
 *     Pointer to be set to the issuer of the attribute. The caller
 *     must not modify or free this value.
 * @param value
 *     Pointer to be set to the value of the attribute. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_add_environmentt_attribute(),
 *      xacml_request_get_environmentt_attribute_count()
 */
xacml_result_t
xacml_request_get_environment_attribute(
    const xacml_request_t               request,
    size_t                              num,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value)
{
    size_t c = 0;

    if (request == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    for (xacml::attribute_set::iterator j =
                request->environment_attributes.begin();
         j != request->environment_attributes.end();
         j++)
    {
        for (xacml::attributes::iterator k = j->second.begin();
             k != j->second.end();
             k++)
        {
            if (c == num)
            {
                if (issuer)
                {
                    *issuer = j->first == "" ? NULL : j->first.c_str();
                }
                if (attribute_id)
                {
                    *attribute_id = k->attribute_id.c_str();
                }
                if (data_type)
                {
                    *data_type = k->data_type.c_str();
                }
                if (value)
                {
                    *value = k->value.c_str();
                }
                return XACML_RESULT_SUCCESS;
            }
            c++;
        }
    }

    if (issuer)
    {
        *issuer = NULL;
    }
    if (attribute_id)
    {
        *attribute_id = NULL;
    }
    if (data_type)
    {
        *data_type = NULL;
    }
    if (value)
    {
        *value = NULL;
    }
    return XACML_RESULT_INVALID_PARAMETER;
}
/* xacml_request_get_environment_attribute() */

/**
 * Set the subject of an XACML query request
 * @ingroup xacml_request
 *
 * @param request
 *     XACML query request to set the subject.
 * @param subject
 *     String representation of the XACML request subject.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 * @see xacml_request_get_subject()
 */
xacml_result_t 
xacml_request_set_subject(  
    xacml_request_t                     request,
    const char *                        subject)
{
    if (request == NULL || subject == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    request->subject = subject;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_set_subject() */

/**
 * Get the value of a request attribute
 * @ingroup xacml_request
 * Retrieves the information related to the request subject.

 * @param request
 *     The XACML query request to inspect.
 * @param subject
 *     Pointer to be set to the subject. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_request_set_subject()
 */
xacml_result_t
xacml_request_get_subject(
    const xacml_request_t               request,
    const char **                       subject)
{
    if (request == NULL || subject == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *subject = request->subject == "" ? NULL : request->subject.c_str();

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_get_subject() */

xacml_result_t
xacml_request_set_return_context(
    const xacml_request_t               request,
    int                                 return_context)
{
    if (request == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    request->return_context = return_context;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_set_return_context() */

xacml_result_t
xacml_request_get_return_context(
    const xacml_request_t               request,
    int *                               return_context)
{
    if (request == NULL || return_context == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *return_context = request->return_context;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_get_return_context() */
