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

/**
 * Initialize an XACML resource attribute
 * @ingroup xacml_common_resource_attributes
 *
 * Creates an XACML resource attribute which can contain a set of attributes
 * of a single resource. The resource attributes can be added to an XACML query
 * request by calling xacml_request_add_resource_attribute().
 *
 * @param attribute
 *     Resource attribute to initialize. The value pointed to this can be
 *     passed to other xacml_resource_attribute_* functions.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_resource_attribute_destroy()
 */
xacml_result_t
xacml_resource_attribute_init(
    xacml_resource_attribute_t *        attribute)
{
    if (attribute == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *attribute = new xacml_resource_attribute_s;

    return XACML_RESULT_SUCCESS;
}
/* xacml_resource_attribute_init() */

/**
 * Add an attribute value to a resource attribute
 * @ingroup xacml_common_resource_attributes
 *
 * Adds a new attribute to a resource attribute set.
 *
 * @param attribute
 *     Resource attribute to add the attribute value to.
 * @param attribute_id
 *     String defining the identifier of the attribute.
 *     See @ref xacml_common_resource_attributes for standard
 *     attribute IDs.
 * @param data_type
 *     String defining the data type of the attribute's value. See
 *     @ref xacml_common_datatypes for standard XACML data type names.
 * @param issuer
 *     String defining the issuer of the resource attribute. This may be NULL.
 * @param value
 *     String defining the attribute value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 */
xacml_result_t
xacml_resource_attribute_add(
    xacml_resource_attribute_t          attribute,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute                    a;

    if (attribute == NULL || attribute_id == NULL ||
        data_type == NULL || value == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    a.attribute_id = attribute_id;
    a.data_type = data_type;
    a.value = value;

    attribute->attributes[issuer ? issuer : ""].push_back(a);

    return XACML_RESULT_SUCCESS;
}
/* xacml_resource_attribute_add() */

/**
 * Destroy an resource attribute
 * @ingroup xacml_common_resource_attributes
 *
 * Frees resources associated with a resource attribute set. After
 * calling this, the @a attribute value must not be used by the caller.
 *
 * @param attribute
 *     Resource attribute to destroy.
 *
 * @return void
 *
 * @see xacml_resource_attribute_init().
 */
void
xacml_resource_attribute_destroy(
    xacml_resource_attribute_t          attribute)
{
    delete attribute;
}
/* xacml_resource_attribute_destroy() */

/** 
 * Count the number of attributes in a resource attribute set.
 * @ingroup xacml_common_resource_attributes
 * Modifies the value pointed to by @a count to contain the number of
 * subject attribute in @a request. Values from 0 to the value returned
 * in @a count can be passed to xacml_request_get_subject_attribute() to
 * iterate through the set of subject attributes in a request.
 *  
 * @param attribute
 *     Resource attribute to inspect.
 * @param count
 *     Pointer to be set to the number of attributes.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_resource_attribute_get_attribute()
 */
xacml_result_t
xacml_resource_attribute_get_count(
    xacml_resource_attribute_t          attribute,
    size_t *                            count)
{
    size_t                              c = 0;

    if (attribute == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    for (xacml::attribute_set::iterator i = attribute->attributes.begin();
         i != attribute->attributes.end();
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
/* xacml_resource_attribute_get_count() */
    
/**
 * Get the value of a resource attribute
 * @ingroup xacml_common_resource_attributes
 * Retrieves the information related to a resource attribute, based on the
 * attribute's index. The total number of subject attributes can be determined
 * by calling xacml_resource_attribute_get_count(). 
 * 
 * @param attribute
 *     The XACML query request to inspect.
 * @param num
 *     Attribute index.
 * @param attribute_id
 *     Pointer to be set to the id of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_resource_attributes for standard values this may be
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
 * @see xacml_resource_attribute_get_count()
 */
xacml_result_t
xacml_resource_attribute_get_attribute(
    const xacml_resource_attribute_t    attribute,
    size_t                              num,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value)
{
    size_t                              c = 0;
    if (attribute == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    for (xacml::attribute_set::iterator i = attribute->attributes.begin();
         i != attribute->attributes.end();
         i++)
    {
        for (xacml::attributes::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            if (num == c)
            {
                if (attribute_id)
                {
                    *attribute_id = j->attribute_id.c_str();
                }
                if (data_type)
                {
                    *data_type = j->data_type.c_str();
                }
                if (issuer)
                {
                    *issuer = i->first == "" ? NULL : i->first.c_str();
                }
                if (value)
                {
                    *value = j->value.c_str();
                }
                return XACML_RESULT_SUCCESS;
            }
            c++;
        }
    }

    return XACML_RESULT_INVALID_PARAMETER;
}
/* xacml_resource_attribute_get_attribute() */
