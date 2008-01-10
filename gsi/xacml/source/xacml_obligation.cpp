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
 * @defgroup xacml_obligation Obligations
 * @ingroup xacml_common
 */

/**
 * Initialize an obligation
 * @ingroup xacml_obligation
 *
 * Creates an obligation structure which can be used to contain a
 * set of attributes related to a single obligation.
 * When the obligation is no longer needed, the caller must destroy it by
 * calling xacml_obligation_destroy().
 *
 * @param obligation
 *     Response to initialize. The value pointed to by this can be passed
 *     to other xacml_obligation_* functions.
 * @param obligation_id
 *     Obligation identifier.
 * @param fulfill_on
 *     The effect for which the obligation must be fulfilled.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_obligation_destroy().
 */
xacml_result_t
xacml_obligation_init(
    xacml_obligation_t *                obligation,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on)
{
    xacml_obligation_s *                o;

    if (obligation == NULL ||
        obligation_id == NULL ||
        fulfill_on < XACML_EFFECT_Permit ||
        fulfill_on > XACML_EFFECT_Deny)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    o = new xacml_obligation_s();

    o->obligation.obligation_id = obligation_id;
    o->obligation.fulfill_on = fulfill_on;

    *obligation = o;

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_init() */

/**
 * Destroy an obligation
 * @ingroup xacml_obligation
 *
 * Frees resources associated with an obligation. After
 * calling this, the @a obligation value must not be used by the caller.
 *
 * @param obligation
 *     Obligation to destroy.
 *
 * @return void
 *
 * @see xacml_obligation_init().
 */
void
xacml_obligation_destroy(
    xacml_obligation_t                  obligation)
{
    if (obligation)
    {
        delete obligation;
    }
}
/* xacml_obligation_destroy() */

/**
 * Add an attribute value to an obligation
 * @ingroup xacml_obligation
 *
 * Adds a new attribute to an obligation.
 *
 * @param obligation
 *     Obligation to add the attribute value to.
 * @param attribute_id
 *     String defining the identifier of the attribute.
 * @param data_type
 *     String defining the data type of the attribute's value. See
 *     @ref xacml_common_datatypes for standard XACML data type names.
 * @param value
 *     String defining the attribute value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 */
xacml_result_t
xacml_obligation_add_attribute(
    xacml_obligation_t                  obligation,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        value)
{
    xacml::attribute                    attribute;

    if (obligation == NULL ||
        attribute_id == NULL ||
        data_type == NULL ||
        value == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    attribute.attribute_id = attribute_id;
    attribute.data_type = data_type;
    attribute.value = value;

    obligation->obligation.attributes.push_back(attribute);

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_add_attribute() */

/**
 * Count the number of attributes in an obligation
 * @ingroup xacml_obligation
 * Modifies the value pointed to by @a count to contain the number of
 * attributes in @a obligation. Values from 0 to the value returned
 * in @a count can be passed to xacml_obligatino_get_attribute() to
 * iterate through the set of attributes in an obligation.
 *
 * @param obligation
 *     Obligation to inspect.
 * @param count
 *     Pointer to be set to the number of attributes.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_obligation_get_attribute()
 */
xacml_result_t
xacml_obligation_get_attribute_count(
    const xacml_obligation_t            obligation,
    size_t *                            count)
{
    if (obligation == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *count = obligation->obligation.attributes.size();

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_get_attribute_count() */

/**
 * Get the value of an attribute
 * @ingroup xacml_obligation
 * Retrieves the information related to an attribute, based on the
 * attribute's index. The total number of attributes can be determined
 * by calling xacml_obligation_get_attribute_count(). 
 * 
 * @param obligation
 *     The obligation to inspect.
 * @param num
 *     Attribute index.
 * @param attribute_id
 *     Pointer to be set to the id of the attribute. The caller
 *     must not modify or free this value.
 * @param data_type
 *     Pointer to be set to the data type of the attribute. The caller
 *     must not modify or free this value. See
 *     @ref xacml_common_datatypes for standard values this may be
 *     set to.
 * @param value
 *     Pointer to be set to the value of the attribute. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_obligation_add_attribute(),
 *      xacml_obligation_get_attribute_count()
 */
xacml_result_t
xacml_obligation_get_attribute(
    const xacml_obligation_t            obligation,
    size_t                              num,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       value)
{
    if (obligation == NULL ||
        (num+1) > obligation->obligation.attributes.size())
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    const xacml::attribute &a = obligation->obligation.attributes[num];

    if (attribute_id != NULL)
    {
        *attribute_id = a.attribute_id.c_str();
    }
    if (data_type != NULL)
    {
        *data_type = a.data_type.c_str();
    }
    if (value != NULL)
    {
        *value = a.value.c_str();
    }

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_get_attribute() */

/**
 * Get the id of an obligation
 * @ingroup xacml_obligation
 *
 * Modifies the value pointed to by @a obligation_id to contain the identifier
 * associated with the obligation. The caller must not modify or free the value
 * returned via @a obligation
 *
 * @param obligation
 *     Obligation to inspect.
 * @param obligation_id
 *     Pointer to be set to the ID of the obligation.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_obligation_init()
 */
xacml_result_t
xacml_obligation_get_id(
    const xacml_obligation_t            obligation,
    const char **                       obligation_id)
{
    if (obligation == NULL || obligation_id == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *obligation_id = obligation->obligation.obligation_id.c_str();

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_get_id() */

/**
 * Get the effect when an obligation applies
 * @ingroup xacml_obligation
 *
 * Modifies the value pointed to by @a fulfill_on to contain the 
 * effect associated with the obligation. 
 *
 * @param obligation
 *     Obligation to inspect.
 * @param fulfill_on
 *     Pointer to be set to the effect of the obligation.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_obligation_init()
 */
xacml_result_t
xacml_obligation_get_effect(
    const xacml_obligation_t            obligation,
    xacml_effect_t *                    fulfill_on)
{
    if (obligation == NULL || fulfill_on == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *fulfill_on = obligation->obligation.fulfill_on;

    return XACML_RESULT_SUCCESS;
}
/* xacml_obligation_get_effect() */
