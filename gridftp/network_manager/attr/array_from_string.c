/*
 * Copyright 1999-2014 University of Chicago
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

/**
 * @file attr/array_from_string.c
 * @brief globus_net_manager_attr_array_from_string()
 */

#include "globus_net_manager_attr.h"

/**
 * @brief Parse an array of Network Manager attributes from a string
 * @ingroup globus_net_manager_attr
 * @details
 * This function parses a string containing a list
 * of attributes and creates a new array of Network Manager attribute
 * values from it. The array is terminated by globus_net_manager_null_attr.
 *
 * Attribute strings are formed by the regular expression
@verbatim
    NAME=VALUE(;NAME=VALUE)*
@endverbatim
 * The NAME and VALUE strings may contain any character except <code>;</code>
 * and <code>=</code>.
 *
 * The caller must free the array stored in *attr by calling
 * globus_net_manager_attr_array_destroy().
 *
 * @param[out] attr
 *     A pointer to an array of attributes to be allocated and initialized.
 * @param[in] scope
 *     The string to be added as the scope value of the attributes.
 * @param[in] attr_string
 *     The string to be parsed.
 */
globus_result_t
globus_net_manager_attr_array_from_string(
    globus_net_manager_attr_t         **attr,
    const char                         *scope,
    const char                         *attr_string)
{
    return GLOBUS_FAILURE;
}
/* globus_net_manager_attr_array_from_string() */
