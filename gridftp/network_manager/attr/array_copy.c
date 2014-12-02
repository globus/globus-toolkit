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
 * @file attr/array_copy.c
 * @brief globus_net_manager_attr_array_copy()
 */

#include "globus_net_manager_attr.h"

/**
 * @brief Copy an array of Network Manager attributes
 * @ingroup globus_net_manager_attr
 * @details
 * This function performs a deep copy of array of net_manager attributes.
 * The new array will be stored in the pointer passed to by the dest_array
 * parameter. It will contain all entries in the array passed as the 
 * src_array, ending with the value #GLOBUS_NET_MANAGER_NULL_ATTR.
 *
 * The caller must free the array stored in *dest_array by calling
 * globus_net_manager_attr_array_destroy().
 *
 *
 * @param[out] dest_array
 *     A pointer to an array of attributes to be allocated and initialized.
 * @param[in] src_array
 *     An array of attributes to copy.
 *
 * @return
 * On error, the dest_array is set to NULL and this function returns an error
 * object. Otherwise, this function returns GLOBUS_SUCCESS.
 */
globus_result_t
globus_net_manager_attr_array_copy(
    globus_net_manager_attr_t         **dest_array,
    const globus_net_manager_attr_t    *src_array)
{
    return GLOBUS_FAILURE;
}
/* globus_net_manager_attr_array_copy() */
