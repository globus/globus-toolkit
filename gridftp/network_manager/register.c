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

#include "globus_net_manager.h"

/**
 * @brief Register a network manager
 * @ingroup globus_net_manager
 * @details
 * The globus_net_manager_register() function adds this network manager
 * to those which will be called by the network manager interface
 * when network events occur. This is typically called by the network
 * manager when its module is activated.
 * @param[in] manager
 *     Manager information to register.
 *
 */
globus_result_t
globus_net_manager_register(
    globus_net_manager_t               *manager)
{
    return GLOBUS_SUCCESS;
}
