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
 * @file context/post_close.c
 * @brief globus_net_manager_context_post_close()
 */

#include "globus_net_manager_context.h"

globus_result_t
globus_net_manager_context_post_close(
    globus_net_manager_context_t        context,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array)
{
    return GLOBUS_SUCCESS;
}
