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

#ifndef GLOBUS_I_RVF_H
#define GLOBUS_I_RVF_H

#include "globus_common.h"

typedef struct
{
    int aspect;
    char *string_value;
    int when_value;
    globus_bool_t bool_value;
}
globus_i_rvf_aspect_t;

#endif /* GLOBUS_I_RVF_H */
