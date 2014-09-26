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

/**
 * @file globus_rsl_assist.h
 * @brief RSL Utility Functions
 */

#ifndef GLOBUS_RSL_ASSIST_H
#define GLOBUS_RSL_ASSIST_H

#include "globus_common.h"
#include "globus_rsl.h"

#ifdef __cplusplus
extern "C" {
#endif

extern
void
globus_rsl_assist_string_canonicalize(char * ptr);

extern
int
globus_rsl_assist_attributes_canonicalize(globus_rsl_t * rsl);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_RSL_ASSIST_H */
