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

/******************************************************************************
globus_gass_transfer_keyvalue.h
 
Description:
    This header implements a keyvalue list
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H
#define GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_list.h"

EXTERN_C_BEGIN

typedef struct
{
    char *					key;
    char *					value;
} globus_gass_transfer_keyvalue_t;

char *
globus_i_gass_transfer_keyvalue_lookup(
    globus_list_t **				list,
    char *					key);

void
globus_i_gass_transfer_keyvalue_insert(
    globus_list_t **				list,
    char *					key,
    char *					value);

void
globus_i_gass_transfer_keyvalue_replace(
    globus_list_t **				list,
    char *					key,
    char *					value);

void
globus_i_gass_transfer_keyvalue_destroy(
    globus_list_t **				list);

EXTERN_C_END

#endif /* GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H */
