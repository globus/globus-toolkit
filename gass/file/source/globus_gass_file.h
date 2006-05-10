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
globus_gass_file_api.h
 
Description:
    This header contains the GASS File Access API definitions
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_FILE_API_H
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_FILE_API_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_common.h"

#include <stdio.h>
#include <fcntl.h>

EXTERN_C_BEGIN

int
globus_gass_open(
    char *				file,
    int					oflags,
    ...);

FILE *
globus_gass_fopen(
    char *				file,
    char *				mode);
int
globus_gass_close(
    int					fd);
int
globus_gass_fclose(
    FILE *				f);

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
extern globus_module_descriptor_t globus_i_gass_file_module;
#define GLOBUS_GASS_FILE_MODULE (&globus_i_gass_file_module)

EXTERN_C_END

#endif
