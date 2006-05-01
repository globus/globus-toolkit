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

#ifndef __GLOBUS_AUTH_ERROR_H_
#define __GLOBUS_AUTH_ERROR_H_

#include "globus_common.h"
#include "globus_error.h"

#define GLOBUS_RESULT_MAX_STRING_LENGTH 1024

#define GLOBUS_AUTH_INVALID_ARGUMENT                1
#define GLOBUS_AUTH_INTERNAL_GAA_ERROR              2 
#define GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR         3
#define GLOBUS_AUTH_BAD_HANDLE                      4
#define GLOBUS_AUTH_BAD_POLICY_SOURCE               5 
#define GLOBUS_AUTH_INSUFFICIENT_BUFFER_SIZE        6
#define GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT             7
#define GLOBUS_AUTH_INTERNAL_GSS_ERROR              8
#define GLOBUS_AUTH_AUTHORIZATION_FAILED            9
#define GLOBUS_AUTH_MAYBE                           10
#define GLOBUS_AUTH_UNKNOWN_ERROR                   11
#define GLOBUS_AUTH_UNIMPLEMENTED_REDELEGATION	    12

/*to avoid compiling in globus common*/
/*#define GLOBUS_TRUE 1
  #define GLOBUS_FALSE 0 */


typedef struct globus_error_s
{
/* used to distinguish static from dynamic result_t's */
   globus_bool_t free_me;

/* the integer return value */
   int                  errnum;

/* the string return value, limited to 1024 characters */
   char                 errstr[GLOBUS_RESULT_MAX_STRING_LENGTH];
} globus_error_t;

typedef globus_error_t * globus_auth_result_t;

/* Get a pointer to a error structure */
globus_auth_result_t 
globus_result_set(
        int                             errnum,
        const char *                    format,
        ...);

/* Deallocate the memory associated with a copied error structure */
globus_auth_result_t
globus_result_destroy(
        globus_auth_result_t                 result);

/* Copy a error structure */
globus_auth_result_t
globus_result_duplicate(
        globus_auth_result_t                 result);

/* Extract the integer error from a error structure */
globus_auth_result_t
globus_result_get_error_type(
        globus_auth_result_t                 result,
        int *                                errnum);

/* Extract the string error from a error structure */
globus_auth_result_t
globus_result_get_error_string(
        globus_auth_result_t                 result,
        char *                               errstr,
        int                                  errstr_len);


#endif /* __GLOBUS_AUTH_ERROR_H_ */
