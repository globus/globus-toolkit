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

#include "globus_auth_error.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/**  globus_result_set()
 * 
 * Construct a globus_auth_result_t from the input error number and string
 *
 * @param   errnum
 *          input integer error number
 * @param   format
 *          input format string describing the error
 * @param   ...
 *          additional parameters for format specifiers
 *
 * @retval  globus_auth_result_t 
 *          the globus_auth_result_t structure corresponding to the error
 *
 * @note
 *          If the input string is longer than GLOBUS_RESULT_MAX_STRING_LENGTH,
 *          it will be truncated.
 *      
 */

globus_auth_result_t 
globus_result_set(
        int                             errnum,
        const char *                    format,
        ...)
{
    va_list ap;
    globus_auth_result_t result;

    va_start(ap, format);
    
    if(result = (globus_auth_result_t) malloc(sizeof(globus_error_t)))
    {
        result->free_me = GLOBUS_TRUE;/*Is this correct?*/
        result->errnum = errnum;
    
        vsnprintf(result->errstr, GLOBUS_RESULT_MAX_STRING_LENGTH, format, ap);
        /*force the last char to null to prevent future crashes*/
        /*NOTE : if the error string exceeds GLOBUS_RESULT_MAX_STRING_LENGTH,
        * it will be truncated
        */
        result->errstr[GLOBUS_RESULT_MAX_STRING_LENGTH-1] = 0;
    }
    va_end(ap);
    return result;
}
    
/** globus_result_destroy()
 * 
 * Deallocate the memory associated with a copied error structure 
 * 
 * @param   result
 *          input result structure
 *
 * @retval  GLOBUS_SUCCESS
 *          success
 * 
 */

globus_auth_result_t
globus_result_destroy(
        globus_auth_result_t                 result)
{
    if(result && result->free_me)
        free(result);

    result = NULL; /*does that help?*/
    return GLOBUS_SUCCESS;
}
    
/** globus_result_get_error_type()
 * 
 * Extract the integer error from a error structure 
 *
 * @param   result
 *          input globus_auth_result_t structure
 * @param   errnum
 *          output error number associated with result
 *
 * @retval  GLOBUS_SUCCESS
 *          sucess
 * @retval  GLOBUS_AUTH_INVALID_ARGUMENT
 *          input result structure was null
 *
 * @note
 *          The function fills in 0 for errnum if result was null,
 *          and the errnum from result otherwise
 */

globus_auth_result_t
globus_result_get_error_type(
        globus_auth_result_t                 result,
        int *                           errnum)
{

    if(!result)
    {
        *errnum = 0;
        return(globus_result_set(
                GLOBUS_AUTH_INVALID_ARGUMENT,
                "invalid result structure"));
    }
    *errnum = result->errnum;

    return GLOBUS_SUCCESS;
}


/** globus_result_get_error_string()
 * 
 * Extract the string error from a error structure 
 *
 * @param   result
 *          input globus_auth_result_t structure
 * @param   errstr
 *          output error string associated with result
 * @param   errstr_len
 *          length of errstr buffer
 *
 * @retval  GLOBUS_SUCCESS
 *          sucess
 * @retval  GLOBUS_AUTH_INVALID_ARGUMENT
 *          input result structure was null
 *
 * @note
 *          The function fills in "GLOBUS SUCCESS" for errstr if 
 *          result was null, and the errstr from result otherwise.
 */

/* should it be changed to accept int * and char *? */

globus_auth_result_t
globus_result_get_error_string(
        globus_auth_result_t                 result,
        char *                               errstr,
        int                                  errstr_len)
   
{
    /* Check arguments */
    if (errstr == NULL)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INVALID_ARGUMENT,
                   "invalid error string argument"));
    }
    
    if(result == NULL)
    {
        snprintf(errstr, errstr_len, "GLOBUS SUCCESS");
        return(globus_result_set(
                   GLOBUS_AUTH_INVALID_ARGUMENT,
                   "invalid result structure"));
    }
    
    snprintf(errstr, errstr_len, "%s", result->errstr);

    return GLOBUS_SUCCESS;

}

/** globus_result_duplicate()
 *
 * Copy an error structure 
 *
 * @param   result
 *          input result structure to duplicate
 *
 * @retval globus_auth_result_t 
 *          the duplicated result structure 
 *          (GLOBUS_SUCCESS if result was null)
 *          
 */
globus_auth_result_t
globus_result_duplicate(
        globus_auth_result_t                 result)
{
    globus_auth_result_t out_result;

    if(!result) return GLOBUS_SUCCESS;
    
    /*result is not empty; copy corresponding fields*/
    out_result = (globus_auth_result_t) malloc(sizeof(globus_error_t));
  
    out_result->free_me = result->free_me; 
    out_result->errnum = result->errnum;
    
    strncpy(out_result->errstr, result->errstr, GLOBUS_RESULT_MAX_STRING_LENGTH);
    /*force the error string to be null-terminated*/
    out_result->errstr[GLOBUS_RESULT_MAX_STRING_LENGTH-1] = 0;

    return out_result;
}

    
