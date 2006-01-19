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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_error_errno.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "globus_i_error_errno.h"
#include "globus_libc.h"
#include "globus_object.h"
#include "globus_error.h"
#include "globus_error_generic.h"
#include "globus_common.h"

/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus Errno Error object.
 * @ingroup globus_errno_error_object 
 * 
 * @param src
 *        The source instance data
 * @param dst
 *        The destination instance data
 * @return
 *        void
 */
static
void
globus_l_error_copy_errno(
    void *                              src,
    void **                             dst)
{
    if(src == NULL || dst == NULL) return;
    (*dst) = (void *) malloc(sizeof(int));
    *((int *) *dst) = *((int *) src);
    return;
}/* globus_l_error_copy_errno */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus Errno Error object.
 * @ingroup globus_errno_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_errno(
    void *                              data)
{
    globus_libc_free(data);
}/* globus_l_error_free_errno */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_errno_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_error_errno_printable(
    globus_object_t *                   error)
{
    globus_module_descriptor_t *        base_source;
    char *                              sys_failed =
        _GCSL("A system call failed:");
    char *                              sys_error;
    int                                 length = 4 + strlen(sys_failed);
    char *                              printable;


    sys_error = globus_libc_system_error_string(
        *((int *) globus_object_get_local_instance_data(error)));

    if(sys_error == NULL)
    {
        sys_error = "(null)";
    }
    
    length += strlen(sys_error);
    
    base_source = globus_error_get_source(error);

    if(base_source && base_source->module_name)
    {
        length += strlen(base_source->module_name);
        printable = globus_libc_malloc(length);
        globus_libc_snprintf(printable,length,"%s: %s %s",
                             base_source->module_name,
                             sys_failed,
                             sys_error);
        
    }
    else
    {
        printable = globus_libc_malloc(length);
        globus_libc_snprintf(printable,length,"%s %s",
                             sys_failed,
                             sys_error);
    }
    
    return printable;
    
}/* globus_l_error_errno_printable */
/*@}*/

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_ERRNO_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_errno,
    globus_l_error_free_errno,
    globus_l_error_errno_printable);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

