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
 * @file globus_i_error_generic.c
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "globus_i_error_generic.h"
#include "globus_libc.h"
#include "globus_object.h"
#include "globus_error.h"

/**
 * @name Copy Error Data
 */
/*@{*/
/**
 * Copy the instance data of a Globus Generic Error object.
 * @ingroup globus_generic_error_object 
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
globus_l_error_copy_globus(
    void *                              src,
    void **                             dst)
{
    globus_l_error_data_t *             source;
    globus_l_error_data_t *             dest;
    
    if(src == NULL || dst == NULL) return;
    
    source = (globus_l_error_data_t *) src;
    dest = (globus_l_error_data_t *) malloc(sizeof(globus_l_error_data_t));
    if(dest)
    {
        memset(dest, 0 ,sizeof(globus_l_error_data_t));
        dest->type = source->type;
        dest->file = source->file;
        dest->func = source->func;
        dest->line = source->line;
        
        if(source->short_desc)
        {
            dest->short_desc = globus_libc_strdup(source->short_desc);
        }
        
        if(source->long_desc)
        {
            dest->long_desc = globus_libc_strdup(source->long_desc);
        }
    }
    
    *dst = dest;
}/* globus_l_error_copy_globus */
/*@}*/

/**
 * @name Free Error Data
 */
/*@{*/
/**
 * Free the instance data of a Globus Generic Error object.
 * @ingroup globus_generic_error_object 
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_error_free_globus(
    void *                              data)
{
    if(((globus_l_error_data_t *) data)->short_desc)
    {
        globus_libc_free(((globus_l_error_data_t *) data)->short_desc);
    }

    if(((globus_l_error_data_t *) data)->long_desc)
    {
        globus_libc_free(((globus_l_error_data_t *) data)->long_desc);
    }
    
    globus_libc_free(data);
}/* globus_l_error_free_globus */
/*@}*/

/**
 * @name Print Error Data
 */
/*@{*/
/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_generic_error_object 
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 * 
 *      (<module name> | <file> ":" <func> ":" <line>) ": " <short_desc>
 */
static
char *
globus_l_error_globus_printable(
    globus_object_t *                   error)
{
    globus_l_error_data_t *             data;
    const char *                        layout[9];
    char                                line[12];
    int                                 i = 0;
    
    data = (globus_l_error_data_t *) 
        globus_object_get_local_instance_data(error);
    
    if(!data->short_desc)
    {
        return NULL;
    }
    
    if(globus_i_error_verbose)
    {
        if(data->file)
        {
            layout[i++] = data->file;
        }
        
        if(data->func)
        {
            if(i)
            {
                layout[i++] = ":";
            }
            layout[i++] = data->func;
        }
        
        if(i)
        {
            layout[i++] = ":";
            snprintf(line, sizeof(line), "%d", data->line);
            layout[i++] = line;
        }
    }
    
    if(i == 0)
    {
        globus_module_descriptor_t *    source_module;
        
        source_module = globus_error_get_source(error);
        if(source_module && source_module->module_name)
        {
            layout[i++] = source_module->module_name;
        }
    }
    
    if(i > 1)
    {
        layout[i++] = ":\n";
    }
    else if(i == 1)
    {
        layout[i++] = ": ";
    }
    
    layout[i++] = data->short_desc;
    
    if(globus_i_error_verbose && data->long_desc)
    {
        layout[i++] = "\n";
        layout[i++] = data->long_desc;
    }
    
    return globus_libc_join(layout, i);
}/* globus_l_error_globus_printable */
/*@}*/

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_ERROR_TYPE_GLOBUS_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_error_copy_globus,
    globus_l_error_free_globus,
    globus_l_error_globus_printable);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

