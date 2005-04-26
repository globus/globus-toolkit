/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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

