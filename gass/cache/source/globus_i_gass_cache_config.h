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

/******************************************************************************
globus_i_gass_cache_config.h

Description:

  Generic config file utility. Could be used elsewhere.
  
CVS Information:
     
******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_CACHE_CONFIG_H_
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_CACHE_CONFIG_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_hashtable.h"

EXTERN_C_BEGIN

#define GLOBUS_L_ERROR_CONFIG_FILE_NOT_FOUND      -200
#define GLOBUS_L_ERROR_CONFIG_FILE_READ           -201
#define GLOBUS_L_ERROR_CONFIG_FILE_PARSE_ERROR    -202

/* config structure definition */
typedef struct globus_l_gass_cache_config_s 
{
    char*                   buf;     /* buffer that holds the config file */
    globus_hashtable_t      table;   /* parsed config entries (hashtable) */
} globus_l_gass_cache_config_t;

/*
 * globus_l_gass_cache_config_init()
 *
 * Inits the config structure by reading from a file.
 *  
 * Parameters:
 *  - directory   the GASS cache directory 
 *  - config      the config structure
 *  
 * Returns:
 *  - GLOBUS_SUCCESS upon success
 */
int
globus_l_gass_cache_config_init(char*                        file,
				globus_l_gass_cache_config_t *config);


/*
 * globus_l_gass_cache_config_destroy()
 *
 * Destroys the config structure
 *  
 * Parameters:
 *  - config      the config structure
 *  
 * Returns:
 */
int
globus_l_gass_cache_config_destroy(globus_l_gass_cache_config_t *config);

/*
 * globus_l_gass_cache_config_get()
 *
 * Retrieves a config entry
 *  
 * Parameters:
 *  - config      the config structure
 *  - key         the config parameter
 *  
 * Returns:
 *  the value associated with 'key', or GLOBUS_NULL
 */
char*
globus_l_gass_cache_config_get(globus_l_gass_cache_config_t *config,
			       char*                        key);


/*
 * globus_l_gass_cache_config_get()
 *
 * Defines a new config entry
 *  
 * Parameters:
 *  - config      the config structure
 *  - key         the config parameter
 *  - value       the config parameter value
 *  
 * Returns:
 */
int
globus_l_gass_cache_config_set(globus_l_gass_cache_config_t *config,
			       char                         *key,
			       char                         *value);


/*
 * globus_l_gass_cache_config_save()
 *
 * Saves the configuration to a file. NOTE: Any comments in the file
 * will be lost!
 *  
 * Parameters:
 *  - config      the config structure
 *  - file        the file to write to
 *  - overwrite   if TRUE, will overwrite existing file
 *  
 * Returns:
 */
int
globus_l_gass_cache_config_save(globus_l_gass_cache_config_t *config,
				char                         *file,
				globus_bool_t                *overwrite);


EXTERN_C_END

#endif

