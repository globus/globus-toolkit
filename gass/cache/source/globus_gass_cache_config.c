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
globus_gass_cache_config.c
 
Description:
    Internal utlity functions for extracting GASS cache configuration
    information.

******************************************************************************/

#include "globus_common.h"
#include "globus_hashtable.h"
#include "globus_gass_cache.h"
#include "globus_i_gass_cache.h"
#include "globus_i_gass_cache_config.h"
#include <string.h>
#include <ctype.h>

static void strtrimhead(char** str)
{
	while (isspace(**str))
	    (*str)++;

}

static void strtrimtail(char* str)
{
    int    len  = strlen(str);
    char*  stop = str+len;

	while ( (stop-1>str) && isspace(*(stop-1)) )
	    stop--;

    if (stop>str)
        *stop = 0;
}

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
globus_l_gass_cache_config_init(
    char *                          file,
    globus_l_gass_cache_config_t *  config)
{
    globus_off_t                    length;
    int                             i, n, fd, rc, status;
    char                            *p, *q, *r;
    char                            *key, *value;

    memset(config, '\0', sizeof(globus_l_gass_cache_config_t));

    status = GLOBUS_SUCCESS;

    config->buf = GLOBUS_NULL;

    /* open the config file, figure out size, then read the file into
       a buffer */
    fd = globus_libc_open(file, O_RDONLY);

    if (fd < 0)
    {
        status = GLOBUS_L_ERROR_CONFIG_FILE_NOT_FOUND;
        goto cleanup;
    }

    length = globus_libc_lseek(fd,0,SEEK_END);
    if (length <= 0)
    {
        status = GLOBUS_L_ERROR_CONFIG_FILE_READ;
        goto cleanup;
    }

    config->buf = globus_libc_malloc(length+1);
    if (config->buf == NULL)
    {
        status = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
        goto cleanup;
    }

    if (globus_libc_lseek(fd,0,SEEK_SET) != 0)
    {
        status = GLOBUS_L_ERROR_CONFIG_FILE_READ ;
        goto free_config_buf;
    }

    for (i=0; i<length; i+=n)
    {
        n = read(fd, config->buf+i, length-i);

        if (n <= 0)
        {
            status = GLOBUS_L_ERROR_CONFIG_FILE_READ;
            goto free_config_buf;
        }
    }
    *(config->buf+length) = '\0';
    
    rc = globus_hashtable_init(&config->table, 16, 
			       (void*) globus_hashtable_string_hash,
			       (void*) globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        status = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
        goto free_config_buf;
    }

    for (p=config->buf; (p-config->buf)<length; p=q+1)
    {
	if (!(q = strchr(p, '\n')))
	    q = config->buf+length;

        *q = 0;

	strtrimhead(&p);
	strtrimtail(p);
	if (*p=='#' || !strlen(p))     /* a comment or empty line */
	    continue;

	r = strchr(p, '=');
        if (r == NULL)
        {
            status = GLOBUS_L_ERROR_CONFIG_FILE_PARSE_ERROR;

            goto destroy_hashtable;
        }

	*r = 0;
	key = p;
	value = r+1;
	
	strtrimtail(key);
	strtrimhead(&value);

	globus_hashtable_insert(&config->table,
				(void *) key,
				(void *) value);
    }
    if (fd >= 0)
    {
        globus_libc_close(fd);
    }

    return status;

destroy_hashtable:
    globus_hashtable_destroy(&config->table);
free_config_buf:
    globus_libc_free(config->buf);
    config->buf = NULL;
cleanup:
    if (fd >= 0)
    {
        globus_libc_close(fd);
    }
    return status;
}
/* globus_l_gass_cache_config_init() */

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
globus_l_gass_cache_config_destroy(globus_l_gass_cache_config_t *config)
{
    int   rc = globus_hashtable_destroy(&config->table);
    if (config->buf)
    {
        globus_libc_free(config->buf);
    }
    return rc;
}
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
			       char*                        key)
{
    return globus_hashtable_lookup(&config->table, key);
}

