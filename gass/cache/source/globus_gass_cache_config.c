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
int globus_l_gass_cache_config_init(char*                        file,
				    globus_l_gass_cache_config_t *config)
{
    globus_off_t               length;
    int                        i, n, fd, rc, status;
    char                       *p, *q, *r;
    char                       *key, *value;

    memset(config, '\0', sizeof(globus_l_gass_cache_config_t));

#ifdef assert
#undef assert
#endif
#define assert(x,e) if (!(x)) { status=e; goto cleanup; }

    status = GLOBUS_SUCCESS;

    config->buf = GLOBUS_NULL;

    /* open the config file, figure out size, then read the file into
       a buffer */
    assert( 0 <= (fd = globus_libc_open(file, O_RDONLY)),
	    GLOBUS_L_ERROR_CONFIG_FILE_NOT_FOUND );

    assert( 0 < (length = globus_libc_lseek(fd,0,SEEK_END)),
	    GLOBUS_L_ERROR_CONFIG_FILE_READ );

    assert( config->buf = globus_libc_malloc(length+1),
	    GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );

    assert( 0 == globus_libc_lseek(fd,0,SEEK_SET),
	    GLOBUS_L_ERROR_CONFIG_FILE_READ );

    for (i=0; i<length; i+=n)
    {
         n = read(fd, config->buf+i, length-i);
         assert( n>0, GLOBUS_L_ERROR_CONFIG_FILE_READ );
    }
    *(config->buf+length) = '\0';
    
    rc = globus_hashtable_init(&config->table, 16, 
			       (void*) globus_hashtable_string_hash,
			       (void*) globus_hashtable_string_keyeq);

    for (p=config->buf; (p-config->buf)<length; p=q+1)
    {
	if (!(q = strchr(p, '\n')))
	    q = config->buf+length;

        *q = 0;

	strtrimhead(&p);
	strtrimtail(p);
	if (*p=='#' || !strlen(p))     /* a comment or empty line */
	    continue;
	
	assert( r = strchr(p, '='), GLOBUS_L_ERROR_CONFIG_FILE_PARSE_ERROR );
	*r = 0;
	key = p;
	value = r+1;
	
	strtrimtail(key);
	strtrimhead(&value);

	globus_hashtable_insert(&config->table,
				(void *) key,
				(void *) value);
    }

 cleanup:
    if (fd >= 0)
    {
        globus_libc_close(fd);
    }

    return status;
} 


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

