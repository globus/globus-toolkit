/******************************************************************************
globus_gass_file_api.c 

Description: Implemetation of public gass file access API
             (uses globus_gass_client and globus_gass_cache APIs)

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include "nexus.h"

#include "globus_common.h"
#include "globus_gass_file.h"
#include "globus_gass_cache.h"
#include "globus_gass_client.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct globus_l_gass_file_s
{
    char *url;
    char *filename;
    int oflag;
    int fd;
    unsigned long timestamp;
    unsigned long total_length;
} globus_l_gass_file_t;

/******************************************************************************
                          Module specific variables
******************************************************************************/
static globus_bool_t globus_l_gass_file_inited = GLOBUS_FALSE;
static globus_gass_cache_t globus_l_gass_file_cache_handle;
static globus_mutex_t globus_l_gass_file_mutex;
static char *globus_l_gass_file_tag;
static globus_hashtable_t globus_l_gass_file_hash;

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
#define globus_gass_file_enter() globus_mutex_lock(&globus_l_gass_file_mutex);
#define globus_gass_file_exit()  globus_mutex_unlock(&globus_l_gass_file_mutex);
static int globus_l_gass_add_and_trunc(globus_l_gass_file_t *file, int oflag, int mode);
static int globus_l_gass_add_and_get(globus_l_gass_file_t *file, int oflag, int mode);
/******************************************************************************
Function: globus_gass_open()

Description: 

Parameters:

Returns:
******************************************************************************/


int
globus_i_gass_file_activate()
{
    char *tag;

    globus_module_activate(GLOBUS_NEXUS_MODULE);
    globus_module_activate(GLOBUS_GASS_CLIENT_MODULE);

    globus_mutex_init(&globus_l_gass_file_mutex, GLOBUS_NULL);
    globus_gass_cache_open(GLOBUS_NULL,
			   &globus_l_gass_file_cache_handle);
    tag = (char *) getenv("GLOBUS_GRAM_JOB_CONTACT");
    if(tag != GLOBUS_NULL)
    {
	globus_l_gass_file_tag = globus_malloc(strlen(tag)+ 1);
	strcpy(globus_l_gass_file_tag, tag);
    }
    else
    {
	globus_l_gass_file_tag = GLOBUS_NULL;
    }
    globus_hashtable_init(&globus_l_gass_file_hash,
			  256,
			  globus_hashtable_int_hash,
			  globus_hashtable_int_keyeq);

    globus_l_gass_file_inited = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}

int
globus_i_gass_file_deactivate()
{
    globus_l_gass_file_inited = GLOBUS_FALSE;

    globus_hashtable_destroy(&globus_l_gass_file_hash);

    if(globus_l_gass_file_tag != GLOBUS_NULL)
    {
	globus_free(globus_l_gass_file_tag);
	globus_l_gass_file_tag = GLOBUS_NULL;
    }
    globus_gass_cache_close(&globus_l_gass_file_cache_handle);
    globus_mutex_destroy(&globus_l_gass_file_mutex);
    
    globus_module_deactivate(GLOBUS_GASS_CLIENT_MODULE);
    globus_module_deactivate(GLOBUS_NEXUS_MODULE);

    return GLOBUS_SUCCESS;
}

int
globus_gass_open(char *url, int oflag, ...)
{
    va_list ap;
    int fd=-1;
    globus_url_t globus_url;
    globus_l_gass_file_t *file;
    int mode=0777;
    int rc;
    
    if(oflag & O_CREAT)
    {
	va_start(ap, oflag);
	mode = va_arg(ap, int);
	va_end(ap);
    }
    
    if(globus_l_gass_file_inited == GLOBUS_FALSE)
    {
	return(GLOBUS_GASS_ERROR_NOT_INITIALIZED);
    }

    globus_gass_file_enter();
    
    rc = globus_url_parse(url, &globus_url);
    if(rc != GLOBUS_SUCCESS ||
       globus_url.scheme_type == GLOBUS_URL_SCHEME_UNKNOWN)
    {
	fd = open(url, oflag, mode);
	globus_url_destroy(&globus_url);
	globus_gass_file_exit();
	return fd;
    }
    else if(globus_url.scheme_type == GLOBUS_URL_SCHEME_FILE)
    {
	fd = open(globus_url.url_path, oflag, mode);
	globus_url_destroy(&globus_url);
	globus_gass_file_exit();
	return fd;
    }
    globus_url_destroy(&globus_url);

    /* check for invalid combos on GASS urls */
    if((O_RDONLY != 0 &&
       ((oflag & (O_RDONLY|O_APPEND)) == (O_RDONLY|O_APPEND))) ||
       ((oflag & (O_RDWR|O_APPEND))   == (O_RDWR|O_APPEND)) ||
       ((oflag & (O_RDONLY|O_TRUNC))  == (O_RDONLY|O_TRUNC)))
    {
	globus_gass_file_exit();
	return -1;
    }

    file = (globus_l_gass_file_t *)
	globus_malloc(sizeof(globus_l_gass_file_t));
    file->url = globus_malloc(strlen(url)+1);
    strcpy(file->url, url);
    file->oflag = oflag;
    file->fd = -1;

    switch(oflag & (O_RDONLY|O_WRONLY|O_RDWR|O_TRUNC|O_APPEND))
    {
    case (O_RDONLY):
	rc = globus_l_gass_add_and_get(file,
			       oflag,
			       mode);
	
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	break;

    case (O_WRONLY|O_TRUNC):
	rc = globus_l_gass_add_and_trunc(file,
				 oflag,
				 mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	break;

    case (O_WRONLY):
	rc = globus_l_gass_add_and_get(file,
			       oflag,
			       mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	break;

    case (O_RDWR):
	rc = globus_l_gass_add_and_get(file,
			       oflag,
			       mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	break;

    case (O_RDWR|O_TRUNC):
	rc = globus_l_gass_add_and_trunc(file,
				 oflag,
				 mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	break;
	
    case (O_WRONLY|O_APPEND):
	rc = globus_gass_client_put_socket(url,
					   GLOBUS_NULL,
					   GLOBUS_TRUE,
					   GLOBUS_GASS_ACK_NONE,
					   &file->fd);
	file->filename = GLOBUS_NULL;
	if(rc != GLOBUS_GASS_REQUEST_PENDING)
	{
	    goto failure;
	}
	else
	{
	    globus_hashtable_insert(&globus_l_gass_file_hash,
				    (void *) file->fd,
				    (void *) file);
	}
	break;
    default:
	globus_free(file);
	globus_gass_file_exit();
	return GLOBUS_GASS_ERROR_NOT_SUPPORTED;
    }
    globus_gass_file_exit();
    return file->fd;

failure:
    free(file);
    globus_gass_file_exit();
    return -1;
}

/******************************************************************************
Function: globus_gass_fopen()

Description: Open a file stream to a GASS-opened file, by URL

Parameters: filename -> the URL of the file to open
            type -> The file open type (see fopen(3))

Returns: a valid file stream pointer, or GLOBUS_NULL, if an error occurred
******************************************************************************/
FILE *
globus_gass_fopen(char *filename,
	   char *type)
{
    int fd = -1;
    if(strcmp(type, "r") == 0 ||
       strcmp(type, "rb") == 0)
    {
	fd = globus_gass_open(filename, O_RDONLY);
    }
    else if(strcmp(type, "w") == 0 ||
	    strcmp(type, "wb") == 0)
    {
	fd = globus_gass_open(filename, O_WRONLY|O_CREAT|O_TRUNC);
    }
    else if(strcmp(type, "a") == 0 ||
	    strcmp(type, "ab") == 0)
    {
	fd = globus_gass_open(filename, O_WRONLY|O_APPEND|O_CREAT);
    }
    else if(strcmp(type, "r+") == 0 ||
	    strcmp(type, "r+b") == 0 ||
	    strcmp(type, "rb+") == 0)
    {
	fd = globus_gass_open(filename, O_RDWR);
    }
    else if(strcmp(type, "w+") == 0 ||
	    strcmp(type, "w+b") == 0 ||
	    strcmp(type, "wb+") == 0)
    {
	fd = globus_gass_open(filename, O_RDWR|O_TRUNC|O_CREAT);
    }
    else if(strcmp(type, "a+") == 0 ||
	    strcmp(type, "a+b") == 0 ||
	    strcmp(type, "ab+") == 0)
    {
	fd = globus_gass_open(filename, O_APPEND|O_CREAT|O_RDWR);
    }
    else
    {
	return GLOBUS_NULL;
    }

    if(fd >= 0)
    {
	/*globus_gass_file_diagnostics_printf("Opening FILE with fd = %i\n", fd);*/
	return fdopen(fd, type);
    }
    else
    {
	return GLOBUS_NULL;
    }
}


int
globus_gass_close(int fd)
{
    int rc;
    globus_l_gass_file_t *file;
    
    if(fd < 0)
    {
	return -1;
    }
    globus_gass_file_enter();
    file = globus_hashtable_remove(&globus_l_gass_file_hash,
				   (void *) fd);
    
    if(file == GLOBUS_NULL)
    {
	close(fd);
	globus_gass_file_exit();
	return 0;
    }
    else
    {
	close(file->fd);
	switch(file->oflag & (O_RDONLY|O_WRONLY|O_APPEND|O_RDWR))
	{
	case (O_RDONLY):
	    globus_gass_cache_delete(&globus_l_gass_file_cache_handle,
			      file->url,
			      globus_l_gass_file_tag,
			      file->timestamp,
			      GLOBUS_FALSE);
	    break;
	case (O_WRONLY|O_APPEND):
	    globus_gass_client_put_socket_close(file->fd,
					 GLOBUS_NULL,
					 GLOBUS_NULL,
					 GLOBUS_NULL);
	    break;
	case (O_WRONLY):
	case (O_RDWR):
	    file->fd = open(file->filename,
			    O_RDONLY);
	    globus_gass_client_put_fd(file->url,
			       GLOBUS_NULL,
			       file->fd,
			       GLOBUS_GASS_LENGTH_UNKNOWN,
			       GLOBUS_GASS_LENGTH_UNKNOWN,
			       GLOBUS_FALSE,
			       GLOBUS_GASS_ACK_COMPLETE,
			       &file->timestamp,
			       &file->total_length,
			       &rc);
	    close(file->fd);
	    globus_gass_cache_delete(&globus_l_gass_file_cache_handle,
			      file->url,
			      globus_l_gass_file_tag,
			      file->timestamp,
			      GLOBUS_FALSE);
			    
	    break;
	default:
	    globus_gass_file_exit();
	    return -1;
	}

	if(file->filename != GLOBUS_NULL)
	{
	    globus_free(file->filename);	    
	}
	globus_free(file->url);
	globus_free(file);
	globus_gass_file_exit();

	return 0;
    }
}

int
globus_gass_fclose(FILE *f)
{
    fflush(f);
    return globus_gass_close(fileno(f));
}


static int
globus_l_gass_add_and_get(globus_l_gass_file_t *file,
		  int oflag,
		  int mode)
{
    int rc;
/* cache_add (with create)
   GLOBUS_GASS_CACHE_ADD_NEW:
       connect to server to get,
       if server connect fails,
           if create,
	       create new file
	   else
	       globus_gass_cache_delete
	       return GLOBUS_GASS_ERROR_NOT_FOUND
	   endif
       else
           get url to local file
       endif
   GLOBUS_GASS_CACHE_ADD_EXISTS:
       ;
   default:
       return rc;
   endif
   
   open local file with (oflag)
   globus_gass_cache_add_done;
*/
    rc = globus_gass_cache_add(&globus_l_gass_file_cache_handle,
			file->url,
			globus_l_gass_file_tag,
			GLOBUS_TRUE,
			&file->timestamp,
			&file->filename);

    switch(rc)
    {
    case GLOBUS_GASS_CACHE_ADD_EXISTS:
	globus_gass_cache_add_done(&globus_l_gass_file_cache_handle,
			    file->url,
			    globus_l_gass_file_tag,
			    file->timestamp);
	break;
    case GLOBUS_GASS_CACHE_ADD_NEW:
	file->fd = open(file->filename,
			O_WRONLY|O_CREAT|O_TRUNC);
	
	rc = globus_gass_client_get_fd(file->url,
				GLOBUS_NULL,
				file->fd,
				GLOBUS_GASS_LENGTH_UNKNOWN,
				&file->timestamp,
				GLOBUS_NULL,
				GLOBUS_NULL);
	close(file->fd);
	if(rc != GLOBUS_SUCCESS &&
	   ((oflag & O_CREAT) != O_CREAT))
	{
		globus_gass_cache_delete(&globus_l_gass_file_cache_handle,
				  file->url,
				  globus_l_gass_file_tag,
				  file->timestamp,
				  GLOBUS_TRUE);
		return GLOBUS_GASS_ERROR_NOT_FOUND;
	}
	else
	{
	    globus_gass_cache_add_done(&globus_l_gass_file_cache_handle,
				file->url,
				globus_l_gass_file_tag,
				file->timestamp);
	}
	break;
    default:
	return rc;
    }
    file->fd = open(file->filename,
		    oflag,
		    mode);
    if(file->fd >= 0)
    {
	globus_hashtable_insert(&globus_l_gass_file_hash,
				(void *) file->fd,
				(void *) file);
	return GLOBUS_SUCCESS;
    }
    else
    {
	return -1;
    }
}

static int
globus_l_gass_add_and_trunc(globus_l_gass_file_t *file,
		    int oflag,
		    int mode)
{
    int rc;
    
    rc = globus_gass_cache_add(&globus_l_gass_file_cache_handle,
			file->url,
			globus_l_gass_file_tag,
			GLOBUS_TRUE,
			&file->timestamp,
			&file->filename);

    if(rc != GLOBUS_GASS_CACHE_ADD_EXISTS &&
       rc != GLOBUS_GASS_CACHE_ADD_NEW)
    {
	return rc;
    }
    else
    {
	file->fd = open(file->filename,
			oflag,
			mode);
	globus_gass_cache_add_done(&globus_l_gass_file_cache_handle,
			    file->url,
			    globus_l_gass_file_tag,
			    file->timestamp);
	if(file->fd >= 0)
	{
	    globus_hashtable_insert(&globus_l_gass_file_hash,
				    (void *) file->fd,
				    (void *) file);
	    return GLOBUS_SUCCESS;
	}
	else
	{
	    return -1;
	}
    }
}
