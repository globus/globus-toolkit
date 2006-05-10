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
globus_gass_file_api.c 

Description: Implemetation of public gass file access API
             (uses globus_gass_transfer and globus_gass_cache APIs)

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include "globus_gass_file.h"
#include "globus_gass_cache.h"
#include "globus_gass_transfer.h"
#include "globus_gass_copy.h"
#include "version.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
enum
{
    GLOBUS_L_GASS_APPEND_BUFLEN = 4096
};

typedef struct
{
    char *				url;
    char *				filename;
    int					oflag;
    int					fd;
    unsigned long			timestamp;
    unsigned long			total_length;
    FILE *				fp;
    globus_url_scheme_t			scheme_type;
    struct globus_l_gass_file_tailf_s *	append;
} globus_l_gass_file_t;

typedef struct globus_l_gass_file_tailf_s
{
    globus_l_gass_file_t *		file;
    globus_io_handle_t			read_handle;
    globus_size_t			bytes_sent;
    globus_byte_t			buf[GLOBUS_L_GASS_APPEND_BUFLEN];
    globus_bool_t			transfer_in_progress;
    globus_bool_t			ignore;
    globus_bool_t			closing;
    globus_gass_transfer_request_t	request;
} globus_l_gass_file_tailf_t;

/******************************************************************************
                          Module specific variables
******************************************************************************/
enum
{
    GLOBUS_GASS_FILE_TABLE_SIZE=256
};

static volatile globus_bool_t	globus_l_gass_file_inited = GLOBUS_FALSE;
static globus_gass_cache_t	globus_l_gass_file_cache_handle;
static globus_mutex_t		globus_l_gass_file_mutex;
static globus_cond_t		globus_l_gass_file_cond;
static char *			globus_l_gass_file_tag;
static globus_l_gass_file_t *	globus_l_gass_file_table[GLOBUS_GASS_FILE_TABLE_SIZE];
static globus_fifo_t		globus_l_gass_file_append_fifo;
static globus_callback_handle_t	globus_l_gass_file_append_callback_handle;

/******************************************************************************
                          Module definition
******************************************************************************/
static
int
globus_l_gass_file_activate(void);

static
int
globus_l_gass_file_deactivate(void);

globus_module_descriptor_t globus_i_gass_file_module =
{
    "globus_gass_file",
    globus_l_gass_file_activate,
    globus_l_gass_file_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
#if defined(DEBUG_MUTEX)
#define globus_gass_file_enter() printf("Acquiring mutex at [t%d]%s:%d\n", globus_thread_self(), __FILE__, __LINE__), globus_mutex_lock(&globus_l_gass_file_mutex)
#define globus_gass_file_exit()  printf("Releasing mutex at [t%d]%s:%d\n", globus_thread_self(), __FILE__, __LINE__), globus_mutex_unlock(&globus_l_gass_file_mutex)
#else
#define globus_gass_file_enter() globus_mutex_lock(&globus_l_gass_file_mutex)
#define globus_gass_file_exit()  globus_mutex_unlock(&globus_l_gass_file_mutex)
#endif
static
int
globus_l_gass_add_and_trunc(
    globus_l_gass_file_t *		file,
    int					oflag,
    int					mode);

static
int
globus_l_gass_add_and_get(
    globus_l_gass_file_t *		file,
    int					oflag,
    int					mode);

static
void
globus_l_gass_file_append_callback(
    void *			        callback_arg);

static
void
globus_l_gass_file_send_callback(
    void *				user_arg,
    globus_gass_transfer_request_t	request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data);

static
globus_bool_t
globus_l_gass_file_handle_append(
    globus_l_gass_file_tailf_t *	cur);
/******************************************************************************
Function: globus_l_gass_file_activate()

Description: 

Parameters:

Returns:
******************************************************************************/
static
int
globus_l_gass_file_activate(void)
{
    char *				tag;
    int					i;
    globus_reltime_t                    delay_time;
    globus_reltime_t                    period_time;
    
    globus_module_activate(GLOBUS_GASS_COPY_MODULE);
    globus_module_activate(GLOBUS_GASS_CACHE_MODULE);

    globus_mutex_init(&globus_l_gass_file_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_gass_file_cond, GLOBUS_NULL);
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
    for(i = 0; i < GLOBUS_GASS_FILE_TABLE_SIZE; i++)
    {
	globus_l_gass_file_table[i]=GLOBUS_NULL;
    }

    globus_fifo_init(&globus_l_gass_file_append_fifo);

    GlobusTimeReltimeSet(delay_time, 0, 0);    
    GlobusTimeReltimeSet(period_time, 2, 0);    
    globus_callback_register_periodic(
	&globus_l_gass_file_append_callback_handle,
	&delay_time,
	&period_time,
	globus_l_gass_file_append_callback,
	GLOBUS_NULL);
	
    globus_l_gass_file_inited = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}
/* globus_l_gass_file_activate() */

/******************************************************************************
Function: globus_l_gass_file_deactivate()

Description: 

Parameters:

Returns:
******************************************************************************/
static
int
globus_l_gass_file_deactivate(void)
{
    int					i;

    globus_gass_file_enter();

    globus_l_gass_file_inited = GLOBUS_FALSE;

    for(i = 0; i < GLOBUS_GASS_FILE_TABLE_SIZE; i++)
    {
	if(globus_l_gass_file_table[i] != GLOBUS_NULL)
	{
	    if(globus_l_gass_file_table[i]->fp != GLOBUS_NULL)
	    {
		globus_gass_fclose(globus_l_gass_file_table[i]->fp);
	    }
	    else
	    {
		globus_gass_close(globus_l_gass_file_table[i]->fd);
	    }
	}
    }

    if(globus_l_gass_file_tag != GLOBUS_NULL)
    {
	globus_free(globus_l_gass_file_tag);
	globus_l_gass_file_tag = GLOBUS_NULL;
    }
    globus_gass_cache_close(&globus_l_gass_file_cache_handle);

    globus_gass_file_exit();

    globus_mutex_destroy(&globus_l_gass_file_mutex);
    globus_cond_destroy(&globus_l_gass_file_cond);
    
    globus_module_deactivate(GLOBUS_GASS_CACHE_MODULE);
    globus_module_deactivate(GLOBUS_GASS_COPY_MODULE);

    return GLOBUS_SUCCESS;
}
/* globus_l_gass_file_deactivate() */

/******************************************************************************
Function: globus_gass_open()

Description: 

Parameters:

Returns:
******************************************************************************/
int
globus_gass_open(
    char *				url,
    int					oflag,
    ...)
{
    va_list				ap;

    int					fd = -1;
    globus_url_t			globus_url;
    globus_l_gass_file_t *		file;
    int					mode = 0777;
    int					rc;
    int					checkflag;
    char *				unique_prefix;
    globus_l_gass_file_tailf_t *	append;
    globus_gass_transfer_referral_t	referral;
    globus_bool_t			done;
    
    if(url == GLOBUS_NULL)
    {
        return -1;
    }
    if(oflag & O_CREAT)
    {
	va_start(ap, oflag);
	mode = va_arg(ap, int);
	va_end(ap);
    }
    
    if(globus_l_gass_file_inited == GLOBUS_FALSE)
    {
	/* return(-GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED); */
	return(-1);
    }

    rc = globus_url_parse(url, &globus_url);
    if(rc != GLOBUS_SUCCESS ||
       globus_url.scheme_type == GLOBUS_URL_SCHEME_UNKNOWN)
    {
	fd = open(url, oflag, mode);
	globus_url_destroy(&globus_url);
	return fd;
    }
    else if(globus_url.scheme_type == GLOBUS_URL_SCHEME_FILE)
    {
	fd = open(globus_url.url_path, oflag, mode);
	globus_url_destroy(&globus_url);
	return fd;
    }

    
    /* check for invalid combos on GASS urls, note that
     *  O_RDONLY is defined as 0 on most systems, so we have
     *  to be careful on what we check for
     */
    checkflag = oflag & (O_RDONLY|O_RDWR|O_WRONLY|O_APPEND|O_TRUNC);

    if((checkflag == (O_RDONLY|O_APPEND)) ||
       (checkflag == (O_RDWR|O_APPEND)) ||
       (checkflag == (O_RDONLY|O_TRUNC)) ||
       (checkflag == (O_RDWR|O_WRONLY)))
    {
	globus_url_destroy(&globus_url);
	return -1;
    }

    file = (globus_l_gass_file_t *)
	globus_malloc(sizeof(globus_l_gass_file_t));
    file->url = globus_malloc(strlen(url)+1);
    strcpy(file->url, url);
    file->oflag = oflag;
    file->fd = -1;
    file->fp = GLOBUS_NULL;
    file->scheme_type=globus_url.scheme_type;

    globus_gass_file_enter();
    
    if(globus_url.scheme_type == GLOBUS_URL_SCHEME_X_GASS_CACHE)
    {
	rc = globus_l_gass_add_and_trunc(file,
					 oflag,
					 mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}
	globus_url_destroy(&globus_url);

	globus_gass_file_exit();
	return file->fd;
    }

    globus_url_destroy(&globus_url);

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
	globus_free(file->url);
	unique_prefix = globus_get_unique_session_string();
	
	file->url = globus_malloc(strlen(url) +
				  strlen("x-gass-append://") +
				  strlen(unique_prefix) +
				  2);
	sprintf(file->url,
		"x-gass-append://%s/%s",
		unique_prefix,
		url);

	globus_free(unique_prefix);
	rc = globus_l_gass_add_and_trunc(file,
					 oflag,
					 mode);

	if(rc != GLOBUS_SUCCESS)
	{
	    goto failure;
	}

	append = (globus_l_gass_file_tailf_t *)
	    globus_malloc(sizeof(globus_l_gass_file_tailf_t));

	append->file = file;
	globus_io_file_open(file->filename,
			    O_RDONLY,
			    0,
			    GLOBUS_NULL,
			    &append->read_handle);
	append->transfer_in_progress = GLOBUS_FALSE;
	append->ignore = GLOBUS_FALSE;
	append->closing = GLOBUS_FALSE;
	append->bytes_sent = 0;

	memset(&referral,
	       '\0',
	       sizeof(globus_gass_transfer_referral_t));

	done = GLOBUS_FALSE;
	while(!done)
	{
	    globus_gass_transfer_append(&append->request,
					GLOBUS_NULL,
					url,
					GLOBUS_GASS_TRANSFER_LENGTH_UNKNOWN);
	    switch(globus_gass_transfer_request_get_status(append->request))
	    {
	    case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
		if(globus_gass_transfer_referral_get_count(&referral) != 0)
		{
		    globus_gass_transfer_referral_destroy(&referral);
		}
		
		rc = globus_gass_transfer_request_get_referral(
		    append->request,
		    &referral);
		if(rc != GLOBUS_SUCCESS)
		{
		    done = GLOBUS_TRUE;
		    break;
		}
		url = globus_gass_transfer_referral_get_url(&referral,
							    0);
		globus_gass_transfer_request_destroy(append->request);
		if(url == GLOBUS_NULL)
		{
		    done = GLOBUS_TRUE;
		}
		break;
	    case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
	    case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
	    case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
	    case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
		done = GLOBUS_TRUE;
		break;
	    case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
		globus_assert(GLOBUS_FALSE);
		done = GLOBUS_TRUE;
		break;
	    default:
		/* The above are the only documented states which
		 *  globus_gass_transfer_request_get_status can return
		 */
		globus_assert(GLOBUS_FALSE);
		done = GLOBUS_TRUE;
	    }
	}
	if(globus_gass_transfer_request_get_status(append->request) !=
	   GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
	{
	    globus_gass_transfer_request_destroy(append->request);
	    if(globus_gass_transfer_referral_get_count(&referral) != 0)
	    {
		globus_gass_transfer_referral_destroy(&referral);
	    }
	    globus_free(append);

	    /* This is failure *after* adding to cache/file table, so
	     * we need to do more clean up here.
	     */
	    globus_l_gass_file_table[file->fd] = GLOBUS_NULL;
	    close(file->fd);
	    globus_gass_cache_delete(globus_l_gass_file_cache_handle,
				     file->url,
				     globus_l_gass_file_tag,
				     file->timestamp,
				     GLOBUS_FALSE);

	    goto failure;
	}
	file->append = append;
	globus_fifo_enqueue(&globus_l_gass_file_append_fifo,
			    (void *) append);
	break;
    default:
	globus_free(file);
	globus_gass_file_exit();
	/* return GLOBUS_GASS_TRANSFER_ERROR_NOT_SUPPORTED; */
	return -1;
    }
    globus_gass_file_exit();
    return file->fd;

failure:
    free(file->url);
    free(file);
    globus_gass_file_exit();
    return -1;
}
/* globus_gass_open() */

/******************************************************************************
Function: globus_gass_fopen()

Description:

Parameters: 

Returns: 
******************************************************************************/
FILE *
globus_gass_fopen(
    char *				filename,
    char *				type)
{
    int					fd = -1;

    if(filename == GLOBUS_NULL ||
       type == GLOBUS_NULL)
    {
       return GLOBUS_NULL;
    }

    if(strcmp(type, "r") == 0 ||
       strcmp(type, "rb") == 0)
    {
	fd = globus_gass_open(filename, O_RDONLY);
    }
    else if(strcmp(type, "w") == 0 ||
	    strcmp(type, "wb") == 0)
    {
	fd = globus_gass_open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0777);
    }
    else if(strcmp(type, "a") == 0 ||
	    strcmp(type, "ab") == 0)
    {
	fd = globus_gass_open(filename, O_WRONLY|O_APPEND|O_CREAT, 0777);
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
	fd = globus_gass_open(filename, O_RDWR|O_TRUNC|O_CREAT, 0777);
    }
    else if(strcmp(type, "a+") == 0 ||
	    strcmp(type, "a+b") == 0 ||
	    strcmp(type, "ab+") == 0)
    {
	fd = globus_gass_open(filename, O_APPEND|O_CREAT|O_RDWR, 0777);
    }
    else
    {
	return GLOBUS_NULL;
    }

    if(fd >= 0)
    {
	
        if(globus_l_gass_file_table[fd] != GLOBUS_NULL)
        {
	    FILE *			fp;

	    globus_gass_file_enter();

	    globus_l_gass_file_table[fd]->fp = fdopen(fd, type);

	    fp = globus_l_gass_file_table[fd]->fp;
	    
	    globus_gass_file_exit();

	    return fp;
        }
	else
	{
	    return fdopen(fd, type);
	}
    }
    else
    {
	return GLOBUS_NULL;
    }
}
/* globus_gass_fopen() */

/******************************************************************************
Function: globus_gass_close()

Description:

Parameters: 

Returns: 
******************************************************************************/
int
globus_gass_close(
    int					fd)
{
    int					rc = GLOBUS_SUCCESS;
    globus_l_gass_file_t *		file;
    globus_gass_transfer_request_t	request;
    char *				url;
    
    if(fd < 0)
    {
	return -1;
    }
    globus_gass_file_enter();

    file = globus_l_gass_file_table[fd];
    globus_l_gass_file_table[fd] = GLOBUS_NULL;
    
    if(file == GLOBUS_NULL)
    {
	rc = globus_libc_close(fd);
	globus_gass_file_exit();
	return rc;
    }
    else
    {
	globus_libc_close(file->fd);
	if (file->scheme_type == GLOBUS_URL_SCHEME_X_GASS_CACHE)
	{
	    globus_gass_cache_delete(globus_l_gass_file_cache_handle,
				     file->url,
				     globus_l_gass_file_tag,
				     file->timestamp,
				     GLOBUS_FALSE);
	}
	else
	{
	    struct stat			s;
	    
	    switch(file->oflag & (O_RDONLY|O_WRONLY|O_APPEND|O_RDWR))
	    {
	      case (O_RDONLY):
		globus_gass_cache_delete(globus_l_gass_file_cache_handle,
					 file->url,
					 globus_l_gass_file_tag,
					 file->timestamp,
					 GLOBUS_FALSE);
		break;
	      case (O_WRONLY|O_APPEND):
		url = file->url + strlen("x-gass-append://");
		url = strchr(url, '/') + 1;

		file->append->closing = GLOBUS_TRUE;

		while(file->append->transfer_in_progress)
		{
		    globus_cond_wait(&globus_l_gass_file_cond,
				     &globus_l_gass_file_mutex);
		}
		globus_fifo_remove(&globus_l_gass_file_append_fifo,
				   file->append);
		rc = stat(file->filename,
			  &s);

		if(rc != 0)
		{
		    s.st_size = 0;
		}

		/*
		 * flush the rest of whatever's in the append handle
		 * to the server
		 */
		while(file->append->bytes_sent < s.st_size &&
		      globus_gass_transfer_request_get_status(file->append->request) ==
		          GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
		{
		    if(globus_l_gass_file_handle_append(file->append))
		    {
			while(file->append->transfer_in_progress == GLOBUS_TRUE)
			{
			    globus_cond_wait(&globus_l_gass_file_cond,
					     &globus_l_gass_file_mutex);
			}
		    }
		    else
		    {
			break;
		    }
		}
		/* send zero-byte eof */
		file->append->transfer_in_progress = GLOBUS_TRUE;
		globus_gass_transfer_send_bytes(file->append->request,
						file->append->buf,
						0,
						GLOBUS_TRUE,
						globus_l_gass_file_send_callback,
						file->append);
						
		while(file->append->transfer_in_progress == GLOBUS_TRUE &&
		      globus_gass_transfer_request_get_status(file->append->request) ==
		          GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
		{
		    globus_cond_wait(&globus_l_gass_file_cond,
				     &globus_l_gass_file_mutex);
		}
		globus_gass_transfer_request_destroy(file->append->request);
                globus_io_close(&file->append->read_handle);
		globus_free(file->append);

		globus_gass_cache_delete(globus_l_gass_file_cache_handle,
					 file->url,
					 globus_l_gass_file_tag,
					 file->timestamp,
					 GLOBUS_FALSE);
		break;
	      case (O_WRONLY):
	      case (O_RDWR):
	      {
		  globus_gass_copy_handle_t          gass_copy_handle;
		  globus_result_t                    result;
		  char *                             tmp_filename;
		  
		  globus_gass_copy_handle_init(&gass_copy_handle, GLOBUS_NULL);

		  tmp_filename = (char*) globus_libc_malloc
		      (strlen("file:/") +
		       strlen(file->filename) + 2);

		  if(strncmp(file->filename, "/", 1) == 0)
		  {
		      globus_libc_sprintf(
			  tmp_filename,
			  "file:%s",
			  file->filename);
		  }
		  else
		  {
		      globus_libc_sprintf(
			  tmp_filename,
			  "file:/%s",
			  file->filename);
		  }
		  /* put file to url */
		  result = globus_gass_copy_url_to_url(
		      &gass_copy_handle,
		      tmp_filename,
		      GLOBUS_NULL,
		      file->url,
		      GLOBUS_NULL);

		  if (result != GLOBUS_SUCCESS)
		  {
		      globus_libc_fprintf(stderr, "error: %s\n",
			      globus_object_printable_to_string(globus_error_get(result)));
		      /* rc = GLOBUS_GASS_TRANSFER_ERROR_TRANSFER_FAILED; */
		      rc = -1;
		  }
		  globus_gass_copy_handle_destroy(&gass_copy_handle);
		  globus_libc_free(tmp_filename);
		  
	      }
	        globus_gass_cache_delete(globus_l_gass_file_cache_handle,
					 file->url,
					 globus_l_gass_file_tag,
					 file->timestamp,
					 GLOBUS_FALSE);
		
		break;
	      default:
		globus_gass_file_exit();
		return -1;
	    } /* switch(file->oflag... */
	} /* if file->scheme_type =... else */
	
	if(file->filename != GLOBUS_NULL)
	{
	    globus_free(file->filename);	    
	}
	globus_free(file->url);
	globus_free(file);
	globus_gass_file_exit();

	return rc;
    }
}
/* globus_gass_close() */

/******************************************************************************
Function: globus_gass_fclose()

Description:

Parameters: 

Returns: 
******************************************************************************/
int
globus_gass_fclose(
    FILE *				f)
{
    if(f == GLOBUS_NULL)
    {
        return -1;
    }
    fflush(f);
    return globus_gass_close(fileno(f));
}
/* globus_gass_fclose() */

/******************************************************************************
Function: globus_l_gass_add_and_get()

Description:

Parameters: 

Returns: 
******************************************************************************/
static
int
globus_l_gass_add_and_get(
    globus_l_gass_file_t *		file,
    int					oflag,
    int					mode)
{
    int					rc;
    globus_gass_transfer_request_t	request;
    
/* cache_add (with create)
   GLOBUS_GASS_CACHE_ADD_NEW:
       connect to server to get,
       if server connect fails,
           if create,
	       create new file
	   else
	       globus_gass_cache_delete
	       return GLOBUS_GASS_TRANSFER_ERROR_NOT_FOUND
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
    rc = globus_gass_cache_add(globus_l_gass_file_cache_handle,
			       file->url,
			       globus_l_gass_file_tag,
			       GLOBUS_TRUE,
			       &file->timestamp,
			       &file->filename);

    switch(rc)
    {
    case GLOBUS_GASS_CACHE_ADD_EXISTS:
	globus_gass_cache_add_done(globus_l_gass_file_cache_handle,
			    file->url,
			    globus_l_gass_file_tag,
			    file->timestamp);
	break;
    case GLOBUS_GASS_CACHE_ADD_NEW:
    {
	globus_gass_copy_handle_t          gass_copy_handle;
	globus_result_t                    result;
	char *                             tmp_filename;
	
	globus_gass_copy_handle_init(&gass_copy_handle, GLOBUS_NULL);
	
	tmp_filename = (char*) globus_libc_malloc
	    (strlen("file:/") +
	     strlen(file->filename) + 2);
	
	if(strncmp(file->filename, "/", 1) == 0)
	{
	    globus_libc_sprintf(
		tmp_filename,
		"file:%s",
		file->filename);
	}
	else
	{
	    globus_libc_sprintf(
		tmp_filename,
		"file:/%s",
		file->filename);
	}

	/* get file from url */
	result = globus_gass_copy_url_to_url(
	    &gass_copy_handle,
	    file->url, 
	    GLOBUS_NULL,
	    tmp_filename,
	    GLOBUS_NULL);
	
	globus_gass_copy_handle_destroy(&gass_copy_handle);
	globus_libc_free(tmp_filename);
		  
       /*  rc = globus_gass_transfer_assist_get_file_from_url( */
/* 	    &request, */
/* 	    GLOBUS_NULL, */
/* 	    file->url, */
/* 	    file->filename, */
/* 	    GLOBUS_NULL, */
/* 	    GLOBUS_TRUE); */
/* 	globus_gass_transfer_request_destroy(request); */


/*	if(rc != GLOBUS_SUCCESS && */
	if(result != GLOBUS_SUCCESS &&
	   ((oflag & O_CREAT) != O_CREAT))
	{
	    globus_gass_cache_delete(globus_l_gass_file_cache_handle,
				     file->url,
				     globus_l_gass_file_tag,
				     file->timestamp,
				     GLOBUS_TRUE);
	    return GLOBUS_GASS_TRANSFER_ERROR_NOT_FOUND;
	}
	else
	{
	    globus_gass_cache_add_done(globus_l_gass_file_cache_handle,
				       file->url,
				       globus_l_gass_file_tag,
				       file->timestamp);
	}
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
	globus_l_gass_file_table[file->fd] = file;

	return GLOBUS_SUCCESS;
    }
    else
    {
	return -1;
    }
}
/* globus_l_gass_add_and_get() */

/******************************************************************************
Function: globus_l_gass_add_and_trunc()

Description:

Parameters: 

Returns: 
******************************************************************************/
static
int
globus_l_gass_add_and_trunc(
    globus_l_gass_file_t *		file,
    int					oflag,
    int					mode)
{
    int					rc;
    
    rc = globus_gass_cache_add(globus_l_gass_file_cache_handle,
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
	globus_gass_cache_add_done(globus_l_gass_file_cache_handle,
				   file->url,
				   globus_l_gass_file_tag,
				   file->timestamp);
	if(file->fd >= 0)
	{
	    globus_l_gass_file_table[file->fd] = file;

	    return GLOBUS_SUCCESS;
	}
	else
	{
	    return -1;
	}
    }
}
/* globus_l_gass_add_and_trunc() */

static
void
globus_l_gass_file_append_callback(
    void *	                        callback_arg)
{
    globus_fifo_t		processed;
    globus_l_gass_file_tailf_t *cur;

    globus_fifo_init(&processed);
    
    globus_gass_file_enter();
    
    if(globus_fifo_empty(&globus_l_gass_file_append_fifo))
    {
	goto end;
    }
    do
    {
	cur = (globus_l_gass_file_tailf_t *)
	    globus_fifo_dequeue(&globus_l_gass_file_append_fifo);
	
	if(! (cur->transfer_in_progress == GLOBUS_TRUE ||
	      cur->closing == GLOBUS_TRUE ||
	      cur->ignore == GLOBUS_TRUE))
	{
	    globus_l_gass_file_handle_append(cur);
	}
							  
	globus_fifo_enqueue(&processed,
			    (void *) cur);
    }
    while(!globus_fifo_empty(&globus_l_gass_file_append_fifo)  && 
	  !globus_callback_has_time_expired());

    while(!globus_fifo_empty(&processed))
    {
	cur = (globus_l_gass_file_tailf_t *)
	    globus_fifo_dequeue(&processed);

	globus_fifo_enqueue(&globus_l_gass_file_append_fifo,
			    (void *) cur);
    }

	
 end:
    globus_gass_file_exit();
}
/* globus_l_gass_file_append_callback() */

static
void
globus_l_gass_file_send_callback(
    void *				user_arg,
    globus_gass_transfer_request_t	request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data)
{
    globus_l_gass_file_tailf_t *	cur;

    cur = (globus_l_gass_file_tailf_t *) user_arg;
    
    globus_gass_file_enter();
    
    if(last_data == GLOBUS_TRUE)
    {
	cur->ignore = GLOBUS_TRUE;
    }
    cur->transfer_in_progress = GLOBUS_FALSE;
    cur->bytes_sent += length;

    globus_cond_signal(&globus_l_gass_file_cond);
    
    globus_gass_file_exit();
}
/* globus_l_gass_file_append_callback() */

static
globus_bool_t
globus_l_gass_file_handle_append(
    globus_l_gass_file_tailf_t *	cur)
{
    globus_size_t			bytes_read;
    
    /* try to read */
    globus_io_try_read(&cur->read_handle,
		       cur->buf,
		       GLOBUS_L_GASS_APPEND_BUFLEN,
		       &bytes_read);
    
    if(bytes_read == 0)
    {
	return GLOBUS_FALSE;
    }
	
    /* transfer_data */
    cur->transfer_in_progress = GLOBUS_TRUE;
    globus_gass_transfer_send_bytes(cur->request,
				    cur->buf,
				    bytes_read,
				    GLOBUS_FALSE,
				    globus_l_gass_file_send_callback,
				    cur);
    
    return GLOBUS_TRUE;
    
}
