/******************************************************************************
globus_gass_server_ez.c
 
Description:
    Simple File Server Library Implementation using GASS Server API
 
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
#include "globus_gass_server_ez.h"
#include "globus_i_gass_common.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>

/******************************************************************************
                               Type definitions
******************************************************************************/
/* Data type associated with each server_ez listener */
typedef struct globus_l_gass_server_ez_s
{
    globus_gass_server_ez_client_shutdown_t callback;
    unsigned long options;
    unsigned short port;
} globus_l_gass_server_ez_t;

/* Data type associated with each put request handled by the server_ez
 * library
 */
typedef struct globus_gass_server_ez_request_s
{
    int fd;
    unsigned long timestamp;
    globus_byte_t *line_buffer;
    unsigned long line_buffer_used;
    unsigned long line_buffer_length;
    globus_bool_t special;
    globus_bool_t linebuffer;
    unsigned short port;
} globus_gass_server_ez_request_t;

/******************************************************************************
                          Module specific variables
******************************************************************************/
#define GLOBUS_L_GASS_SERVER_EZ_MAX_LISTENERS 65536
static globus_l_gass_server_ez_t *globus_l_gass_servers[GLOBUS_L_GASS_SERVER_EZ_MAX_LISTENERS];
static globus_mutex_t globus_l_gass_server_ez_mutex;

/******************************************************************************
                          Module definition
******************************************************************************/
static int
globus_l_gass_server_ez_activate(void);

static int
globus_l_gass_server_ez_deactivate(void);

static globus_module_descriptor_t globus_l_gass_server_ez_module =
{
    "globus_gass_server_ez",
    globus_l_gass_server_ez_activate,
    globus_l_gass_server_ez_deactivate,
    GLOBUS_NULL
};

#define GLOBUS_L_GASS_SERVER_EZ_MODULE (&globus_l_gass_server_ez_module)
/******************************************************************************
                          Module specific prototypes
******************************************************************************/
/* callbacks called by globus_gass_server library when a request arrives */
static int globus_l_gass_server_ez_put_callback(void *user_arg,
						char *url,
						globus_gass_server_put_request_t *request);
static int globus_l_gass_server_ez_get_callback(void *user_arg,
						char *url,
						globus_gass_server_get_request_t *request,
						unsigned long *timestamp,
						unsigned long *total_length);

/* callbacks to handle completed send or receive of part of the request's data */
static void globus_l_gass_server_ez_get_fd_done(globus_gass_server_get_request_t *request,
						int fd,
						unsigned long send_length);

static void globus_gass_server_ez_put_fd_done(globus_gass_server_put_request_t *request,
					      int fd,
					      unsigned long receive_length);

static void globus_gass_server_ez_put_memory_done(globus_gass_server_put_request_t *request,
						  globus_byte_t *buffer,
						  unsigned long buffer_length,
						  unsigned long receive_length);
/* utility routines */
static int globus_l_gass_server_ez_tilde_expand(unsigned long options,
						char *inpath,
						char **outpath);
#define globus_l_gass_server_ez_enter() globus_mutex_lock(&globus_l_gass_server_ez_mutex)
#define globus_l_gass_server_ez_exit()	globus_mutex_unlock(&globus_l_gass_server_ez_mutex)

/******************************************************************************
Function: globus_gass_server_ez_init()

Description: 

Parameters: 

Returns: 
******************************************************************************/
int
globus_gass_server_ez_init(unsigned short *port,
			   char **url,
			   unsigned long options,
			   globus_gass_server_ez_client_shutdown_t callback)
{
    char host[1024];
    size_t url_length;
    int rc;
    globus_l_gass_server_ez_t *server;

    globus_module_activate(GLOBUS_L_GASS_SERVER_EZ_MODULE);

    globus_l_gass_server_ez_enter();

    if(*port != 0 &&
       globus_l_gass_servers[*port] != GLOBUS_NULL)
    {
	*port = 0;
	
	globus_l_gass_server_ez_exit();
	
	return GLOBUS_GASS_ERROR_BAD_PORT;
    }

    server = (globus_l_gass_server_ez_t *)
	globus_malloc(sizeof(globus_l_gass_server_ez_t));

    server->callback = callback;
    server->options = options;

    rc = globus_gass_server_listen(port,
				   globus_l_gass_server_ez_get_callback,
				   server,
				   globus_l_gass_server_ez_put_callback,
				   server);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gass_server_ez_exit();

	return rc;
    }

    if(*port != 0 &&
       globus_l_gass_servers[*port] != GLOBUS_NULL)
    {
	*port = 0;
	globus_gass_server_close(*port);
	globus_l_gass_server_ez_exit();
	return GLOBUS_GASS_ERROR_BAD_PORT;
    }
    server->port = *port;
    globus_l_gass_servers[*port] = server;    

    globus_l_gass_server_ez_exit();

    globus_libc_gethostname(host, 1024);
    url_length = 0;
    url_length += 9; /* x-gass:// */
    url_length += strlen(host);
    url_length += 1; /* : */
    url_length += 5; /* largest port # is 65536 */
    url_length += 1; /* \0 */

    *url =  globus_malloc(url_length);
    
    globus_nexus_stdio_lock();
    sprintf(*url, "x-gass://%s:%u", host, (unsigned int) *port);
    globus_nexus_stdio_unlock();

    return GLOBUS_SUCCESS;
} /* globus_gass_server_ez_init() */

/******************************************************************************
Function: globus_gass_server_ez_shutdown()

Description: 

Parameters: 

Returns: 
******************************************************************************/
int
globus_gass_server_ez_shutdown(unsigned short port)
{
    int rc;
    globus_bool_t success=GLOBUS_TRUE;
    int mycount=0;
    globus_l_gass_server_ez_t *server;

    globus_l_gass_server_ez_enter();
    
    server = globus_l_gass_servers[port];
    globus_l_gass_servers[port] = GLOBUS_NULL;

    if(server == GLOBUS_NULL)
    {
	globus_l_gass_server_ez_exit();
	return GLOBUS_GASS_ERROR_BAD_PORT;
    }
    
    /* Disallow any new requests */
    rc = globus_gass_server_close(port);

    globus_l_gass_server_ez_exit();

    /* Deactivate modules we needed */
    rc = globus_module_deactivate(GLOBUS_L_GASS_SERVER_EZ_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	success = GLOBUS_FALSE;
    }
    globus_free(server);
    
    return success;
} /* globus_gass_server_ez_shutdown() */

/******************************************************************************
Function: globus_l_gass_server_ez_get_fd_done()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static void
globus_l_gass_server_ez_get_fd_done(globus_gass_server_get_request_t *request,
				    int fd,
				    unsigned long send_length)
{
    globus_gass_server_ez_request_t *r;
    globus_l_gass_server_ez_t *server;
    
    r = (globus_gass_server_ez_request_t *) request->user_pointer;
    close(r->fd);
    
    globus_free(r);

    globus_gass_server_get_request_done(request);
} /* globus_l_gass_server_ez_get_fd_done() */

/******************************************************************************
Function: globus_l_gass_server_ez_put_fd_done()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static void
globus_gass_server_ez_put_fd_done(globus_gass_server_put_request_t *request,
				  int fd,
				  unsigned long receive_length)
{
    globus_gass_server_ez_request_t *r;
    struct stat s;

    /* When this function is called, the request either is done, or failed.
     * In any case, we should be able to clean up the request-related structures
     */
    r = (globus_gass_server_ez_request_t *) request->user_pointer;

    /* Don't close /dev/<*> files, as we didn't open them */
    if(r->special == GLOBUS_FALSE)
    {
        globus_libc_fstat(r->fd, &s);
        globus_libc_close(r->fd);
    }
    else
    {
	s.st_mtime = 0U;
    }
    r->timestamp = (unsigned long) s.st_mtime;

    globus_gass_server_put_request_done(request,
					r->timestamp);
    globus_free(r);
} /* globus_l_gass_server_ez_put_fd_done() */

/******************************************************************************
Function: globus_l_gass_server_ez_put_memory_done()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static void
globus_gass_server_ez_put_memory_done(globus_gass_server_put_request_t *request,
				      globus_byte_t *buffer,
				      unsigned long buffer_length,
				      unsigned long receive_length)
{
    globus_gass_server_ez_request_t *r;
    unsigned long lastnl, x;
    int outstanding;
    int status;
    
    /* This callback handles line-buffered put requests. Whenever this
     * is called request->outstanding should be '0', because we only
     * feed one buffer into the globus_gass_server library at a time
     */    
    r = (globus_gass_server_ez_request_t *) request->user_pointer;
    outstanding = request->outstanding;
    status = request->status;
    lastnl = 0UL;

    /* find last \n in the buffer, since we are line-buffering */
    for(x = receive_length; x > 0UL; x--)
    {
	if(buffer[x-1] == '\n')
	{
	    lastnl = x;
	    break;
	}
    }
    
    if(status == GLOBUS_GASS_REQUEST_PENDING)
    {
	/* data arrived, and more will be available, so write up until
	 * the last \n we've received and save the rest
	 */
	if(r->line_buffer != GLOBUS_NULL &&
	   lastnl != 0UL &&
	    r->line_buffer_used != 0UL)
	{
	    globus_i_gass_write(r->fd,
				r->line_buffer,
				r->line_buffer_used);
	    r->line_buffer_used = 0UL;
	}
	
	if(lastnl != 0UL)
	{
	    globus_i_gass_write(r->fd,
				buffer,
				lastnl);
	}
	else
	{
	    lastnl = 0;
	}
	if(r->line_buffer_used + receive_length - lastnl >
	   r->line_buffer_length)
	{
	    r->line_buffer = (globus_byte_t *)
		realloc(r->line_buffer,
			r->line_buffer_used + receive_length - lastnl);
	    r->line_buffer_length = r->line_buffer_used + receive_length - lastnl;
	    memcpy(r->line_buffer + r->line_buffer_used,
		   buffer + lastnl,
		   receive_length - lastnl);
	    r->line_buffer_used += receive_length - lastnl;
	}
	else
	{
	    memcpy(r->line_buffer + r->line_buffer_used,
		   buffer + lastnl,
		   receive_length - lastnl);
	    r->line_buffer_used += receive_length - lastnl;
	}
	
	globus_gass_server_put_request_memory(request,
					      buffer,
					      buffer_length,
					      1UL,
					      globus_gass_server_ez_put_memory_done);
    }
    else
    {
	struct stat s;

	s.st_mtime = (time_t) 0;
	
	if(r->line_buffer != GLOBUS_NULL &&
	   r->line_buffer_used != 0UL)
	{
	    globus_i_gass_write(r->fd,
				r->line_buffer,
				r->line_buffer_used);
	}
	if(receive_length != 0UL)
	{
	    globus_i_gass_write(r->fd,
				buffer,
				receive_length);
	}

	/* This should _always_ be the case */
	if(outstanding == 0)
	{
	    fstat(r->fd, &s);
	    
	    if(r->special == GLOBUS_FALSE)
	    {
		globus_libc_close(r->fd);
	    }
	    r->timestamp = (unsigned long) s.st_mtime;

	    if(buffer != GLOBUS_NULL)
	    {
		globus_gass_server_put_request_memory_free(request,
							   buffer);
	    }
	    globus_gass_server_put_request_done(request,
						r->timestamp);
	    if(r->linebuffer)
	    {
		globus_free(r->line_buffer);
	    }
	    globus_free(r);
	}
    }
} /* globus_l_gass_server_ez_put_memory_done() */

/******************************************************************************
Function: globus_l_gass_server_ez_get_callback()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_get_callback(void *user_arg,
				     char *url,
				     globus_gass_server_get_request_t *request,
				     unsigned long *timestamp,
				     unsigned long *total_length)
{
    globus_url_t parsed_url;
    globus_gass_server_ez_request_t *r;
    char *path;
    int rc;
    globus_l_gass_server_ez_t *s;

    /* Figure out what server options we are using */
    s = (globus_l_gass_server_ez_t *) user_arg;
    if((s->options & GLOBUS_GASS_SERVER_EZ_READ_ENABLE) == 0UL)
    {
	return -1;
    }
    /* Create request-specific structure, and associate with server */
    r = (globus_gass_server_ez_request_t *)
	globus_malloc(sizeof(globus_gass_server_ez_request_t));
    r->port = s->port;

    /* parse the requested url, and see if we can handle it*/
    rc = globus_url_parse(url, &parsed_url);
    if(rc != GLOBUS_SUCCESS ||
       parsed_url.url_path == GLOBUS_NULL)
    {
	globus_free(r);
	globus_url_destroy(&parsed_url);
	return -1;
    }

    if(strlen(parsed_url.url_path) == 0U)
    {
	globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    /* expand the ~ and ~user prefix to the path, if it is in the options */
    rc = globus_l_gass_server_ez_tilde_expand(s->options,
					      parsed_url.url_path,
					      &path);
    /* open the local file to serve */
    r->fd = globus_libc_open(path,
			     O_RDONLY);

    /* free up non-needed memory */
    globus_free(path);
    globus_url_destroy(&parsed_url);
    request->user_pointer = (void *) r;

    if(r->fd < 0)
    {
	globus_free(r);
	return -1;
    }

    /* request the first data for this request */
    rc = globus_gass_server_get_request_fd(request,
					   r->fd,
					   GLOBUS_GASS_LENGTH_UNKNOWN,
					   GLOBUS_GASS_LENGTH_UNKNOWN,
					   GLOBUS_TRUE,
					   globus_l_gass_server_ez_get_fd_done);

    return rc;
} /* globus_l_gass_server_ez_get_callback() */

/******************************************************************************
Function: globus_l_gass_server_ez_put_callback()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_put_callback(void *user_arg,
				     char *url,
				     globus_gass_server_put_request_t *request)
{
    globus_url_t parsed_url;
    globus_gass_server_ez_request_t *r;
    char *path;
    globus_bool_t special = GLOBUS_FALSE;
    int rc;
    globus_l_gass_server_ez_t *s;

    s = (globus_l_gass_server_ez_t *) user_arg;

    /* Check for valid URL */
    rc = globus_url_parse(url, &parsed_url);
    if(rc != GLOBUS_SUCCESS ||
       parsed_url.url_path == GLOBUS_NULL)
    {
        globus_url_destroy(&parsed_url);
	return -1;
    }
    if(strlen(parsed_url.url_path) == 0U)
    {
        globus_url_destroy(&parsed_url);
	return -1;
    }

    /* Allocate and initialize the request-specific data structure */
    r = (globus_gass_server_ez_request_t *)
	globus_malloc(sizeof(globus_gass_server_ez_request_t));
    r->linebuffer = GLOBUS_FALSE;
    r->port = s->port;

    /* Check to see if this is a request we are allowed to handle */
    if(((s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE) == 0UL) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE) == 0UL) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE) == 0UL) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE) == 0UL))
    {
	globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    /* Enable line buffering in the request structure, if it is wanted */ 
    if(s->options & GLOBUS_GASS_SERVER_EZ_LINE_BUFFER)
    {
	r->line_buffer		= globus_malloc(80);
	r->line_buffer_used 	= 0UL;
	r->line_buffer_length	= 80UL;
	r->linebuffer		= GLOBUS_TRUE;
    }

    /* Epand ~ and ~user prefix if enaabled in options */
    rc = globus_l_gass_server_ez_tilde_expand(s->options,
					      parsed_url.url_path,
					      &path);

    /* Check for "special" file names, and if we will handle them */
    if(strcmp(path, "/dev/stdout") == 0 &&
       (s->options & GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE))
    {
        r->fd = fileno(stdout);
	special = GLOBUS_TRUE;
    }
    else if(strcmp(path, "/dev/stdout") == 0)
    {
	if(r->linebuffer == GLOBUS_TRUE)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);
	globus_url_destroy(&parsed_url);
	return -1;
    }
    else if(strcmp(path, "/dev/stderr") == 0 &&
	      (s->options & GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE))
    {
	r->fd = fileno(stderr);
	special = GLOBUS_TRUE;
    }
    else if(strcmp(path, "/dev/stderr") == 0)
    {
	if(r->linebuffer == GLOBUS_TRUE)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);
	globus_url_destroy(&parsed_url);
	return -1;
    }
    else if(strcmp(path, "/dev/globus_gass_client_shutdown") == 0)
    {
	if(s->options & GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE &&
	   s->callback != GLOBUS_NULL)
	{
	    s->callback();
	}
	if(r->linebuffer == GLOBUS_TRUE)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);
	globus_url_destroy(&parsed_url);
	globus_free(path);
	return -1;
    } /* non-special file, try to open an fd for it */
    else if(request->append &&
	    s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE)
    {
	r->fd = globus_libc_open(path,
				 O_WRONLY | O_APPEND | O_CREAT,
				 0777);
    }
    else if(s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE)
    {
	r->fd = globus_libc_open(path,
				 O_WRONLY | O_CREAT | O_TRUNC,
				 0777);
    }
    else
    {
	if(r->linebuffer == GLOBUS_TRUE)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);
	globus_free(path);
	globus_url_destroy(&parsed_url);
	return -1;
    }

    /* free no-longer needed memory */
    globus_free(path);
    globus_url_destroy(&parsed_url);
    request->user_pointer = (void *) r;
    r->special = special;

    /* if globus_libc_open()s succeeded, put in data request, otherwise fail out */
    if(r->fd >= 0)
    {
	/* If line-buffered, then we need to handle this request, piece by piece */
	if((s->options & GLOBUS_GASS_SERVER_EZ_LINE_BUFFER) != 0UL)
	{
	    globus_gass_server_put_request_memory(request,
						  NULL,
						  0UL,
						  0UL,
						  globus_gass_server_ez_put_memory_done);
	}
	else
	{
	    /* Otherwise, we can handle it in one chunk */
	    globus_gass_server_put_request_fd(request,
					      r->fd,
					      GLOBUS_GASS_LENGTH_UNKNOWN,
					      GLOBUS_GASS_LENGTH_UNKNOWN,
					      globus_gass_server_ez_put_fd_done);
	}
	return GLOBUS_SUCCESS;
    }
    else
    {
	globus_free(r);
	
	return -1;
    }
} /* globus_l_gass_server_ez_put_callback() */

/******************************************************************************
Function: globus_l_gass_server_ez_tilde_expand()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_tilde_expand(unsigned long options,
			     char *inpath,
			     char **outpath)
{
    struct passwd pwd;
    char buf[1024];
    
    /*
     * If this is a relative path, the strip off the leading /./
     */
    if(strlen(inpath) >= 2U)
    {
	if (inpath[1] == '.' && inpath[2] == '/')
	{
	    inpath += 3;
	    goto notilde;
	}
    }
    
    if(strlen(inpath) < 2U ||
       (((options & GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND) == 0UL) &&
       ((options & GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND) == 0UL)))
    {
        goto notilde;
    }
    if(inpath[1] == '~')
    {
	int pos = 2;
	char *username;
	struct passwd *pw;

	while(isalnum(inpath[pos]))
	{
	    pos++;
	}
	if(pos == 2)
	{
	   if((options & GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND) == 0UL)
	   {
	       goto notilde;
	   }
	    /* expand ~ to home of current user */
           globus_libc_getpwuid_r(getuid(),
				  &pwd,
				  buf,
				  1024,
				  &pw);
	}
	else
	{
	    if((options & GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND) == 0UL)
	    {
	       goto notilde;
	    }
	    /* expand ~ to home of current user */
	    username = globus_malloc(pos-1);
	    strncpy(username,
		    &inpath[2],
		    pos-2);
	    username[pos-2] = '\0';

	    globus_libc_getpwnam_r(username,
				   &pwd,
				   buf,
				   1024,
				   &pw);
	    globus_free(username);
	}
	if(pw != NULL)
	{
	    size_t path_length = 0;
	    path_length += strlen(pw->pw_dir);
	    path_length += strlen(inpath)-pos+1;
	    path_length += 1;
	    
	    *outpath = globus_malloc(path_length);
	    strcpy(*outpath, pw->pw_dir);
	    strcat(*outpath, &inpath[pos]);
	}
	else
	{
	    *outpath = globus_malloc(strlen(inpath)+1);
	    strcpy(*outpath, inpath);
	}
    }
    else
    {
	goto notilde;
    }
    return GLOBUS_SUCCESS;
notilde:
    *outpath = globus_malloc(strlen(inpath)+1);
    strcpy(*outpath, inpath);
    return GLOBUS_SUCCESS;
} /* globus_l_gass_server_ez_tilde_expand() */

/******************************************************************************
Function: globus_l_gass_server_ez_deactivate()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_activate(void)
{
    int rc;
    int i;
    
    rc = globus_module_activate(GLOBUS_GASS_SERVER_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    for(i = 0; i < GLOBUS_L_GASS_SERVER_EZ_MAX_LISTENERS; i++)
    {
	globus_l_gass_servers[i] = GLOBUS_NULL;
    }
    globus_mutex_init(&globus_l_gass_server_ez_mutex,
		      GLOBUS_NULL);
    return GLOBUS_SUCCESS;
} /* globus_l_gass_server_ez_activate() */

/******************************************************************************
Function: globus_l_gass_server_ez_deactivate()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_deactivate(void)
{
    int rc;
    
    globus_mutex_destroy(&globus_l_gass_server_ez_mutex);

    globus_gass_server_wait_for_requests();
    
    rc = globus_module_deactivate(GLOBUS_GASS_SERVER_MODULE);

    return rc;
} /* globus_l_gass_server_ez_deactivate() */
