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

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>

#define server_ez_enter(r) globus_mutex_lock(&r->mutex);
#define server_ez_exit(r) globus_mutex_unlock(&r->mutex);

typedef struct globus_l_gass_server_ez_s
{
    globus_gass_server_ez_client_shutdown_t callback;
    int requests_outstanding;
    globus_mutex_t mutex;
    unsigned long options;
} globus_l_gass_server_ez_t;

typedef struct globus_gass_server_ez_request_s
{
    globus_gass_server_put_request_t *prequest;
    globus_gass_server_get_request_t *grequest;
    int fd;
    unsigned long timestamp;
    globus_byte_t *line_buffer;
    unsigned long line_buffer_used;
    unsigned long line_buffer_length;
    globus_bool_t special;
    globus_bool_t linebuffer;
    globus_l_gass_server_ez_t *server;
} globus_gass_server_ez_request_t;

/******************************************************************************
                          Module specific variables
******************************************************************************/
static globus_l_gass_server_ez_t *servers[65536];

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static int globus_l_gass_server_ez_put_callback(void *user_arg,
					char *url,
					globus_gass_server_put_request_t *request);
static int globus_l_gass_server_ez_get_callback(void *user_arg,
					char *url,
					globus_gass_server_get_request_t *request,
					unsigned long *timestamp,
					unsigned long *total_length);
static int globus_l_gass_server_ez_tilde_expand(unsigned long options,
					char *inpath,
					char **outpath);

static int globus_l_gass_server_ez_write(int fd,
				globus_byte_t *buf,
				unsigned long buflen);
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
    int url_length;
    int rc;
    globus_l_gass_server_ez_t *server;

    globus_module_activate(GLOBUS_NEXUS_MODULE);
    globus_module_activate(GLOBUS_GASS_SERVER_MODULE);

    server = (globus_l_gass_server_ez_t *)
	globus_malloc(sizeof(globus_l_gass_server_ez_t));

    server->callback = callback;
    server->requests_outstanding = 0;
    server->options = options;
    globus_mutex_init(&server->mutex, NULL);
    server_ez_enter(server);

    rc = globus_gass_server_listen(port,
			    globus_l_gass_server_ez_get_callback,
			    server,
			    globus_l_gass_server_ez_put_callback,
			    server);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    servers[*port] = server;    
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
    server_ez_exit(server);

    return GLOBUS_SUCCESS;
} /* globus_gass_server_ez_init() */

/******************************************************************************
Function: globus_gass_server_ez_shutdown()

Description: 

Parameters: 

Returns: 
******************************************************************************/
int globus_gass_server_ez_shutdown(unsigned short port)
{
    int rc;
    globus_bool_t success=GLOBUS_TRUE;
    while(servers[port]->requests_outstanding != 0)
    {
	globus_poll_blocking();
    }
    globus_gass_server_close(port);

    rc = globus_module_deactivate(GLOBUS_GASS_SERVER_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	success = GLOBUS_FALSE;
    }
    rc = globus_module_deactivate(GLOBUS_NEXUS_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	success = GLOBUS_FALSE;
    }
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
    server = r->server;

    server_ez_enter(server);
    globus_gass_server_get_request_done(request);
    r->server->requests_outstanding--;
    server_ez_exit(server);
    globus_free(r);
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
    globus_l_gass_server_ez_t *server;
    struct stat s;

    r = (globus_gass_server_ez_request_t *) request->user_pointer;
    server = r->server;
    server_ez_enter(server);
	
    if(r->special == GLOBUS_FALSE)
    {
        fstat(r->fd, &s);
        close(r->fd);
    }
    else
    {
	s.st_mtime = 0U;
    }
    r->timestamp = (unsigned long) s.st_mtime;

    globus_gass_server_put_request_done(request,
				 r->timestamp);
    if(r->linebuffer)
    {
	globus_free(r->line_buffer);
    }
    globus_free(r);

    server->requests_outstanding--;
    server_ez_exit(server);
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
    int lastnl,x;
    globus_l_gass_server_ez_t *server;
    
    r = (globus_gass_server_ez_request_t *) request->user_pointer;

    server = r->server;
    lastnl = -1;

    for(x = receive_length; x > 0; x--)
    {
	if(buffer[x-1] == '\n')
	{
	    lastnl = x;
	    break;
	}
    }
    
    if(request->status == GLOBUS_GASS_REQUEST_PENDING)
    {
	if(r->line_buffer != GLOBUS_NULL &&
	   lastnl != -1)
	{
	    globus_l_gass_server_ez_write(r->fd,
				     r->line_buffer,
				     r->line_buffer_used);
	    r->line_buffer_used = 0;
	}
	
	if(lastnl != -1)
	{
	    globus_l_gass_server_ez_write(r->fd,
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
    else if(request->outstanding == 0)
    {
	struct stat s;

	s.st_mtime = (time_t) 0;
	
	if(request->status == GLOBUS_GASS_REQUEST_DONE)
	{
	    if(r->line_buffer != GLOBUS_NULL &&
	       r->line_buffer_used != 0UL)
	    {
		globus_l_gass_server_ez_write(r->fd,
			     r->line_buffer,
			     r->line_buffer_used);
	    }
	    globus_l_gass_server_ez_write(r->fd,
			 buffer,
			 receive_length);
	    fstat(r->fd, &s);
	}
	
	if(r->special == GLOBUS_FALSE)
	{
	    close(r->fd);
	}
	r->timestamp = (unsigned long) s.st_mtime;
	globus_gass_server_put_request_memory_free(request,
					    buffer);
        server_ez_enter(server);
	globus_gass_server_put_request_done(request,
				     r->timestamp);
	if(r->linebuffer)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);

	server->requests_outstanding--;
        server_ez_exit(server);
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
    
    s = (globus_l_gass_server_ez_t *) user_arg;
    if((s->options & GLOBUS_GASS_SERVER_EZ_READ_ENABLE) == 0)
    {
	return -1;
    }
    r = (globus_gass_server_ez_request_t *)
	globus_malloc(sizeof(globus_gass_server_ez_request_t));
    r->grequest = request;
    
    rc = globus_url_parse(url, &parsed_url);
    if(rc != GLOBUS_SUCCESS ||
       parsed_url.url_path == GLOBUS_NULL)
    {
	globus_free(r);
	globus_url_destroy(&parsed_url);
	return -1;
    }

    if(strlen(parsed_url.url_path) == 0)
    {
	globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    rc = globus_l_gass_server_ez_tilde_expand(s->options,
				      parsed_url.url_path,
				      &path);
    r->fd = open(path,
		 O_RDONLY,
		 0666);
    r->grequest = request;
    globus_free(path);
    globus_url_destroy(&parsed_url);
    request->user_pointer = (void *) r;
    r->server = s;

    if(r->fd < 0)
    {
	return -1;
    }
    server_ez_enter(s);
    s->requests_outstanding++;
    server_ez_exit(s);
    globus_gass_server_get_request_fd(request,
			       r->fd,
			       GLOBUS_GASS_LENGTH_UNKNOWN,
			       GLOBUS_GASS_LENGTH_UNKNOWN,
			       GLOBUS_TRUE,
			       globus_l_gass_server_ez_get_fd_done);
    return GLOBUS_SUCCESS;
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
    
    r = (globus_gass_server_ez_request_t *)
	globus_malloc(sizeof(globus_gass_server_ez_request_t));
    r->linebuffer = GLOBUS_FALSE;
    r->prequest = request;
    s = (globus_l_gass_server_ez_t *) user_arg;
    r->server = s;
    rc = globus_url_parse(url, &parsed_url);
    if(rc != GLOBUS_SUCCESS ||
       parsed_url.url_path == GLOBUS_NULL)
    {
        globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    if(strlen(parsed_url.url_path) == 0)
    {
        globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    if(((s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE) == 0) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE) == 0) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE) == 0) &&
       ((s->options & GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE) == 0))
    {
	globus_url_destroy(&parsed_url);
	globus_free(r);
	return -1;
    }

    if(s->options & GLOBUS_GASS_SERVER_EZ_LINE_BUFFER)
    {
	r->line_buffer =  globus_malloc(80);
	r->line_buffer_used = 0UL;
	r->line_buffer_length = 80UL;
	r->linebuffer = GLOBUS_TRUE;
    }

    rc = globus_l_gass_server_ez_tilde_expand(s->options,
				      parsed_url.url_path,
				      &path);

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
    }
    else if(request->append &&
	    s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE)
    {
	r->fd = open(path,
		     O_WRONLY | O_APPEND | O_CREAT,
		     0666);
    }
    else if(s->options & GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE)
    {
	r->fd = open(path,
		     O_WRONLY | O_CREAT | O_TRUNC,
		     0666);
    }
    else
    {
	if(r->linebuffer == GLOBUS_TRUE)
	{
	    globus_free(r->line_buffer);
	}
	globus_free(r);
	globus_url_destroy(&parsed_url);
	return -1;
    }
    server_ez_enter(s);
    s->requests_outstanding++;
    server_ez_exit(s);
    
    globus_free(path);
    globus_url_destroy(&parsed_url);
    request->user_pointer = (void *) r;
    r->special = special;
    if(r->fd >= 0)
    {
	if((r->server->options & GLOBUS_GASS_SERVER_EZ_LINE_BUFFER) == GLOBUS_TRUE)
	{
	    globus_gass_server_put_request_memory(request,
					   NULL,
					   0UL,
					   0UL,
					   globus_gass_server_ez_put_memory_done);
	}
	else
	{
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
    if (inpath[1] == '.' && inpath[2] == '/')
    {
	inpath += 3;
	goto notilde;
    }
    
    
    if(strlen(inpath) < 2 ||
       (((options & GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND) == 0) &&
       ((options & GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND) == 0)))
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
	   if((options & GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND) == 0)
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
	    if((options & GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND) == 0)
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
	    int path_length = 0;
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
Function: globus_l_gass_server_ez_write()

Description: 

Parameters: 

Returns: 
******************************************************************************/
static int
globus_l_gass_server_ez_write(int fd,
		     globus_byte_t *buf,
		     unsigned long buflen)
{
    int written = 0;
    int x;

    while(written < buflen)
    {
	x = write(fd, buf+written, buflen - written);
	if(x < 0)
	{
	    if(errno != EAGAIN)
	    {
		return errno;
	    }
	    else
	    {
		x = 0;
	    }
	}
	written += x;
    }
    return 0;
} /* globus_l_gass_server_ez_write() */
