/*
 * myproxy_log.c
 *
 * See myproxy_log.h for documentation.
 */

#include "myproxy_log.h"

#include "verror.h"

#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

/**********************************************************************
 *
 * Internal Variables
 *
 */

struct myproxy_log_context 
{
    int syslog_facility;
    char *syslog_name;
    int debug_level;
    FILE *log_stream;
};

static struct myproxy_log_context my_context = 
{
    0,
    NULL,
    0,
    NULL
};



/**********************************************************************
 *
 * Internal Functions
 *
 */

/*
 * do_log()
 *
 * Do the actual logging of the given string.
 */
static void
do_log(const char *string, int level)
{
    if (my_context.syslog_facility != 0) 
    {
	/* Use "%s" here to prevent problems from "%s" in string. */
	syslog(my_context.syslog_facility|level, "%s: %s",
	       my_context.syslog_name, string);
    }
    
    if (my_context.log_stream != NULL)
    {
	fprintf(my_context.log_stream, "%s\n", string);
    }
	       
    return;
}

/*
 * my_vsnprintf()
 *
 * Wrapper around vsnprintf(). Returned an allocated buffer.
 */
static char *
my_vsnprintf(const char *format, va_list ap)
{
    char *buffer = NULL;
    int buffer_len = 1024;
    int string_len = -1;

    buffer = malloc(buffer_len);
    
    if (buffer == NULL)
    {
	/* Punt */
	return NULL;
    }
    
#ifdef HAVE_VSNPRINTF

    while (string_len == -1)
    {
	char *new_buffer;

	string_len = vsnprintf(buffer, buffer_len,
			       format, ap);
	
	if (string_len == -1)
	{
	    buffer_len *= 2;
	}

	new_buffer = realloc(buffer, buffer_len);
	
	if (new_buffer == NULL)
	{
	    /* Punt */
	    if (buffer != NULL)
	    {
		free(buffer);
	    }
	    return NULL;
	}
	
	buffer = new_buffer;
	
    }
#else /* !HAVE_VSNPRINTF */

    /* Just got to hope it's big enough */
    string_len = vsprintf(buffer, format, ap);
    

#endif /* !HAVE_VSNPRINTF */

    return buffer;
}

/**********************************************************************
 *
 * API Functions
 *
 */

void
myproxy_log_use_syslog(const int facility,
		       const char *name)
{
    my_context.syslog_facility = facility;
    my_context.syslog_name = (name == NULL) ? NULL : strdup(name);
}

void
myproxy_log_use_stream(FILE *stream)
{
    my_context.log_stream = stream;
}


void
myproxy_log(const char *format, ...)
{
    char *string = NULL;
    va_list ap;
    
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
    }
    
    do_log(string, LOG_NOTICE);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}

void
myproxy_log_verror()
{
    do_log(verror_get_string(), LOG_ERR);
    
    return;
}

void
myproxy_log_close()
{
    my_context.syslog_facility = 0;
    
    if (my_context.syslog_name != NULL)
    {
	free(my_context.syslog_name);
	my_context.syslog_name = NULL;
    }
    
    my_context.debug_level = 0;
    
    my_context.log_stream = NULL;
}


int
myproxy_debug_set_level(int level)
{
    int old_level = my_context.debug_level;

    my_context.debug_level = level;

    return old_level;
}


void
myproxy_debug(const char *format, ...)
{
    char *string = NULL;
    va_list ap;

    if (my_context.debug_level == 0)
    {
	return;
    }
	
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
    }
    
    do_log(string, LOG_NOTICE);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}
