/*
 * verror.c
 *
 * Simple error-handling interface. See verror.h for documentation.
 */

#include "verror.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/**********************************************************************
 *
 * Internal variables.
 *
 */

struct verror_context 
{
    int is_set;
    char *string;
    int value;
    int number;
};

struct verror_context my_context = { 0, NULL, 0, 0 };

/**********************************************************************
 *
 * Internal functions.
 *
 */

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
    
#ifndef HAVE_VSNPRINTF

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
verror_put_string(const char *format, ...)
{
    char *string = NULL;
    char *new_string = NULL;
    int new_string_len;
    va_list ap;
    
    my_context.is_set = 1;
    
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
	
    }

    if (my_context.string == NULL)
    {
	my_context.string = string;

	/* To avoide free() below */
	string = NULL;
    }
    else 
    {
	/* Make existing string buffer long enough */
	new_string_len = strlen(string) +
	    strlen(my_context.string) +
	    1 /* NUL */;
    
	new_string = realloc(my_context.string, new_string_len);
    
	if (new_string == NULL)
	{
	    goto error;
	}

	my_context.string = strcat(new_string, string);
    }
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}

void
verror_put_errno(const int error_number)
{
    my_context.is_set = 1;
    my_context.number = error_number;
}

void
verror_put_value(const int value)
{
    my_context.is_set = 1;
    my_context.value = value;
}

int
verror_is_error()
{
    return my_context.is_set;
}


char *
verror_get_string()
{
    return my_context.string;
}

int
verror_get_errno()
{
    return my_context.number;
}

char *
verror_strerror()
{
    char *return_string;
    
    if (my_context.number == 0)
    {
	return_string = "";
    }
    else
    {
	return_string = strerror(my_context.number);
    }
    return return_string;
}

int
verror_get_value()
{
    return my_context.value;
}

void
verror_clear()
{
    my_context.is_set = 0;

    if (my_context.string != NULL)
    {
	free(my_context.string);
	my_context.string = NULL;
    }
    my_context.value = 0;
    my_context.number = 0;
}

    
