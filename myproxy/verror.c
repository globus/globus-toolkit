/*
 * verror.c
 *
 * Simple error-handling interface. See verror.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

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

static struct verror_context my_context = { 0, NULL, 0, 0 };

/**********************************************************************
 *
 * Internal constants
 *
 */

/* Values for where_flag to verror_add_string() */
#define VERROR_PREPEND			0
#define VERROR_APPEND			1

/**********************************************************************
 *
 * Internal functions.
 *
 */


/*
 * Added a string to the current error.
 *
 * If where_flag == VERROR_PREPEND, then prepend the string.
 *               == VERROR_APPEND, then append the string.
 */
static void
verror_add_string(const char			*string,
		  int				where_flag)
{
    int				need_cr = 0;
    int				string_len;
    int				new_string_length;
    char			*new_string;
    
    assert(string != NULL);
    
    string_len = strlen(string);
    
    /* Do we need to add a carriage return to the string */
    if (string[string_len - 1] != '\n')
    {
	need_cr = 1;
    }
    
    /* Determine the length of the new string */
    new_string_length = (my_context.string == NULL ?
			 0 : strlen(my_context.string));
    
    new_string_length += strlen(string) + 1 /* NUL */;
    
    if (need_cr == 1)
    {
	new_string_length++;
    }
    
    new_string = malloc(new_string_length);
    
    if (new_string == NULL)
    {
	/* Punt */
	return;
    }

    new_string[0] = '\0';
    
    /* Fill in new_string */
    switch (where_flag) 
    {
      case VERROR_PREPEND:
	strcat(new_string, string);
	if (need_cr)
	{
	    strcat(new_string, "\n");
	}
	if (my_context.string != NULL)
	{
	    strcat(new_string, my_context.string);
	}
	break;
	
      default:
	/* Punt */
      case VERROR_APPEND:
	if (my_context.string != NULL)
	{
	    strcat(new_string, my_context.string);
	}
	strcat(new_string, string);
	if (need_cr)
	{
	    strcat(new_string, "\n");
	}
	break;
    }
    
    /* And put new_string in place */
    if (my_context.string != NULL)
    {
	free(my_context.string);
    }
    
    my_context.string = new_string;
    
    return;
}

	
    
    
/**********************************************************************
 *
 * API Functions
 *
 */

void
verror_prepend_string(const char *format, ...)
{
    char *string = NULL;
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

    verror_add_string(string, VERROR_PREPEND);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}

void
verror_put_string(const char *format, ...)
{
    char *string = NULL;
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

    verror_add_string(string, VERROR_APPEND);
    
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
    if (!my_context.string) {
	return "unknown error";
    }
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

void
verror_print_error(FILE *stream)
{
    if (my_context.number) {
	fprintf(stream, "%s%s\n", verror_get_string(), verror_strerror());
    } else {
	fprintf(stream, "%s", verror_get_string());
    }
}
