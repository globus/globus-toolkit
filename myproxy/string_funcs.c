/*
 * string_funcs.c
 *
 * String manipulation functions.
 *
 * See string_funcs.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

/**********************************************************************
 *
 * API Functions
 *
 */

int
concatenate_strings(char			*destination,
		    size_t			destination_length,
		    const char			*source_1,
		    ...)
{
    va_list				ap;
    const char				*source;
    int					appended_chars = 0;

    assert(destination != NULL);
    
    /*
     * Subtract current length of destination (and NULL) from
     * destination_length so that it contains the number of characters we can
     * add.
     */
    destination_length -= strlen(destination) + 1 /* for NULL */;
    
    va_start(ap, source_1);

    source = source_1;
    
    while (source != NULL) 
    {
	strncat(destination, source, destination_length - appended_chars);

	appended_chars += strlen(source);
	
	if (appended_chars > destination_length)
	{
	    appended_chars = -1;
	    break;
	}

	source = va_arg(ap, const char *);
    }
    va_end(ap);

    return appended_chars;
}

/*
 * strip_char()
 *
 * strips a string of a given character
 */
void strip_char (char *buf, char ch)
{
   int len,i, k = 0;
   char *tmp;

   tmp = strdup (buf); /* creates a storage */

   len = strlen (buf);

   for (i = 0; i < len; i ++)
   {
      if (buf[i] == ch)
      	continue;
	
      tmp[k++] = buf[i];
   }

   for (i = 0; i < k; i ++) /*copy back */
  	buf[i] = tmp[i];

  buf[i] = '\0';
}
   
     
   


int
concatenate_string(char				*destination,
		   size_t			destination_length,
		   const char			*source)
{
    assert(destination != NULL);
    
    return concatenate_strings(destination, destination_length, source, NULL);
}


int
my_strncpy(char					*destination,
	   const char				*source,
	   size_t				destination_length)

{
    assert(destination != NULL);

    destination[0] = '\0';
    destination_length--;

    return concatenate_string(destination, destination_length, source);
}

char *
my_snprintf(const char *format, ...)
{
    char *string = NULL;
    va_list ap;
    
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    return string;
}

char *
my_vsnprintf(const char				*format,
	     va_list				ap)
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

    while (1)
    {
	char *new_buffer;

	string_len = vsnprintf(buffer, buffer_len,
			       format, ap);
	
	/*
	 * Was buffer big enough? On gnu libc boxes we get -1 if it wasn't
	 * on Solaris boxes we get > buffer_len.
	 */
	if ((/* GNU libc */ string_len != -1) &&
	    (/* Solaris */ string_len <= buffer_len))
	{
	    break;
	}

	buffer_len *= 2;

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

    /* XXX Just got to hope it's big enough */
    string_len = vsprintf(buffer, format, ap);
    
#endif /* !HAVE_VSNPRINTF */
    
    return buffer;
}


/*
 * copy_file()
 *
 * Copy source to destination, creating destination if needed.
 * Set permissions on destination to given mode.
 *
 * Returns 0 on success, -1 on error.
 */
int
copy_file(const char *source,
          const char *dest,
          const mode_t mode)
{
    int src_fd = -1;
    int dst_fd = -1;
    int src_flags = O_RDONLY;
    int dst_flags = O_CREAT | O_EXCL | O_WRONLY;
    char buffer[2048];
    int bytes_read;
    int return_code = -1;
    
    assert(source != NULL);
    assert(dest != NULL);

    src_fd = open(source, src_flags);

    if (src_fd == -1)
    {
        verror_put_errno(errno);
        verror_put_string("opening %s for reading", source);
        goto error;
    }

    unlink(dest);
    dst_fd = open(dest, dst_flags, mode);
    
    if (dst_fd == -1)
    {
        verror_put_errno(errno);
        verror_put_string("opening %s for writing", dest);
        goto error;
    }

    do 
    {
        bytes_read = read(src_fd, buffer, sizeof(buffer)-1);
	buffer[bytes_read]='\0';

        if (bytes_read == -1)
        {
            verror_put_errno(errno);
            verror_put_string("reading %s", source);
            goto error;
        }

        if (bytes_read != 0)
        {
            if (write(dst_fd, buffer, bytes_read) == -1)
            {
                verror_put_errno(errno);
                verror_put_string("writing %s", dest);
                goto error;
            }
      }
    }
    while (bytes_read > 0);
  
    /* Success */
    return_code = 0;
        
  error:
    if (src_fd != -1)
    {
        close(src_fd);
    }
    if (dst_fd != -1)
    {
        close(dst_fd);

        if (return_code == -1)
        {
            unlink(dest);
        }
    }
    
    return return_code;
}
