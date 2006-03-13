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

  free(tmp);
}
     
int
my_append(char **dest, const char *src, ...)
{
    va_list ap;
    size_t len = 1;
    
    assert(dest);

    if (*dest) {
	len += strlen(*dest);
    } else {
	*dest = (char *)malloc(1);
	**dest = '\0';
    }

    va_start(ap, src);
    while (src) {
	len += strlen(src);
	*dest = realloc(*dest, len);
	if (*dest == NULL) {
	    verror_put_errno(errno);
	    return -1;
	}
	strcat(*dest, src);
	src = va_arg(ap, const char *);
    }
    va_end(ap);

    return len-1;
}

int
my_strncpy(char					*destination,
	   const char				*source,
	   size_t				destination_length)

{
    int len;

    assert(destination != NULL);
    assert(source != NULL);

    len = strlen(source);

    if (len >= destination_length) {
	strncpy(destination, source, destination_length-1);
	destination[destination_length-1] = '\0';
	len = -1;
    } else {
	strcpy(destination, source);
    }

    return len;
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

/*
 * buffer_from_file()
 *
 * Read the entire contents of a file into a buffer.
 *
 * Returns 0 on success, -1 on error, setting verror.
 */
int
buffer_from_file(const char			*path,
		 unsigned char			**pbuffer,
		 int				*pbuffer_len)
{
    int				fd = -1;
    int				open_flags;
    int				return_status = -1;
    struct stat			statbuf;
    unsigned char		*buffer = NULL, *b = NULL;
    int				buffer_len;
    int				remaining;
    int				rval;
    
    assert(path != NULL);
    assert(pbuffer != NULL);
    
    open_flags = O_RDONLY;
    
    fd = open(path, open_flags);
    
    if (fd == -1)
    {
	verror_put_string("Failure opening file \"%s\"", path);
	verror_put_errno(errno);
	goto error;
    }
    
    if (fstat(fd, &statbuf) == -1)
    {
	verror_put_string("Failure stating file \"%s\"", path);
	verror_put_errno(errno);
	goto error;
    }

    buffer_len = statbuf.st_size;
    
    b = buffer = malloc(buffer_len+1);
    if (buffer == NULL)
    {
	verror_put_string("malloc() failed");
	verror_put_errno(errno);
	goto error;
    }
    
    remaining = buffer_len;
    while (remaining) {
	rval = read(fd, b, remaining);
	if (rval == -1)
	{
	    verror_put_string("Error reading file \"%s\"", path);
	    verror_put_errno(errno);
	    goto error;
	}
	remaining -= rval;
	b += rval;
    }
    buffer[buffer_len++] = '\0';

    /* Succcess */
    *pbuffer = buffer;
    if (pbuffer_len) *pbuffer_len = buffer_len;
    return_status = 0;

  error:
    if (fd != -1)
    {
	close(fd);
    }
    
    if (return_status == -1)
    {
	if (buffer != NULL)
	{
	    free(buffer);
	}
    }
    
    return return_status;
}

int
make_path(char *path)
{
    struct stat sb;
    char *p;

    assert (path != NULL);

    p = path+1;
    while ((p = strchr(p, '/')) != NULL) {
        *p = '\0';
        if (stat(path, &sb) < 0) {
            if (errno == ENOENT) { /* doesn't exist. create it. */
                myproxy_debug("Creating directory %s", path);
                if (mkdir(path, 0700) < 0) {
                    verror_put_errno(errno);
                    verror_put_string("Failed to create directory %s",
                            strerror(errno));
                    *p = '/';
                    return -1;
                }
            } else {
                verror_put_errno(errno);
                verror_put_string("failed to stat %s", path);
                *p = '/';
                return -1;
            }
        }
        if (!(sb.st_mode & S_IFDIR)) {
            verror_put_string("%s exists and is not a directory", path);
            *p = '/';
            return -1;
        }
        *p = '/';
        p++;
    }

    return 0;
}

int
b64_encode(const char *input, char **output)
{
    BIO *mbio, *b64bio, *bio;
    char *outbuf;
    long inlen, outlen;

    assert(input != NULL);

    mbio = BIO_new(BIO_s_mem());
    b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64bio, mbio);

    inlen = strlen(input);
    if (BIO_write(bio, input, inlen) != inlen) {
	verror_put_string("error in BIO_write when base64 encoding");
	return -1;
    }
    BIO_flush(bio);

    outlen = BIO_get_mem_data(bio, &outbuf);

    *output = malloc(outlen+1);
    memcpy(*output, outbuf, outlen);
    (*output)[outlen] = '\0';

    BIO_free_all(bio);

    return 0;
}

int
b64_decode(const char *input, char **output)
{
    BIO *mbio, *b64bio, *bio;
    long inlen, outlen;

    assert(input != NULL);
    assert(output != NULL);

    mbio = BIO_new_mem_buf((void *)input, -1);
    b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64bio, mbio);

    inlen = strlen(input);
    outlen = inlen*2;

    *output = malloc(outlen+1);

    if ((outlen = BIO_read(bio, *output, outlen)) <= 0) {
	verror_put_string("error in BIO_read when base64 encoding");
	return -1;
    }
    (*output)[outlen] = '\0';
    BIO_free_all(bio);

    return 0;
}

#define TRUSTED_CERT_PATH "/.globus/certificates/"
#define USER_CERT_PATH "/.globus/usercert.pem"
#define USER_KEY_PATH "/.globus/userkey.pem"

/*
** Return the path to the user's home directory.
*/
char *
get_home_path()
{
    char *home = NULL;

    if (getenv("HOME"))
    {
        home = getenv("HOME");
    }
    if (home == NULL) 
    {
        struct passwd *pw;
        
        pw = getpwuid(getuid());
        
        if (pw != NULL)
        {
            home = pw->pw_dir;
        }
    }
    if (home == NULL)
    {
        verror_put_string("Could not find user's home directory\n");
        return NULL;
    } 

    home = strdup(home);
    if (home == NULL)
    {
        verror_put_errno(errno);
        verror_put_string("strdup() failed");
        return NULL;
    }

    return home;
}


/*
** Return the path to the trusted certificates directory.      
**/
char*
get_trusted_certs_path()
{
    char *path = NULL;

    if (getenv("X509_CERT_DIR"))
    {
        path = strdup(getenv("X509_CERT_DIR"));
        
        if (path == NULL)
        {
            verror_put_errno(errno);
            verror_put_string("strdup() failed.");
            return NULL;
        }
        return path;
    }

    path = get_home_path();
        
    if (path == NULL)
    {
        return NULL;
    }   

    if (my_append(&path, TRUSTED_CERT_PATH, NULL) == -1)
    {
        free(path);
        return NULL;
    }
    
    return path;
}

/*
** Given a filename, return the full path of that file as it would
** exist in the trusted certificates directory.
*/
char*
get_trusted_file_path(char *filename)
{
    char *sterile_filename = NULL;
    char *file_path = NULL;
    
    sterile_filename = strdup(filename);
    
    if (sterile_filename == NULL)
    {
        goto error;
    }
    
    sterilize_string(sterile_filename);

    file_path = get_trusted_certs_path();
    
    if (file_path == NULL)
    {
        goto error;
    }

    if (my_append(&file_path, sterile_filename, NULL) == -1)
    {
        goto error;
    }

    /* Success */
    free(sterile_filename);
    
    return file_path;
    
    /* We jump here on error */
  error:        
    if (sterile_filename != NULL)
    {
        free(sterile_filename);
    }
    if (file_path != NULL)
    {
        free(file_path);
    }
    return NULL;
}


int
get_user_credential_filenames( char **certfile, char **keyfile )
{
    if (certfile) {
	*certfile = NULL;
	if (getenv("X509_USER_CERT")) {
	    *certfile = strdup(getenv("X509_USER_CERT"));
	} else {
	    *certfile = get_home_path();
	    if (my_append(certfile, USER_CERT_PATH, NULL) == -1) {
		free(*certfile);
		*certfile = NULL;
	    }
	}
    }
    if (keyfile) {
	if (getenv("X509_USER_KEY")) {
	    *keyfile = strdup(getenv("X509_USER_KEY"));
	} else {
	    *keyfile = get_home_path();
	    if (my_append(keyfile, USER_KEY_PATH, NULL) == -1) {
		free(*keyfile);
		*keyfile = NULL;
	    }
	}
    }

    return 0;
}

/*
 * sterilize_string
 *
 * Walk through a string and make sure that is it acceptable for using
 * as part of a path.
 */
void
sterilize_string(char *string)
{
    /* Characters to be removed */
    char *bad_chars = "/";
    /* Character to replace any of above characters */
    char replacement_char = '-';
    
    assert(string != NULL);
    
    /* No '.' as first character */
    if (*string == '.')
    {
        *string = replacement_char;
    }
    
    /* Replace any bad characters with replacement_char */
    while (*string != '\0')
    {
        if (strchr(bad_chars, *string) != NULL)
        {
            *string = replacement_char;
        }

        string++;
    }

    return;
}

#ifndef HAVE_SETENV
int
setenv(const char *var,
       const char *value,
       int override)
{
    char *envstr = NULL;
    int status;

    assert(var != NULL);
    assert(value != NULL);
    
    /* If we're not overriding and it's already set, then return */
    if (!override && getenv(var))
	return 0;

    envstr = malloc(strlen(var) + strlen(value) + 2 /* '=' and NUL */);

    if (envstr == NULL)
    {
	return -1;
    }
    
    sprintf(envstr, "%s=%s", var, value);

    status = putenv(envstr);

    /* Don't free envstr as it may still be in use */
  
    return status;
}
#endif

#ifndef HAVE_UNSETENV
void
unsetenv(const char *var)
{
    extern char **environ;
    char **p1 = environ;	/* New array list */
    char **p2 = environ;	/* Current array list */
    int len = strlen(var);

    assert(var != NULL);
    
    /*
     * Walk through current environ array (p2) copying each pointer
     * to new environ array (p1) unless the pointer is to the item
     * we want to delete. Copy happens in place.
     */
    while (*p2) {
	if ((strncmp(*p2, var, len) == 0) &&
	    ((*p2)[len] == '=')) {
	    /*
	     * *p2 points at item to be deleted, just skip over it
	     */
	    p2++;
	} else {
	    /*
	     * *p2 points at item we want to save, so copy it
	     */
	    *p1 = *p2;
	    p1++;
	    p2++;
	}
    }

    /* And make sure new array is NULL terminated */
    *p1 = NULL;
}
#endif
