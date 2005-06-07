/*
 * string_funcs.h
 *
 * String manipulation functions.
 */

#ifndef _STRING_FUNCS_H
#define _STRING_FUNCS_H

#include <sys/types.h>
#include <stdarg.h>

/*
 * strip_char()
 *
 * Strips a given string of a given character
 */
void strip_char (char *buf, char ch);

/*
 * concatenate_strings()
 *
 * Append given source string(s) to given destination string. Final source
 * string must be NULL. Maximum length of destination (including terminating
 * NULL) is destination_length.  Return number of characters appended or -1 if
 * destination_length characters was reached and output was truncated.
 */
int
concatenate_strings(char			*destination,
		    size_t			destination_length,
		    const char			*source_1,
		    ... /* More source strings with terminating NULL*/);

/*
 * concatenate_string()
 *
 * Append given source string to given destination string. Maximum length of
 * destination (including terminating NULL) is destination_length.Return number
 * of characters appended or -1 if max_char characters was reached and output
 * was truncated.
 */
int
concatenate_string(char				*destination,
		   size_t			destination_length,
		   const char			*source);

/*
 * myappend()
 *
 * Append one string to another, reallocating the buffer of the target string
 * to size. Uses realloc() - so target string may be relocated and pointer
 * changed. Return -1 on error, 0 otherwise.
 */
int
myappend(char                                   **target,
         char                                   *append);


/*
 * my_strncpy()
 *
 * Copy string from source to destination, which is destination_length
 * characters long. Maximum number of characters copies will be
 * destination_length - 1. Return number of characters copied or -1 if source
 * is was truncated. Result will always be NULL terminated.
 */
int
my_strncpy(char					*destination,
	   const char				*source,
	   size_t				destination_length);

/*
 * my_snprintf()
 *
 * A wrapper around my_vnsprintf() for a variable number of arguments.
 */
char *
my_snprintf(const char				*format, ...);
	     
/*
 * my_vsnprintf()
 *
 * A wrapper around vsnprintf(). For systems without vsnprintf() we just
 * do a vsprintf() and pray to the gods of memory management.
 */
char *
my_vsnprintf(const char				*format,
	     va_list				ap);

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
          const mode_t mode);

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
		 int				*pbuffer_len);

/*
 * make_path()
 *
 * Given a path, create any missing directory conponents.
 *
 * Returns 0 on success, -1 on error, setting verror.
 */
int
make_path(char                                  *path);

/*
 * b64_encode()
 *
 * Base64 encode a string.  Returns an allocated string.
 *
 * Returns 0 on success, -1 on error, setting verror.
 */
int
b64_encode(const char *input, char **output);

/*
 * b64_decode()
 *
 * Base64 decode a string.  Returns an allocated string.
 *
 * Returns 0 on success, -1 on error, setting verror.
 */
int
b64_decode(const char *input, char **output);

/*
** Return the path to the user's home directory.
*/
char *
get_home_path();

/*
** Return the path to the trusted certificates directory.      
**/
char*
get_trusted_certs_path();

/*
** Given a filename, return the full path of that file as it would
** exist in the trusted certificates directory.
*/
char*
get_trusted_file_path(char *filename);

/*
** Return the paths to the user's certificate and key files.
*/
int
get_user_credential_filenames( char **certfile, char **keyfile );

/*
 * sterilize_string
 *
 * Walk through a string and make sure that is it acceptable for using
 * as part of a path.
 */
void
sterilize_string(char *string);

#endif /* _STRING_FUNCS_H */
