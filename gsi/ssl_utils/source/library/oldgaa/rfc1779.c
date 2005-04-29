/*********************************************************************

rfc1779.c

Description:
	Routines to parse subjects names that are in RFC 1779 format
	and convert them to the format used internally by SSLeay

CVS Information:
	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/
/**********************************************************************
                             Include header files
**********************************************************************/

#include <string.h>
#include <ctype.h>					/* for isxdigit() */
#include <stdlib.h>					/* for realloc() */
#include <errno.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                                Definitions
**********************************************************************/
/* End of line characters */
#define END_OF_LINE_CHARS		"\n"

/* Escaping characters */
#define ESCAPING_CHARS		       	"\\"

/* Hex representation character */
#define HEX_CHARS			"x"

/* String terminator character */
#ifndef NUL
#define NUL				'\0'
#endif /* NUL */

/* Chunk size at which to grow buffer (arbitrary value) */
#define BUFFER_CHUNK_SIZE		16

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

static void handle_error(char **errstring,
			 const char * const message);

static int xdigit_to_value(char xdigit);

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
                              Exported Functions
**********************************************************************/

/******************************************************************************
Function:   gridmap_ssleay_rfc1779_name_parse
Description:
	Function that takes a string representing a distinguished name
	and parse all the escaped characters and hexcodes as layed out
	in RFC 1779.

Parameters:
	rfc1779_string, the string with escaped characters

	imported_name, pointer to a pointer that will be set to
	point at an allocated string with the parsed name.

	errstring, pointer to a pointer that will be set to point
	at an allocated string with a description of an error, if
	an error occurs.
	

Returns:
	0 on success, non-zero on error.

******************************************************************************/

int
oldgaa_rfc1779_name_parse(
  char *				rfc1779_string,
  char **				imported_name,
  char **				errstring)
{
  /* Is the current character escaped? (Previous char was backslash) */
  int					escaped = 0;

  /* Buffer we are putting resulting name into */
  char *				buffer = NULL;

  /* Buffer's length in bytes */
  int					buffer_len = 0;

  /* And our current position in buffer */
  int					buffer_index = 0;

  /* Character we're currently looking at */
  char					rfc1779_char;


  /*
   * Check input parameters for legality
   */
  if (!rfc1779_string)
  {
    handle_error(errstring, "bad input string parameter");
    errno = EINVAL;
    goto error_return;
  }

  if (!imported_name)
  {
    handle_error(errstring, "bad output string parameter");
    errno = EINVAL;
    goto error_return;
  }

  buffer_len = strlen(rfc1779_string);

  buffer = malloc(buffer_len);

  if (buffer == NULL)
  {
    handle_error(errstring, "out of memory");
    goto error_return;
  }

  /*
   * Walk through the name, parsing as we go
   */
  while ((rfc1779_char = *(rfc1779_string++)) != NUL)
  {
    /* Unescaped backslash */
    if (strchr(ESCAPING_CHARS, rfc1779_char) && !escaped)
    {
      escaped = 1;
      continue;
    }

    /* Unescaped newline */
    if (strchr(END_OF_LINE_CHARS, rfc1779_char) && !escaped)
    {
      handle_error(errstring, "closing double quote delimitor missing");
      goto error_return;
    }

    /* Escaped hex character - e.g. '\xfe' */
    if (strchr(HEX_CHARS, rfc1779_char) && escaped)
    {
      if (isxdigit(*rfc1779_string) &&
	  isxdigit(*(rfc1779_string + 1)))
      {
	/* Set rfc1779_char to value represented by hex value */
	rfc1779_char =
	  xdigit_to_value(*rfc1779_string) << 4 +
	  xdigit_to_value(*(rfc1779_string + 1));
	
	rfc1779_string += 2;
      }
      else
      {
	handle_error(errstring, "bad hex character format");
	goto error_return;
      }
    }

    /*
     * Ok, we now have the character in rfc1779_char to be appended
     * to our output string.
     *
     * First, make sure we have enough room in our output buffer.
     */
    if ((buffer_index + 1 /* for NUL */) >= buffer_len)
    {
      /* Grow buffer */
      char *tmp_buffer;

      buffer_len += BUFFER_CHUNK_SIZE;

      tmp_buffer = realloc(buffer, buffer_len);

      if (tmp_buffer == NULL)
      {
	handle_error(errstring, "out of memory");
	goto error_return;
      }

      buffer = tmp_buffer;
    }

    buffer[buffer_index++] = rfc1779_char;
    buffer[buffer_index] = NUL;

    escaped = 0;
  }

  /* XXX What if escaped == 1 here? */

  /* Success */

  *imported_name = buffer;

  return 0;

 error_return:

  if (buffer)
    free(buffer);

  return -1;
} /* globus_ssleay_rfc1779_name_parse() */


/**********************************************************************
                            Internal Functions
**********************************************************************/

/******************************************************************************
Function:   handle_error
Description:
	Given and error message and a pointer to a pointer to be
	allocated handle the allocation and setting of the pointer.

Parameters:
	errstring, pointer to a pointer to be set to the allocated
	error message. May be NULL.

	message, the error message.

Returns:
	Nothing

******************************************************************************/

static void
handle_error(
  char **				errstring,
  const char * const			message)
{
  if (errstring)
  {
    /* If this fails we're hoses so don't bother checking */
    *errstring = strdup(message);
  }

} /* handle_error() */


/******************************************************************************
Function:   xdigit_to_value
Description:
	Convert a ascii character representing a hexadecimal digit
	into a integer.

Parameters:
	xdigit, character contain the hex digit.

Returns:
	value contained in xdigit, or -1 on error.

******************************************************************************/

static int
xdigit_to_value(
  char 					xdigit)
{
  if ((xdigit >= '0') && (xdigit <= '9'))
    return (xdigit - '0');

  if ((xdigit >= 'a') && (xdigit <= 'f'))
    return (xdigit - 'a' + 0xa);

  if ((xdigit >= 'A') && (xdigit <= 'F'))
    return (xdigit - 'A' + 0xa);

  /* Illegal digit */
  return -1;
} /* xdigit_to_value() */



