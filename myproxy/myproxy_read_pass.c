/*
 * myproxy_read_pass.c
 *
 * See myproxy_read_pass.h for documentation
 */

#include "myproxy_common.h"	/* all needed headers included here */

/**********************************************************************
 *
 * Constants
 *
 */

#define PROMPT	"Enter MyProxy pass phrase:"

/**********************************************************************
 *
 * Internal functions.
 *
 */

/*
 * read_passphrase()
 *
 * Turn off echo and read a pass phrase straight from the tty into
 * buffer which has a length of buffer_len.
 *
 * Prompt with prompt, if non-null.
 *
 * If verify is non-zero, verify the pass phrase by having the user
 * enter it twice.
 *
 * Return the number of characters read or -1 on error.
 */
static int
read_passphrase(char				*buffer,
		const int			buffer_len,
		const char			*prompt,
		int				verify)
{
    int			return_code;
    char		*verify_buffer = NULL;
    
    assert(buffer != NULL);

    if (verify != 0)
    {
	/*
	 * We need to give des_read_pw() a buffer to hold the verify
	 * passphrase in.
	 */
	verify_buffer = malloc(buffer_len);
    
	if (verify_buffer == NULL)
	{
	    return -1;
	}
    }
    
    return_code = des_read_pw(buffer,
			      verify_buffer,
			      buffer_len,
			      prompt,
			      verify);

    switch(return_code)
    {
      case 0:
	/* Success */
	return_code = strlen(buffer);
	break;
	
      case 1:
	/* Interactive use error */
	return_code = -1;
	verror_put_string("Error entering passphrase");
	break;
	
      case -1:
	/* System error */
	return_code = -1;
	verror_put_string("System error reading password");
	break;
	
      default:
	/* Unknown value */
	verror_put_string("Unrecognized return value(%d) from des_read_pw()",
			 return_code);
	return_code = -1;
	break;
    }

    if (verify_buffer != NULL)
    {
	free(verify_buffer);
    }
    
    return return_code;
}

static int
read_passphrase_stdin(char			*buffer,
		      const int			buffer_len,
		      const char		*prompt,
		      int			verify)
{
    int		i;

    if (!(fgets(buffer, buffer_len, stdin))) {
	verror_put_string("Error reading passphrase");
	return -1;
    }
    i = strlen(buffer)-1;
    if (buffer[i] == '\n') {
        buffer[i] = '\0';
    }
    return i;
}

/**********************************************************************
 *
 * API functions
 *
 */

int myproxy_read_passphrase(char		*buffer,
			    int			buffer_len,
			    const char		*prompt)
{
    return read_passphrase(buffer, buffer_len, prompt ? prompt : PROMPT,
			   0 /* No verify */);
}


int myproxy_read_verified_passphrase(char	*buffer,
				     int	buffer_len,
				     const char *prompt)
{
    return read_passphrase(buffer, buffer_len, prompt ? prompt : PROMPT,
			   1 /* Verify */);
}

int myproxy_read_passphrase_stdin(char		*buffer,
				  int		buffer_len,
				  const char	*prompt)
{
    return read_passphrase_stdin(buffer, buffer_len, prompt ? prompt : PROMPT,
				 0 /* No verify */);
}
