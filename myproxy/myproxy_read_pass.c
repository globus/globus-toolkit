/*
 * myproxy_read_pass.c
 *
 * See myproxy_read_pass.h for documentation
 */

#include "myproxy_read_pass.h"

#include <des.h>	/* From SSLeay */

#include <string.h>
#include <assert.h>
#include <stdlib.h>

/**********************************************************************
 *
 * Constants
 *
 */

#define PROMPT	"Enter MyProxy Pass Phrase:"

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
			      PROMPT,
			      verify);
    
    if (return_code == 0)
    {
	/* Success */
	return_code = strlen(buffer);
    }
    else
    {
	/* Error */
	return_code = -1;
    }

    if (verify_buffer != NULL)
    {
	free(verify_buffer);
    }
    
    return return_code;
}

/**********************************************************************
 *
 * API functions
 *
 */

int myproxy_read_passphrase(char		*buffer,
			    int			buffer_len)
{
    int return_code;
    
    assert(buffer != NULL);
    
    return_code = des_read_pw(buffer,
			      NULL /* No verify buffer */,
			      buffer_len,
			      PROMPT,
			      0 /* No verify */);
    
    if (return_code == 0)
    {
	/* Success */
	return_code = strlen(buffer);
    }
    else
    {
	/* Error */
	return_code = -1;
    }
    
    return return_code;
}


int myproxy_read_verified_passphrase(char	*buffer,
				     int	buffer_len)
{
    int return_code;
    char *verify_buffer = NULL;
    
    assert(buffer != NULL);

    /*
     * We need to give des_read_pw() a buffer to hold the verify
     * passphrase in.
     */
    verify_buffer = malloc(buffer_len);
    
    if (verify_buffer == NULL)
    {
	return -1;
    }
    
    return_code = des_read_pw(buffer,
			      verify_buffer,
			      buffer_len,
			      PROMPT,
			      1 /* Verify */);
    
    if (return_code == 0)
    {
	/* Success */
	return_code = strlen(buffer);
    }
    else
    {
	/* Error */
	return_code = -1;
    }

    free(verify_buffer);
    
    return return_code;
}


