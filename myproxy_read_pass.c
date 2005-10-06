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
        if (return_code < MIN_PASS_PHRASE_LEN && return_code != 0) {
            verror_put_string("Passphrase must be at least %d characters long.",
                              MIN_PASS_PHRASE_LEN);
            return_code = -1;
        }
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
    if (i < MIN_PASS_PHRASE_LEN && i != 0) {
	verror_put_string("Passphrase must be at least %d characters long.",
			  MIN_PASS_PHRASE_LEN);
	return -1;
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

/*
 * Check for good passphrases:
 * 1. Make sure the passphrase is at least MIN_PASS_PHRASE_LEN long.
 * 2. Optionally run an external passphrase policy program.
 *
 * Returns 0 if passphrase is accepted and -1 otherwise.
 */
int
myproxy_check_passphrase_policy(const char *passphrase,
				const char *passphrase_policy_pgm,
				const char *username,
				const char *credname,
				const char *retrievers,
				const char *renewers,
				const char *client_name)
{
    pid_t childpid;
    int p0[2], p1[2], p2[2];
    size_t passphrase_len = 0;
    int exit_status;

    if (passphrase) {
	passphrase_len = strlen(passphrase);
    }

    /* Zero length passphrase is allowed, for authentication methods
       that don't use a passphrase, like credential renewal
       or Kerberos. */
    if (passphrase_len != 0 && passphrase_len < MIN_PASS_PHRASE_LEN) {
	verror_put_string("Pass phrase too short.  "
			  "Must be at least %d characters long.",
			  MIN_PASS_PHRASE_LEN);
	return -1;
    }

    if (!passphrase_policy_pgm) return 0;

    myproxy_debug("Running passphrase policy program: %s",
		  passphrase_policy_pgm);

    if (pipe(p0) < 0 || pipe(p1) < 0 || pipe(p2) < 0) {
	verror_put_string("pipe() failed");
	verror_put_errno(errno);
	return -1;
    }

    /* fork/exec passphrase policy program */
    if ((childpid = fork()) < 0) {
	verror_put_string("fork() failed");
	verror_put_errno(errno);
	return -1;
    }
    
    if (childpid == 0) {	/* child */
	close(p0[1]); close(p1[0]); close(p2[0]);
	if (dup2(p0[0], 0) < 0 ||
	    dup2(p1[1], 1) < 0 ||
	    dup2(p2[1], 2) < 0)	{
	    perror("dup2");
	    exit(1);
	}
	execl(passphrase_policy_pgm,
	      passphrase_policy_pgm,
	      username,
	      client_name,
	      (credname) ? credname : "",
	      (retrievers) ? retrievers : "",
	      (renewers) ? renewers : "",
	      NULL);
	fprintf(stderr, "failed to run %s: %s\n",
		passphrase_policy_pgm, strerror(errno));
	exit(1);
    }

    close(p0[0]); close(p1[1]); close(p2[1]);

    /* send passphrase to child's stdin */
    if (passphrase_len) {
	write(p0[1], passphrase, passphrase_len);
    }
    write(p0[1], "\n", 1);
    close(p0[1]); 

    /* wait for child */
    if (wait4(childpid, &exit_status, 0, NULL) < 0) {
	verror_put_string("wait() failed for passphrase policy child");
	verror_put_errno(errno);
	return -1;
    }

    if (exit_status != 0) { /* passphrase not allowed */
	FILE *fp = NULL;
	char buf[100];
	verror_put_string("Pass phrase violates local policy.");
	fp = fdopen(p1[0], "r");
	if (fp) {
	    while (fgets(buf, 100, fp) != NULL) {
		verror_put_string(buf);
	    }
	}
	fclose(fp);
	fp = fdopen(p2[0], "r");
	if (fp) {
	    while (fgets(buf, 100, fp) != NULL) {
		verror_put_string(buf);
	    }
	}
	fclose(fp);
	return -1;
    }

    close(p1[0]); close(p2[0]);
    return 0;
}
