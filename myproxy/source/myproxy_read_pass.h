/*
 * my_proxy_read_pass.h
 *
 * Common client side routines.
 */
#ifndef _MYPROXY_READ_PASS_H
#define _MYPROXY_READ_PASS_H

/* Minimum pass phrase length */
#define MIN_PASS_PHRASE_LEN		6

/*
 * myproxy_read_passphrase()
 *
 * Issue the specified prompt (or a standard prompt if prompt is NULL)
 * and read the pass phrase from the tty
 * and place it into the given buffer with length given by buffer_len.
 * If pass phrase is greater than buffer_len bytes, it is silently
 * truncated.
 * 
 * Returns number of characters read, -1 on error.
 */
int myproxy_read_passphrase(char		*buffer,
			    int			buffer_len,
			    const char		*prompt);

/*
 * myproxy_read_passphrase_stdin()
 *
 * Same as myproxy_read_passphrase() except reads pass phrase from stdin.
 */
int myproxy_read_passphrase_stdin(char		*buffer,
				  int		buffer_len,
				  const char	*prompt);

/*
 * myproxy_read_verified_passphrase()
 *
 * Same as myproxy_read_passphrase except the user is prompted
 * twice for the passphrase and both must match.
 */
int myproxy_read_verified_passphrase(char	*buffer,
				     int	buffer_len,
				     const char *prompt);

/*
 * Check for good passphrases:
 * 1. Make sure the passphrase is at least MIN_PASS_PHRASE_LEN long.
 * 2. Optionally run an external passphrase policy program.
 *
 * Returns 0 if passphrase is accepted and -1 otherwise.
 */
int myproxy_check_passphrase_policy(const char *passphrase,
				    const char *passphrase_policy_pgm,
				    const char *username,
				    const char *credname,
				    const char *retrievers,
				    const char *renewers,
				    const char *client_name);

#endif /* _MYPROXY_READ_PASS_H */
