/*
 * vparse.c
 *
 * See vparse.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

/**********************************************************************
 *
 * Definitions
 *
 */

#define	NUL	'\0'

/**********************************************************************
 *
 * Internal functions
 *
 */

/*
 * free_tokens()
 *
 * Free all memory held by a list of tokens.
 */
static void
free_tokens(char **tokens)
{
    char **ptokens = tokens;
    
    if (tokens == NULL)
    {
	return;
    }
    
    while(*ptokens != NULL)
    {
	free(*ptokens);
	ptokens++;
    }
    
    free(tokens);
}

/*
 * add_token()
 *
 * Add a token to a list of tokens, re-allocating as needed.
 */
static char **
add_token(char **tokens,
	  const char *token)
{
    int current_length = 0;
    char **new_tokens;
    char *my_token;
    int new_size;

    assert(token != NULL);
    
    my_token = strdup(token);
    
    if (my_token == NULL)
    {
	return NULL;
    }
    
    if (tokens != NULL)
    {
	while (tokens[current_length] != NULL)
	{
	    current_length++;
	}
    }

    /* Add enough for new pointer and NULL */
    new_size = sizeof(char *) * (current_length + 2);
    
    new_tokens = realloc(tokens, new_size);
    
    if (new_tokens == NULL)
    {
	free_tokens(tokens);
	return NULL;
    }
    
    new_tokens[current_length] = my_token;
    new_tokens[current_length + 1] = NULL;
    
    return new_tokens;
}


/*
 * tokenize_line()
 *
 * Given a line and options return an allocated list of tokens.
 * Currently mangles line.
 */
static char **
tokenize_line(char *line,
	      const struct vparse_options *options)
{
    char **tokens = NULL;
    char *pline = line;

    assert(line != NULL);
    assert(options != NULL);

    tokens = malloc(sizeof(char *));
    if (tokens == NULL)
    {
	goto error;
    }
    tokens[0] = NULL;
    
    while (pline && (*pline != NUL))
    {
	char *token_start;
	char *token_end;
	
	/* Skip over leading whitespace */
	pline += strspn(pline, options->whitespace_chars);

	/*
	 * Are we at the end of the line or looking at the start
	 * of a comment?
	 */
	if ((*pline == NUL) ||
	    (strchr(options->comment_chars, *pline) != NULL))
	{
	    /* Yes, we're done */
	    break;
	}
	    
	/* Is this token quoted? */
	if (strchr(options->quoting_chars, *pline) != NULL)
	{
	    char closing_char = *pline;
	    
	    /* Yes, skip over opening quote and look for closing quote */
	    pline++;
	    token_start = pline;

	    /* Find unescaped closing character */
        token_end = strchr(pline, closing_char);
	    while (token_end &&
               strchr(options->escaping_chars, *(token_end - 1)) != NULL) {
            if (++token_end) {
                token_end = strchr(token_end, closing_char);
            }
        }
	}
	else
	{
	    /* No, just find next white space */
	    token_start = pline;
	    
	    token_end = token_start + strcspn(token_start,
					      options->whitespace_chars);
	}
	
	/*
	 * At this point token_start points to the start of the token,
	 * token_end points at the character one past the end of the
	 * token or NULL if the token had a unclosed quote. pline ==
	 * token_start.
	 */

	/*
	 * Set processing point to just past end of token or set to
	 * NULL if we're done.
	 */
	if ((token_end == NULL) ||
	    (*token_end == NUL))
	{
	    pline = NULL;
	}
	else
	{
	    pline = token_end + 1;
	}
	
	    
	/* Terminate token and add to line */
	if (token_end != NULL)
	{
	    *token_end = NUL;
	}
	
	tokens = add_token(tokens, token_start);
	
	if (tokens == NULL)
	{
	    goto error;
	}
    }

  error:
    return tokens;
}


/**********************************************************************
 *
 * API functions
 *
 */

int
vparse_stream(FILE *stream,
	      const struct vparse_options *user_options,
	      int (*line_parse)(void *arg,
				int line_number,
				const char **tokens),
	      void *line_parse_arg)
{
    struct vparse_options options;
    char buffer[1024];
    int line_number = 0;
    int return_code = -1;
    
    if ((stream == NULL) ||
	(line_parse == NULL))
    {
	errno = EINVAL;
	return -1;
    }
    
    /* Parse options */
    options.whitespace_chars =
	(user_options && user_options->whitespace_chars) ?
	user_options->whitespace_chars : VPARSE_DEFAULT_WHITESPACE_CHARS;
    
    options.quoting_chars =
	(user_options && user_options->quoting_chars) ?
	user_options->quoting_chars : VPARSE_DEFAULT_QUOTING_CHARS;
    
    options.escaping_chars =
	(user_options && user_options->escaping_chars) ?
	user_options->escaping_chars : VPARSE_DEFAULT_ESCAPING_CHARS;
    
    options.comment_chars =
	(user_options && user_options->comment_chars) ?
	user_options->comment_chars : VPARSE_DEFAULT_COMMENT_CHARS;
    
    while (fgets(buffer, sizeof(buffer), stream) != NULL)
    {
	char **tokens;
	int rc;
	
	line_number++;
	
	tokens = tokenize_line(buffer, &options);
	
	if (tokens == NULL)
	{
	    /* Probably a malloc() error - punt */
	    return -1;
	}

	rc = (*line_parse)(line_parse_arg, line_number,
			   /* I don't understand why this typecase is needed */
			   (const char **) tokens);
	
	if (rc == -1)
	{
	    break;
	}
	
	free_tokens(tokens);
    }
    
    if (!feof(stream))
    {
	/* Some sort of error */
	goto error;
    }

    /* Success */
    return_code = 0;
    
  error:
    return return_code;
}

	
	
	
