/*
 * vparse.h
 *
 * Routines for parsing a configuration file. A beefed up strtok().
 */

#ifndef __VPARSE_H
#define __VPARSE_H

#include <stdio.h>

struct vparse_options {
    char *whitespace_chars;
    char *quoting_chars;
    char *escaping_chars;
    char *comment_chars;
};

/*
 * Defaults for above
 */
#define VPARSE_DEFAULT_WHITESPACE_CHARS		" \t\n"
#define VPARSE_DEFAULT_QUOTING_CHARS		"\""
#define VPARSE_DEFAULT_ESCAPING_CHARS		"\\"
#define VPARSE_DEFAULT_COMMENT_CHARS		"#"

/*
 * vparse_stream()
 *
 * Parse the given stream using the given options and line parsing function.
 * options may be NULL indicating that defaults should be used.
 * The line parsing function will be called with the given argument
 * (line_parse_arg), the current line number, and a array of strings
 * holding all the tokens on the line. The function should return -1
 * if it wishes parsing to discontinue, 0 otherwise.
 *
 * Return -1 on a read error, 0 otherwise.
 */
int
vparse_stream(FILE *stream,
	      const struct vparse_options *options,
	      int (*line_parse)(void *arg,
				int line_number,
				const char **tokens),
	      void *line_parse_arg);

#endif /* !__VPARSE_H */
