/*
 * verror.h
 *
 * Simple error-handling interface for MyProxy API.
 * Won't work with multi-threaded.
 */
#ifndef __VERROR_H
#define __VERROR_H

/*
 * verror_prepend_string()
 *
 * Prepend a string to the current error string. Accepts the
 * same arguments as sprintf().
 */
void verror_prepend_string(const char *format, ...);

/*
 * verror_put_string()
 *
 * Add a string to the current error. Accepts the same argumnets
 * as sprintf().
 */
void verror_put_string(const char *format, ...);

/*
 * verror_put_errno()
 *
 * Associate an error number with the current error.
 */
void verror_put_errno(int error_number);

/*
 * verror_put_value()
 *
 * Associate an arbitrary numeric value with the current error.
 */
void verror_put_value(int value);

/*
 * verror_is_error()
 *
 * Is there an error currently set? Returns 1 if set, 0 otherwise.
 */
int verror_is_error();

/*
 * verror_get_string()
 *
 * Return the string associated with the current error context.
 */
char *verror_get_string();

/*
 * verror_get_errno()
 *
 * Return the error number associated with the current error.
 */
int verror_get_errno();

/*
 * verror_strerror()
 *
 * Return a pointer to the error string associated with the current
 * error number or a empty string if no error number is currently
 * set. The string is statically allocated and should not be modified.
 */
char *verror_strerror();

/*
 * verror_get_value()
 *
 * Return the numeric value associated with the current error.
 */
int verror_get_value();

/*
 * verror_clear()
 *
 * Clear the current error state.
 */
void verror_clear();

/*
 * verror_print_error()
 *
 * A helper function to print both the error string and the error
 * number string.
 */
void verror_print_error(FILE *stream);

#endif /* __VERROR_H */
