/*
 * verror.h
 *
 * Simple error-handling interface. Won't work with multi-threaded.
 */
#ifndef __VERROR_H
#define __VERROR_H

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

#endif /* __VERROR_H */
