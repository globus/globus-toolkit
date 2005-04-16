/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "gaa.h"
#include "gaa_private.h"
#include <string.h>

/** gaa_i_new_string()
 *
 *  @ingroup gaa_internal
 *
 *  Create a new string and copy and old string into it.
 *
 *  @param dest
 *         output string to create
 *  @param src
 *         input string to copy
 */
gaa_status
gaa_i_new_string(char **dest, char *src)
{
    if (dest == 0 || src == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*dest) = strdup(src)) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(GAA_S_SUCCESS);
}

/** gaa_i_free_simple()
 *
 *  @ingroup gaa_internal
 *
 *  Free a pointer, if it's nonzero.
 *
 *  @param val
 *         value to free
 */
void
gaa_i_free_simple(void *val)
{
    if (val)
	free(val);
}
