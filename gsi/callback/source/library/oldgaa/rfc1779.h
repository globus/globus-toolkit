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


#ifndef _RFC1779_H_
#define _RFC1779_H_

int
oldgaa_rfc1779_name_parse(
  char *				rfc1779_string,
  char **				imported_name,
  char **				errstring);

#endif
