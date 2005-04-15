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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_authz_error.c
 * Globus GSI Authz Library
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_gsi_authz_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char * 
globus_l_gsi_authz_error_strings[GLOBUS_GSI_AUTHZ_ERROR_LAST] =
{
/* 0 */   "Success",
/* 1 */   "Error with system call",
/* 2 */   "Invalid parameter",
/* 3 */   "Callout returned an error"
};

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
















