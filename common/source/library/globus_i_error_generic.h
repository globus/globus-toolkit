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
 * @file globus_i_error_generic.h
 * Globus Generic Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */

#include "globus_common_include.h"

#ifndef GLOBUS_I_INCLUDE_GENERIC_ERROR_H
#define GLOBUS_I_INCLUDE_GENERIC_ERROR_H


EXTERN_C_BEGIN

/**
 * Generic Error object instance data definition
 * @ingroup globus_generic_error_object
 * @internal
 *
 * This structure contains all of the data associated with a Globus
 * Generic Error.
 *
 * @see globus_error_construct_error(),
 *      globus_error_initialize_error(),
 *      globus_l_error_free_globus()
 */

typedef struct globus_l_error_data_s
{
    /** the error type */
    int                                 type;
    /** the short error description */
    char *                              short_desc;
    /** the long error description */
    char *                              long_desc;
    
    /* these are static strings, do NOT free them */
    const char *                        file;
    const char *                        func;
    int                                 line;
}
globus_l_error_data_t;

EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GENERIC_ERROR_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
