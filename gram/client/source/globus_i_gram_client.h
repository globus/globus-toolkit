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

/*
globus_i_gram_client.h

CVS Information:
    $Source$
    $Date$
    $Revision$
    $Author$
*/

#ifndef GLOBUS_I_I_GRAM_CLIENT_INCLUDE
#define GLOBUS_I_I_GRAM_CLIENT_INCLUDE

#include "globus_gram_client.h"

EXTERN_C_BEGIN

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct
{
    gss_cred_id_t                   credential;
}
globus_i_gram_client_attr_t;

EXTERN_C_END
#endif /* GLOBUS_I_I_GRAM_CLIENT_INCLUDE */

