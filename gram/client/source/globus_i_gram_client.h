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

