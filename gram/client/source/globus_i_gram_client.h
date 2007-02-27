/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    gss_cred_id_t                       credential;
    globus_io_secure_delegation_mode_t  delegation_mode;
}
globus_i_gram_client_attr_t;

EXTERN_C_END
#endif /* GLOBUS_I_I_GRAM_CLIENT_INCLUDE */

