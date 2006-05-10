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

/******************************************************************************
globus_gram_myjob_mp.c

Description:

  Implementation of GRAM_MyJob API for message passing based systems.  See
  gram_myjob.h for generic descriptions of the routines.

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/

#include "globus_gram_myjob.h"

/* determine whether to use MP or DUCT */
#include "globus_mp_mpi.h"

#ifdef GLOBUS_MP_HAS_MPI_PROTO

#include "globus_common.h"
#include "version.h"


/******************************************************************************
		       Define module specific variables
******************************************************************************/
static globus_bool_t			graml_myjob_initialized = GLOBUS_FALSE;
static globus_mp_communicator_t		graml_myjob_communicator;
static int				graml_myjob_size;
static int				graml_myjob_rank;


/******************************************************************************
			 Module activation definitions
******************************************************************************/
static int
globus_l_gram_myjob_activate();

static int
globus_l_gram_myjob_deactivate();


globus_module_descriptor_t		globus_i_gram_myjob_module =
{
    "globus_gram_myjob_mp",
    globus_l_gram_myjob_activate,
    globus_l_gram_myjob_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


/*
 * globus_l_gram_myjob_activate()
 */
static int
globus_l_gram_myjob_activate()
{
    GLOBUS_MP_INITIALIZE();
    GLOBUS_MP_INIT_NODE_INFO(graml_myjob_rank, graml_myjob_size);
    GLOBUS_MP_COMMUNICATOR_ALLOC(graml_myjob_communicator);

    graml_myjob_initialized = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}


/*
 * globus_l_gram_myjob_deactivate()
 */
static int
globus_l_gram_myjob_deactivate()
{
    GLOBUS_MP_COMMUNICATOR_FREE(graml_myjob_communicator);
    GLOBUS_MP_NODE_SHUTDOWN();

    graml_myjob_initialized = GLOBUS_FALSE;

    return GLOBUS_SUCCESS;
}


/******************************************************************************
Function:	globus_gram_myjob_size()

Description:	sets size to number of nodes

Parameters:	see API

Returns:	GLOBUS_SUCCESS
		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
		GLOBUS_GRAM_MYJOB_BAD_PARAM
******************************************************************************/
int
globus_gram_myjob_size(
    int *				size)
{
    if (!graml_myjob_initialized)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (size == NULL)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_BAD_PARAM);
    }

    *size = graml_myjob_size;
    return(GLOBUS_SUCCESS);
}


/******************************************************************************
Function:	globus_gram_myjob_rank()

Description:	sets rank to node's ordinal

Parameters:	see API

Returns:	GLOBUS_SUCCESS
		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
		GLOBUS_GRAM_MYJOB_BAD_PARAM
******************************************************************************/
int
globus_gram_myjob_rank(
    int *				rank)
{
    if (!graml_myjob_initialized)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (rank == NULL)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_BAD_PARAM);
    }

    *rank = graml_myjob_rank;
    return(GLOBUS_SUCCESS);
}


/******************************************************************************
Function:	globus_gram_myjob_send()

Description:	Send a message to another process in this job

Parameters:	see API

Returns:
******************************************************************************/
int
globus_gram_myjob_send(
    int					dest_rank,
    globus_byte_t *			msg_buf,
    int					msg_len)
{
    globus_mp_send_status_t		send_status;
    globus_bool_t			send_done;
    int					error;

    if (!graml_myjob_initialized)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (graml_myjob_size < 2)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_BAD_SIZE);
    }

    if (dest_rank < 0
	|| dest_rank >= graml_myjob_size
	|| dest_rank == graml_myjob_rank)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_BAD_RANK);
    }


    GLOBUS_MP_SEND(graml_myjob_communicator,
		   dest_rank,
		   msg_buf,
		   msg_len,
		   send_status,
		   error);

    send_done = GLOBUS_FALSE;
    do
    {
	GLOBUS_MP_SEND_STATUS(send_status, send_done, error);
    }
    while(!send_done);

    return(GLOBUS_SUCCESS);
}


/******************************************************************************
Function:	globus_gram_myjob_receive()

Description:	Wait for a new message to arrive

Parameters:	see API

Returns:
******************************************************************************/
int
globus_gram_myjob_receive(
    globus_byte_t *			msg_buf,
    int *				msg_len)
{
    globus_mp_receive_status_t		recv_status;
    globus_bool_t			recv_done;
    int					error;

    if (!graml_myjob_initialized)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (graml_myjob_size < 2)
    {
	return(GLOBUS_GRAM_MYJOB_ERROR_BAD_SIZE);
    }

    GLOBUS_MP_POST_RECEIVE(graml_myjob_communicator,
			   globus_gram_myjob_receive,
			   msg_buf,
			   GLOBUS_GRAM_MYJOB_MAX_BUFFER_LENGTH,
			   recv_status,
			   error);

    GLOBUS_MP_RECEIVE_WAIT(globus_gram_myjob_receive(),
			   recv_status,
			   msg_len,
			   recv_done,
			   error);

    return(GLOBUS_SUCCESS);
}


/******************************************************************************
Function:	globus_gram_myjob_kill()

Description:	there are two options possibilities here: (a) the process was
		started by gram, so we must have gram cancel it, or (b) the
		process is on it's own and therefore can simply be aborted.

		TODO: implement (a)

Parameters:     see API

Returns:	this will never return
******************************************************************************/
int
globus_gram_myjob_kill()
{
    GLOBUS_MP_ABORT();
    abort();

    return GLOBUS_GRAM_MYJOB_ERROR_COMM_FAILURE;
}

#endif /* GLOBUS_MP_HAS_MPI_PROTO */
