/******************************************************************************
gram_myjob_mp.c

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
#include "gram_myjob.h"
#include "nexus.h"
#include GRAM_MYJOB_MP_HEADER


/******************************************************************************
		       Define module specific constants
******************************************************************************/


/******************************************************************************
			       Type definitions
******************************************************************************/


/******************************************************************************
		       Define module specific variables
******************************************************************************/
static gram_bool_t			graml_myjob_initialized = GRAM_FALSE;
static mp_communicator_t		graml_myjob_communicator;
static int				graml_myjob_size;
static int				graml_myjob_rank;


/******************************************************************************
			  Module specific prototypes
******************************************************************************/


/******************************************************************************
Function:	gram_myjob_init()

Description:	initializes parallel communication; allocates a new
		 communicator; gets the size and rank, caching them

Parameters:	see API

Returns:	GRAM_MYJOB_SUCCESS
******************************************************************************/
int
gram_myjob_init(
    int *				argc,
    char ***				argv)
{
    if (!graml_myjob_initialized)
    {
	MP_INITIALIZE(argc, argv);
	MP_INIT_NODE_INFO(graml_myjob_rank, graml_myjob_size);
	MP_COMMUNICATOR_ALLOC(graml_myjob_communicator);

	graml_myjob_initialized = GRAM_TRUE;
    }

    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_done()

Description:	frees resources used by the communicator; shut's down
		parallel communication

Parameters:	see API

Returns:	GRAM_MYJOB_SUCCESS
		GRAM_MYJOB_ERROR_NOT_INITIALIZED
******************************************************************************/
int
gram_myjob_done()
{
    if (!graml_myjob_initialized)
    {
	return(GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    MP_COMMUNICATOR_FREE(graml_myjob_communicator);
    MP_NODE_EXIT();

    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_size()

Description:	sets size to one (1)

Parameters:	see API

Returns:	GRAM_MYJOB_SUCCESS
		GRAM_MYJOB_ERROR_NOT_INITIALIZED
		GRAM_MYJOB_BAD_PARAM
******************************************************************************/
int
gram_myjob_size(
    int *				size)
{
    if (!graml_myjob_initialized)
    {
	return(GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (size == NULL)
    {
	return(GRAM_MYJOB_ERROR_BAD_PARAM);
    }

    *size = graml_myjob_size;
    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_rank()

Description:	sets rank to zero (0)

Parameters:	see API

Returns:	GRAM_MYJOB_SUCCESS
		GRAM_MYJOB_ERROR_NOT_INITIALIZED
		GRAM_MYJOB_BAD_PARAM
******************************************************************************/
int
gram_myjob_rank(
    int *				rank)
{
    if (!graml_myjob_initialized)
    {
	return(GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (rank == NULL)
    {
	return(GRAM_MYJOB_ERROR_BAD_PARAM);
    }

    *rank = graml_myjob_rank;
    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_send()

Description:	Send a message to another process in this job

Parameters:	see API

Returns:	
******************************************************************************/
int
gram_myjob_send(
    int					dest_rank,
    gram_byte_t *			msg_buf,
    int					msg_len)
{
    mp_send_status_t			send_status;
    nexus_bool_t			send_done;

    if (!graml_myjob_initialized)
    {
	return(GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (graml_myjob_size < 2)
    {
	return(GRAM_MYJOB_ERROR_BAD_SIZE);
    }

    if (dest_rank < 0
	|| dest_rank >= graml_myjob_size
	|| dest_rank == graml_myjob_rank)
    {
	return(GRAM_MYJOB_ERROR_BAD_RANK);
    }


    MP_SEND(graml_myjob_communicator,
	    dest_rank,
	    msg_buf,
	    msg_len,
	    send_status);

    send_done = NEXUS_FALSE;
    do
    {
	MP_SEND_STATUS(send_status, send_done);
    } while(!send_done);

    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_receive()

Description:	Wait for a new message to arrive

Parameters:	see API

Returns:	
******************************************************************************/
int
gram_myjob_receive(
    gram_byte_t *			msg_buf,
    int *				msg_len)
{
    mp_receive_status_t			recv_status;
    nexus_bool_t			recv_done;

    if (!graml_myjob_initialized)
    {
	return(GRAM_MYJOB_ERROR_NOT_INITIALIZED);
    }

    if (graml_myjob_size < 2)
    {
	return(GRAM_MYJOB_ERROR_BAD_SIZE);
    }

    MP_POST_RECEIVE(graml_myjob_communicator,
		    gram_myjob_receive,
		    msg_buf,
		    GRAM_MYJOB_MAX_BUFFER_LENGTH,
		    recv_status);

    MP_RECEIVE_WAIT(gram_myjob_receive(),
		    recv_status,
		    msg_len,
		    recv_done);

    return(GRAM_MYJOB_SUCCESS);
}


/******************************************************************************
Function:	gram_myjob_kill()

Description:	there are two options possibilities here: (a) the process was
		started by gram, so we must have gram cancel it, or (b) the
		process is on it's own and therefore can simply be aborted.

		TODO: implement (a)

Parameters:     see API

Returns:	this will never return
******************************************************************************/
int
gram_myjob_kill()
{
    MP_NODE_ABORT();
    abort();
}
