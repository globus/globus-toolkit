/******************************************************************************
gram_myjob.h

Description:

  GRAM_MyJob API defintions.  This API defines a simple set of communication
  abstractions along with some other useful routines to facilitate startup and
  shutdown of a job.

  NOTE: this interface is not guaranteed to be thread-safe

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

#ifndef _GRAM_INCLUDE_GRAM_MYJOB_H
#define _GRAM_INCLUDE_GRAM_MYJOB_H

/******************************************************************************
			     Include header files
******************************************************************************/
#include "gram_client.h"


/******************************************************************************
			       Define constants
******************************************************************************/
#define GRAM_MYJOB_MAX_BUFFER_LENGTH	4096


/******************************************************************************
				Type definition
******************************************************************************/


/******************************************************************************
			      Function prototypes
******************************************************************************/

/******************************************************************************
Function:	gram_myjob_init()

Description:	initialize GRAM's communication subsystem

		This routine must be called before any of the other
		communication routines.

		If any node in the job calls gram_myjob_init(), all nodes must
		make the call; failure to do so may result in the job hanging.

Parameters:	argc
			pointer to number of command line arguments

		argv
			pointer to array of command line arguments

		size
			pointer to storage; will be set to the number of
			processes participating in the job; pointer may be NULL

		rank
			pointer to storage; will be set to the rank of the
			current process; pointer may be NULL

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			initialization completed successfully

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			the underlying communication system was not initialized
			prior to calling gram_myjob_init()
******************************************************************************/
int
gram_myjob_init(
    int *				argc,
    char ***				argv);


/******************************************************************************
Function:	gram_myjob_done()

Description:	terminate GRAM's communication subsystem, releasing any
		resource which might have been allocated.  This routine should
		be called anytime a major communcation phase ends to prevent
		resources from being held unnecessarily for the entire duration
		of the job.  Should further communication be required at a
		later time, gram_myjob_init() may be called again.

		the other communication routines may not be used once this
		routine is called, unless gram_myjob_init() is called again

Parameters:	none

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			initialization completed successfully

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			gram_myjob_init() has not been called
******************************************************************************/
int
gram_myjob_done();


/******************************************************************************
Function:	gram_myjob_size()

Description:	obtains the number processes participating in the current job

Parameters:	size
			pointer to storage; will be set to the number of
			processes participating in the job; pointer may be NULL

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			size successfully obtained

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			gram_myjob_init() has not been called

		GRAM_MYJOB_BAD_PARAM
			size does not point to valid storage
******************************************************************************/
int
gram_myjob_size(
    int *				size);


/******************************************************************************
Function:	gram_myjob_rank()

Description:	obtains the ordinal of the current process with respect to
		all of the processes participating in the current job

Parameters:	rank
			pointer to storage; will be set to the rank of the
			current process; pointer may be NULL

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			rank successfully obtained

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			gram_myjob_init() has not been called

		GRAM_MYJOB_BAD_PARAM
			rank does not point to valid storage
******************************************************************************/
int
gram_myjob_rank(
    int *				rank);


/******************************************************************************
Function:	gram_myjob_send()

Description:	send a message to another process in this job

		NOTE: this routine may block until the corresponding receive is
		called on the destination node

Parameters:	dest_rank
			rank of the destination process; the destination
			process may not be the same as the sending process

		msg_buf
			mesage buffer

		msg_len
			message length; the message may not exceed
			GRAM_MYJOB_MAX_BUFFER_LENGTH bytes in length

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			send completed successfully

		GRAM_MYJOB_ERROR_BAD_RANK
			the specified destination rank is outside of the
			valid range

		GRAM_MYJOB_BAD_SIZE
			the job must contain two or more processes before the
			communication routines may be used

		GRAM_MYJOB_COMM_FAILURE
			message was not properly sent; this is likely the
			result of a broken connection, possibly because the
			remote process died

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			gram_myjob_init() has not been called
******************************************************************************/
int
gram_myjob_send(
    int					dest_rank,
    gram_byte_t *			msg_buf,
    int					msg_len);


/******************************************************************************
Function:	gram_myjob_receive()

Description:	receive a message from another process in this job


Parameters:	msg_buf
			pointer to a message buffer; this buffer must be at
			least GRAM_MYJOB_MAX_BUFFER_LENGTH bytes in length

		msg_len
			pointer to storage; will be set to the actual lentgh
			of the received message

Returns:	TODO: define all possible values

		GRAM_MYJOB_SUCCESS
			receive completed successfully

		GRAM_MYJOB_BAD_SIZE
			the job must contain two or more processes before the
			communication routines may be used

		GRAM_MYJOB_COMM_FAILURE
			message was not properly received; this is likely the
			result of a broken connection, possibly because the
			remote process died

		GRAM_MYJOB_ERROR_NOT_INITIALIZED
			gram_myjob_init() has not been called
******************************************************************************/
int
gram_myjob_receive(
    gram_byte_t *			msg_buf,
    int *				msg_len);


/******************************************************************************
Function:	gram_myjob_kill()

Description:	terminate all processes in the job

Parameters:	none

Returns:	TODO: define all possible values

		(if it returns, something is wrong...)
******************************************************************************/
int
gram_myjob_kill();


#endif
