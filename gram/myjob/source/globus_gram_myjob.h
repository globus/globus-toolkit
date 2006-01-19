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

#ifndef GLOBUS_I_GRAM_MYJOB_INCLUDE
#define GLOBUS_I_GRAM_MYJOB_INCLUDE

/******************************************************************************
			     Include header files
******************************************************************************/

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/******************************************************************************
			       Define constants
******************************************************************************/
#define GLOBUS_GRAM_MYJOB_MAX_BUFFER_LENGTH	4096

/*
 * gram_myjob_*() error codes
 */
#define GLOBUS_GRAM_MYJOB_ERROR_BASE		(0x000f0000)
#define GLOBUS_GRAM_MYJOB_SUCCESS		0
#define GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED	\
    (GLOBUS_GRAM_MYJOB_ERROR_BASE + 0)
#define GLOBUS_GRAM_MYJOB_ERROR_BAD_PARAM	\
    (GLOBUS_GRAM_MYJOB_ERROR_BASE + 1)
#define GLOBUS_GRAM_MYJOB_ERROR_COMM_FAILURE	\
    (GLOBUS_GRAM_MYJOB_ERROR_BASE + 2)
#define GLOBUS_GRAM_MYJOB_ERROR_BAD_RANK	\
    (GLOBUS_GRAM_MYJOB_ERROR_BASE + 3)
#define GLOBUS_GRAM_MYJOB_ERROR_BAD_SIZE	\
    (GLOBUS_GRAM_MYJOB_ERROR_BASE + 4)


/******************************************************************************
			Module activation declarations
******************************************************************************/

#define GLOBUS_GRAM_MYJOB_MODULE (&globus_i_gram_myjob_module)

extern globus_module_descriptor_t globus_i_gram_myjob_module;


/******************************************************************************
Function:	globus_gram_myjob_size()

Description:	obtains the number processes participating in the current job

Parameters:	size
			pointer to storage; will be set to the number of
			processes participating in the job; pointer may be NULL

Returns:	TODO: define all possible values

		GLOBUS_GRAM_MYJOB_SUCCESS
			size successfully obtained

		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
			globus_gram_myjob_init() has not been called

		GLOBUS_GRAM_MYJOB_BAD_PARAM
			size does not point to valid storage
******************************************************************************/
int
globus_gram_myjob_size(
    int *				size);


/******************************************************************************
Function:	globus_gram_myjob_rank()

Description:	obtains the ordinal of the current process with respect to
		all of the processes participating in the current job

Parameters:	rank
			pointer to storage; will be set to the rank of the
			current process; pointer may be NULL

Returns:	TODO: define all possible values

		GLOBUS_GRAM_MYJOB_SUCCESS
			rank successfully obtained

		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
			globus_gram_myjob_init() has not been called

		GLOBUS_GRAM_MYJOB_BAD_PARAM
			rank does not point to valid storage
******************************************************************************/
int
globus_gram_myjob_rank(
    int *				rank);


/******************************************************************************
Function:	globus_gram_myjob_send()

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
			GLOBUS_GRAM_MYJOB_MAX_BUFFER_LENGTH bytes in length

Returns:	TODO: define all possible values

		GLOBUS_GRAM_MYJOB_SUCCESS
			send completed successfully

		GLOBUS_GRAM_MYJOB_ERROR_BAD_RANK
			the specified destination rank is outside of the
			valid range

		GLOBUS_GRAM_MYJOB_BAD_SIZE
			the job must contain two or more processes before the
			communication routines may be used

		GLOBUS_GRAM_MYJOB_COMM_FAILURE
			message was not properly sent; this is likely the
			result of a broken connection, possibly because the
			remote process died

		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
			globus_gram_myjob_init() has not been called
******************************************************************************/
int
globus_gram_myjob_send(
    int					dest_rank,
    globus_byte_t *			msg_buf,
    int					msg_len);


/******************************************************************************
Function:	globus_gram_myjob_receive()

Description:	receive a message from another process in this job


Parameters:	msg_buf
			pointer to a message buffer; this buffer must be at
			least GLOBUS_GRAM_MYJOB_MAX_BUFFER_LENGTH bytes in length

		msg_len
			pointer to storage; will be set to the actual lentgh
			of the received message

Returns:	TODO: define all possible values

		GLOBUS_GRAM_MYJOB_SUCCESS
			receive completed successfully

		GLOBUS_GRAM_MYJOB_BAD_SIZE
			the job must contain two or more processes before the
			communication routines may be used

		GLOBUS_GRAM_MYJOB_COMM_FAILURE
			message was not properly received; this is likely the
			result of a broken connection, possibly because the
			remote process died

		GLOBUS_GRAM_MYJOB_ERROR_NOT_INITIALIZED
			globus_gram_myjob_init() has not been called
******************************************************************************/
int
globus_gram_myjob_receive(
    globus_byte_t *			msg_buf,
    int *				msg_len);


/******************************************************************************
Function:	globus_gram_myjob_kill()

Description:	terminate all processes in the job

Parameters:	none

Returns:	TODO: define all possible values

		(if it returns, something is wrong...)
******************************************************************************/
int
globus_gram_myjob_kill(void);


/******************************************************************************
 * Backward compatibility
 *****************************************************************************/

#define GRAM_MYJOB_MAX_BUFFER_LENGTH GLOBUS_GRAM_MYJOB_MAX_BUFFER_LENGTH

#define gram_myjob_size(S) \
    globus_gram_myjob_size(S)
#define gram_myjob_rank(S) \
    globus_gram_myjob_rank(S)
#define gram_myjob_send(D,B,L) \
    globus_gram_myjob_send(D,B,L)
#define gram_myjob_receive(B,L) \
    globus_gram_myjob_receive(B,L)
#define gram_myjob_kill() \
    globus_gram_myjob_Kill()

EXTERN_C_END

#endif /* GLOBUS_I_GRAM_MYJOB_INCLUDE */
