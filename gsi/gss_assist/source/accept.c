/******************************************************************************
accept.c
 
Description:
Globus GSSAPI Assist routine for the gss_accept_sec_context

	This routine accepts a GSSAPI security context and 
	is called by the gram_gatekeeper. It isolates 
	the GSSAPI from the rest of the gram code. 

CVS Information:
 
	$Source$
	$Date$
	$Revision$
	$Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "assist_config.h"
#include "globus_gss_assist.h"
#include <gssapi.h>
#include <malloc.h>

/******************************************************************************
                               Type definitions
******************************************************************************/
/******************************************************************************
                          Module specific prototypes
******************************************************************************/
/******************************************************************************
                       Define module specific variables
******************************************************************************/

/******************************************************************************
Function:   globus_gss_assist_init_sec_context()
Description:
    Initialize a gssapi security connection. Used by the server.  
    The context_handle is returned, and there is one for each
    connection.  This routine will take cake of the looping
    and token processing, using the supplied get_token and
    send_token routines. 


Parameters:
	token_status - assist routine get/send token status
    minor_status - gssapi return code
    context_handle - pointer to returned context. 
    initiator_cred_handle - the cred handle obtained by acquire_cred.
    src_name_char - Pointer to char string repersentation of the
       	client which contacted the server. Maybe NULL if not wanted.  
		Should be freed when done. 
    ret_flags - Pointer to which services are available after
        the connection is established. Maybe NULL if not wanted. 
		We will also use this to pass in flags to the globus
		version of gssapi_ssleay

	user_to_user_flag - Pointer to flag to be set if
		the src_name is the same as our name. 
	(Follwing are particular to this assist routine)
	token_status - assist routine get/send token status
	a get token routine 
	first arg for the get token routine 
	a send token routine 
	first arg for the send token routine

Returns:
    GSS_S_COMPLETE on sucess
    Other gss errors on failure.

******************************************************************************/
OM_uint32
globus_gss_assist_accept_sec_context
(OM_uint32 *		minor_status,
 gss_ctx_id_t *		context_handle,
 const gss_cred_id_t	cred_handle,
 char **			src_name_char,
 OM_uint32 *		ret_flags,
 int *				user_to_user_flag,
 int *				token_status,
 gss_cred_id_t		* delegated_cred_handle,
 int (*gss_assist_get_token)(void *, void **, size_t *), 
 void *gss_assist_get_context,
 int (*gss_assist_send_token)(void *, void *, size_t),
 void *gss_assist_send_context)
{

  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;
  OM_uint32 minor_status2 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;
  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

  gss_channel_bindings_t input_chan_bindings =
							 GSS_C_NO_CHANNEL_BINDINGS;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_name_t my_name = GSS_C_NO_NAME;
  gss_OID mech_type = GSS_C_NO_OID;
  OM_uint32  time_req;

  char * cp;
  gss_buffer_desc tmp_buffer_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    tmp_buffer      = &tmp_buffer_desc;

  *context_handle = GSS_C_NO_CONTEXT;
  *token_status = 0;

  if (src_name_char) {
    *src_name_char = NULL;
  }
  if (user_to_user_flag) {
	*user_to_user_flag = 0;
  }

  do {
    if ((*token_status = gss_assist_get_token(
					  gss_assist_get_context,
                      &input_token->value,
                      &input_token->length)) < 0) {
       major_status = 
			GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_READ;
       break;
    }
#ifdef DEBUG
    fprintf(stderr,"gss_assist_accept_sec_context(1):inlen:%d\n",
				input_token->length);
#endif

    major_status = gss_accept_sec_context(&minor_status1,
                                        context_handle,
                                        cred_handle,
                                        input_token,
                                        input_chan_bindings,
                                        &client_name,
                                        &mech_type,
                                        output_token,
                                        ret_flags,
                                        &time_req,
                                        delegated_cred_handle);

#ifdef DEBUG
    fprintf(stderr,"gss_assist_accept_sec_context(2)maj:%8.8x:min:%8.8x:ret:%8.8x outlen:%d:context:%p\n",
                major_status, minor_status1, 
                (ret_flags)?*ret_flags:-1,
				output_token->length,*context_handle);
#endif

    if (output_token->length != 0) {
      if ((*token_status = gss_assist_send_token(
				   gss_assist_send_context, 
                   output_token->value,
                   output_token->length)) < 0) {
        major_status = 
			GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_WRITE;
      }
      gss_release_buffer(&minor_status2,
                          output_token);
    }
    if (GSS_ERROR(major_status)) {
	/* XXX I think this should be *context_handle? */
      if (context_handle != GSS_C_NO_CONTEXT)
         gss_delete_sec_context(&minor_status2,
                                context_handle,
                                GSS_C_NO_BUFFER);
        break;
    }
    if (input_token->length >0) {
      free(input_token->value); /* alloc done by g_get_token */
      input_token->length = 0;
    }
  } while (major_status & GSS_S_CONTINUE_NEEDED);

  if (input_token->length >0) {
    free(input_token->value); /* alloc done by g_get_token */
    input_token->length = 0;
  }

  if (major_status == GSS_S_COMPLETE) {

	/* caller want the name of the client */

    if (src_name_char) {
	  major_status = gss_display_name(&minor_status2,
						   client_name,
						   tmp_buffer,
						   NULL);
		if (major_status == GSS_S_COMPLETE) {
       
        cp = (char *)malloc(tmp_buffer->length+1);
        if (cp) {
          memcpy(cp, tmp_buffer->value, tmp_buffer->length);
          cp[tmp_buffer->length] = '\0';
          *src_name_char = cp;
        } else {
          major_status = GSS_S_FAILURE;
        }
      }
      gss_release_buffer(&minor_status2, tmp_buffer);
    } 
	/* caller want to know if the client and server are the same */

	if (user_to_user_flag) {
 	  if ((major_status = gss_inquire_cred(&minor_status1,
							cred_handle,
							&my_name,			
							NULL,
							NULL,
							NULL)) == GSS_S_COMPLETE) {
	 	  major_status = gss_compare_name(&minor_status1,
							client_name,
							my_name,
							user_to_user_flag);
	  }
	}
  }

  gss_release_name(&minor_status2, &client_name);
  gss_release_name(&minor_status2, &my_name);
 

  *minor_status = minor_status1;
  return major_status;
}



/******************************************************************************
Function:   globus_gss_assist_accept_sec_context_async()
Description:
	This is a asynchronous version of the
	globus_gss_assist_accept_sec_context() function. Instead of looping
	itself it passes in and out the read and written buffers and
	the calling application is responsible for doing the I/O directly.


Parameters:
	token_status - assist routine get/send token status

	minor_status - gssapi return code

	context_handle - pointer to returned context. 

	initiator_cred_handle - the cred handle obtained by acquire_cred.

	src_name_char - Pointer to char string repersentation of the

       	client which contacted the server. Maybe NULL if not wanted.  
		Should be freed when done. 

	ret_flags - Pointer to which services are available after
        	the connection is established. Maybe NULL if not wanted. 
		We will also use this to pass in flags to the globus
		version of gssapi_ssleay

	user_to_user_flag - Pointer to flag to be set if
		the src_name is the same as our name. 

	input_buffer - pointer to a buffer received from peer.

	input_buffer_len - length of the buffer input_buffer.

	output_bufferp - pointer to a pointer which will be filled in
		with a pointer to a allocated block of memory. If
		non-NULL the contents of this block should be written
		to the peer where they will be fed into the
		gss_assist_init_sec_context_async() function.

       	output_buffer_lenp - pointer to an integer which will be filled
		in with the length of the allocated output buffer
		pointed to by *output_bufferp.
	
		
Returns:
	GSS_S_COMPLETE on successful completion when this function does not
    	need to be called again.

	GSS_S_CONTINUE_NEEDED when *output_bufferp should be sent to the
	peer and a new input_buffer read and this function called again.
	
	Other gss errors on failure.

******************************************************************************/
OM_uint32
globus_gss_assist_accept_sec_context_async
(OM_uint32 *			minor_status,
 gss_ctx_id_t *			context_handle,
 const gss_cred_id_t		cred_handle,
 char **			src_name_char,
 OM_uint32 *			ret_flags,
 int *				user_to_user_flag,
 void *				input_buffer,
 size_t				input_buffer_len,
 void **			output_bufferp,
 size_t *			output_buffer_lenp,
 gss_cred_id_t *    delegated_cred_handle)
{

  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;
  OM_uint32 minor_status2 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;


  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

  gss_channel_bindings_t input_chan_bindings =
      GSS_C_NO_CHANNEL_BINDINGS;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_name_t my_name = GSS_C_NO_NAME;
  gss_OID mech_type = GSS_C_NO_OID;
  OM_uint32  time_req;

  char * cp;
  gss_buffer_desc tmp_buffer_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    tmp_buffer      = &tmp_buffer_desc;


  /* Set up our input token from passed buffer */
  if ((input_buffer != NULL) && (input_buffer_len != 0))
  {
      input_token_desc.length = input_buffer_len;
      input_token_desc.value = input_buffer;
  }

  /* Do initialization first time through the loop */
  if (*context_handle == GSS_C_NO_CONTEXT)
  {
      if (src_name_char) {
	  *src_name_char = NULL;
      }
      if (user_to_user_flag) {
	  *user_to_user_flag = -1;
      }
  }

#ifdef DEBUG
    fprintf(stderr,"gss_assist_accept_sec_context_async(1):inlen:%d\n",
				input_token->length);
#endif
  major_status = gss_accept_sec_context(&minor_status1,
                                        context_handle,
                                        cred_handle,
                                        input_token,
                                        input_chan_bindings,
                                        &client_name,
                                        &mech_type,
                                        output_token,
                                        ret_flags,
                                        &time_req,
                                        delegated_cred_handle);
#ifdef DEBUG
    fprintf(stderr,"gss_assist_accept_sec_context_async(2)maj:%8.8x:min:%8.8x:ret:%8.8x outlen:%d:context:%p\n",
                major_status, minor_status1, 
                (ret_flags)?*ret_flags:-1,
				output_token->length,*context_handle);
#endif

  if (output_token->length != 0)
  {
      *output_bufferp = output_token->value;
      *output_buffer_lenp = output_token->length;
      /* These will now be freed by the caller */
  }
  else
  {    
      *output_bufferp = NULL;
      *output_buffer_lenp = 0;
  }

  if (GSS_ERROR(major_status))
  {
      if (*context_handle != GSS_C_NO_CONTEXT)
	  gss_delete_sec_context(&minor_status2,
				 context_handle,
				 GSS_C_NO_BUFFER);
  }

  /*
   * Do we have the client's name?
   */
  if (!GSS_ERROR(major_status) && client_name)
  {
      OM_uint32 major_status2;

      /* Do this user want the name and we have not set it yet */
      if (src_name_char &&
	  (*src_name_char == NULL))
      {
	  major_status2 = gss_display_name(&minor_status2,
					   client_name,
					   tmp_buffer,
					   NULL);

	  if (major_status2 == GSS_S_COMPLETE)
	  {
       
	      cp = (char *)malloc(tmp_buffer->length+1);
	      if (cp) {
		  memcpy(cp, tmp_buffer->value, tmp_buffer->length);
		  cp[tmp_buffer->length] = '\0';
		  *src_name_char = cp;
	      } else {
		  major_status = GSS_S_FAILURE;
	      }
	  }
	  else
	  {
	      /* Cause failure */
	      major_status = major_status2;
	  }
	  gss_release_buffer(&minor_status2, tmp_buffer);
      }

      /*
       * Does the user want to know if this is user to user and
       * we have not set it yet?
       */
      if (!GSS_ERROR(major_status) &&
	  user_to_user_flag &&
	  (*user_to_user_flag == -1))
      {
 	  if ((major_status2 = gss_inquire_cred(&minor_status1,
					      cred_handle,
					      &my_name,			
					      NULL,
					      NULL,
					      NULL)) == GSS_S_COMPLETE)
	  {
	      major_status2 = gss_compare_name(&minor_status1,
					      client_name,
					      my_name,
					      user_to_user_flag);
#ifdef DEBUG
	  {
		OM_uint32 major_status3;
		OM_uint32 minor_status3;

		fprintf(stderr,"gss_assist_accept_sec_context_async(3): u2uflag:%d\n",*user_to_user_flag);

  	    major_status3 = gss_display_name(&minor_status3,
                           client_name,
                           tmp_buffer,
                           NULL);

		  if (GSS_ERROR(major_status3)) {
			fprintf(stderr,"   NO client_name: status:%8.8x %8.8x\n",
				major_status3, minor_status3);
		  } else {
		  	fprintf(stderr,"     client_name=%*s\n",
					tmp_buffer->length,
					tmp_buffer->value);
   		     gss_release_buffer(&minor_status2, tmp_buffer);
		  }
	
   	   major_status3 = gss_display_name(&minor_status3,
                           my_name,
                           tmp_buffer,
                           NULL);

		  if (GSS_ERROR(major_status3)) {
			fprintf(stderr,"   NO my_name: status:%8.8x %8.8x\n",
					major_status3, minor_status3);
		  } else {
		  	fprintf(stderr,"     my_name=%*s\n",
						tmp_buffer->length,
						tmp_buffer->value);
  	      gss_release_buffer(&minor_status2, tmp_buffer);
		  }
	  }
#endif
	  }

	  if (GSS_ERROR(major_status2))
	  {
	      /* Cause failure */
	      major_status = major_status2;
	  }

      }
  }

  gss_release_name(&minor_status2, &client_name);
  gss_release_name(&minor_status2, &my_name);
 

  *minor_status = minor_status1;
  return major_status;
}
