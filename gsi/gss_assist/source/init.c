/******************************************************************************
init.c

Description:
	Globus GSSAPI Assist routine for the gss_init_sec_context


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

extern gss_OID gss_nt_service_name;
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
	Initialize a gssapi security connection. Used by the client.  
	The context_handle is returned, and there is one for each
	connection.  This routine will take cake of the looping
	and token processing, using the supplied get_token and
	send_token routines. 

Parameters:
	minor_status - gssapi return code
	initiator_cred_handle - the cred handle obtained by acquire_cred.
	context_handle - pointer to returned context. 
	target_name_char - char string repersentation of the
		server to be contacted. 
	req_flags - request flags, such as GSS_C_DELEG_FLAG for delegation
		and the GSS_C_MUTUAL_FLAG for mutual authentication. 
	ret_flags - Pointer to which services are available after
		the connection is established. Maybe NULL if not wanted. 

	(Follwing are particular to this assist routine)
	token_status - assist routine get/send token status 
	a get_token routine
	first arg for the get_token 
	a send_token routine 
	first arg for the send_token

Returns:
	GSS_S_COMPLETE on sucess
    Other gss errors on failure.  

******************************************************************************/
OM_uint32
globus_gss_assist_init_sec_context
(OM_uint32 *			minor_status,
 const gss_cred_id_t	cred_handle,
 gss_ctx_id_t *			context_handle,
 char *					target_name_char,
 OM_uint32 				req_flags,
 OM_uint32 *			ret_flags,
 int *		 			token_status,
 int (*gss_assist_get_token)(void *, void **, size_t *), 
 void *gss_assist_get_context,
 int (*gss_assist_send_token)(void *, void *, size_t),
 void *gss_assist_send_context)
{

  int context_established = 0;

  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;
  OM_uint32 minor_status2 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;
  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

  gss_name_t target_name = GSS_C_NO_NAME;
  gss_OID target_name_type = GSS_C_NO_OID;
  gss_OID mech_type = GSS_C_NO_OID;
  OM_uint32  time_req = 0;
  OM_uint32  time_rec = 0;
  gss_channel_bindings_t input_chan_bindings = 
				GSS_C_NO_CHANNEL_BINDINGS;
  gss_OID * actual_mech_type = NULL;

  gss_buffer_desc tmp_buffer_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    tmp_buffer      = &tmp_buffer_desc;

  *context_handle = GSS_C_NO_CONTEXT;
  if(ret_flags) {
	*ret_flags = 0;
  }

  /* supply the service name to the gss-api
   * If NULL, then we want user_to_user
   * so get it from the cred
   */

  if (target_name_char) {
    tmp_buffer->value = target_name_char;
    tmp_buffer->length = strlen(target_name_char);

	/* 
	 * A gss_nt_service_name is of the form service@FQDN
	 * At least the Globus gssapi, and the Kerberos gssapi 
	 * use the same form. We will check for 
	 * two special forms here: host@FQDN and ftp@FQDN
	 * This could be another parameter to the gss_assist
	 * instead. 
	 */

	if (!strncmp("host@",target_name_char,5) || 
		!strncmp("ftp@",target_name_char,4)) { 
			target_name_type = gss_nt_service_name;
	}

    major_status = gss_import_name(&minor_status1,
                           tmp_buffer,
                           target_name_type,
                           &target_name);
  } else {

	major_status = gss_inquire_cred(&minor_status1,
						cred_handle,
						&target_name,
						NULL,
						NULL,
						NULL);
  }

  if (major_status == GSS_S_COMPLETE)
  while (!context_established) {
#ifdef DEBUG
	fprintf(stderr,"gss_assist_init_sec_context(1)req:%8.8x:inlen:%d\n",
				req_flags,
				input_token->length);
#endif

    major_status = gss_init_sec_context(&minor_status1,
                                        cred_handle,
                                        context_handle,
                                        target_name,
                                        mech_type,
                                        req_flags,
                                        time_req,
                                        input_chan_bindings,
                                        input_token,
                                        actual_mech_type,
                                        output_token,
                                        ret_flags,
                                        &time_rec);
#ifdef DEBUG
	fprintf(stderr,"gss_assist_init_sec_context(2)maj:%8.8x:min:%8.8x:ret:%8.8x:outlen:%d:context:%p\n",
				major_status, minor_status1, 
				(ret_flags)?*ret_flags:-1,
				output_token->length,*context_handle);
#endif

	if (input_token->length > 0) {
		free(input_token->value);
		input_token->length = 0;
	}

    if (output_token->length != 0) {
      if ((*token_status = gss_assist_send_token(gss_assist_send_context, 
                   output_token->value,
                   output_token->length)) != 0) {
        major_status = 
			GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_WRITE;
      }
      gss_release_buffer(&minor_status2,
                          output_token);
    }
    if (GSS_ERROR(major_status)) {
      if (*context_handle != GSS_C_NO_CONTEXT)
         gss_delete_sec_context(&minor_status2,
                                context_handle,
                                GSS_C_NO_BUFFER);
        break;
    }
    if (major_status & GSS_S_CONTINUE_NEEDED) {
       if ((*token_status =  gss_assist_get_token(gss_assist_get_context,
                        &input_token->value,
                        &input_token->length)) != 0) {
         major_status = 
			GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_READ;
		 break;
       }

    } else {
       context_established = 1;
    }
  } /* end of GSS loop */

  if (input_token->length > 0) {
    free(input_token->value); /* alloc done by g_get_token */
	input_token->value = NULL;
    input_token->length = 0;
  }

  if (target_name != GSS_C_NO_NAME) {
	gss_release_name(&minor_status2,&target_name);
  }

  *minor_status = minor_status1;
  return major_status;
}



/******************************************************************************
Function:   globus_gss_assist_init_sec_context_async()
Description:
	This is a asynchronous version of the
	globus_gss_assist_init_sec_context() function. Instead of looping
	itself it passes in and out the read and written buffers and
	the calling application is responsible for doing the I/O directly.



Parameters:
	minor_status - gssapi return code

	initiator_cred_handle - the cred handle obtained by acquire_cred.

	context_handle - pointer to returned context. 

	target_name_char - char string repersentation of the
		server to be contacted. 

	req_flags - request flags, such as GSS_C_DELEG_FLAG for delegation
		and the GSS_C_MUTUAL_FLAG for mutual authentication. 

	ret_flags - Pointer to which services are available after
		the connection is established. Maybe NULL if not wanted. 

	input_buffer - pointer to a buffer received from peer. Should
		be NULL on first call.

	input_buffer_len - length of the buffer input_buffer. Should
		be zero on first call.

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
globus_gss_assist_init_sec_context_async
(OM_uint32 *			minor_status,
 const gss_cred_id_t		cred_handle,
 gss_ctx_id_t *			context_handle,
 char *				target_name_char,
 OM_uint32 			req_flags,
 OM_uint32 *			ret_flags,
 void *				input_buffer,
 size_t				input_buffer_len,
 void **			output_bufferp,
 size_t *			output_buffer_lenp)
{
  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;
  OM_uint32 minor_status2 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;
  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

  gss_name_t target_name = GSS_C_NO_NAME;
  gss_OID target_name_type = GSS_C_NO_OID;
  gss_OID mech_type = GSS_C_NO_OID;
  OM_uint32  time_req = 0;
  OM_uint32  time_rec = 0;
#ifdef CLASS_ADD
  struct gss_channel_bindings_struct class_add_test_channel_bindings
	= {0, {0,NULL},
	   0, {0,NULL},
	   {60,
        "Test class add data added by globus_gss_assist_init_sec_context_async"
	   }
	  };
#endif
  gss_channel_bindings_t input_chan_bindings = 
#ifndef CLASS_ADD
      GSS_C_NO_CHANNEL_BINDINGS;
#else
	&class_add_test_channel_bindings;
#endif
  gss_OID * actual_mech_type = NULL;

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
      if(ret_flags) {
	  *ret_flags = 0;
      }
  }

  /* supply the service name to the gss-api
   * If NULL, then we want user_to_user
   * so get it from the cred
   */

  if (target_name_char)
  {
      tmp_buffer->value = target_name_char;
      tmp_buffer->length = strlen(target_name_char);

      /* 
       * A gss_nt_service_name is of the form service@FQDN
       * At least the Globus gssapi, and the Kerberos gssapi 
       * use the same form. We will check for 
       * two special forms here: host@FQDN and ftp@FQDN
       * This could be another parameter to the gss_assist
       * instead. 
       */

      if (!strncmp("host@",target_name_char,5) || 
	  !strncmp("ftp@",target_name_char,4)) { 
	  target_name_type = gss_nt_service_name;
      }

      major_status = gss_import_name(&minor_status1,
				     tmp_buffer,
				     target_name_type,
				     &target_name);
  } else {

      major_status = gss_inquire_cred(&minor_status1,
				      cred_handle,
				      &target_name,
				      NULL,
				      NULL,
				      NULL);
  }

  if (major_status == GSS_S_COMPLETE)
  {
#ifdef DEBUG
	fprintf(stderr,"gss_assist_init_sec_context_async(1)req:%8.8x:inlen:%d\n",
				req_flags,
				input_token->length);
#endif
      major_status = gss_init_sec_context(&minor_status1,
					  cred_handle,
					  context_handle,
					  target_name,
					  mech_type,
					  req_flags,
					  time_req,
					  input_chan_bindings,
					  input_token,
					  actual_mech_type,
					  output_token,
					  ret_flags,
					  &time_rec);
#ifdef DEBUG
	fprintf(stderr,"gss_assist_init_sec_context_async(2)maj:%8.8x:min:%8.8x:ret:%8.8x:outlen:%d:context:%p\n",
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

  }

  if (target_name != GSS_C_NO_NAME)
  {
	gss_release_name(&minor_status2,&target_name);
  }

  *minor_status = minor_status1;
  return major_status;
}
