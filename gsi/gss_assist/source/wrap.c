/******************************************************************************
wrap.c

Description:
	Globus GSSAPI Assist routine for the gss_wrap


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
Function:   globus_gss_assist_wrap()
Description:

Parameters:
	minor_status - gssapi return code
	context_handle - the context. 
	conf_req_flag
	qop_req
	input_message_buffer
	(Follwing are particular to this assist routine)
	token_status - assist routine get/send token status 
	a send_token routine 
	first arg for the send_token

Returns:
	GSS_S_COMPLETE on sucess
    Other gss errors on failure.  

******************************************************************************/
OM_uint32
globus_gss_assist_wrap_send
(OM_uint32 *          minor_status,
 const gss_ctx_id_t   context_handle,
 char *				  data,
 size_t				  length,
 int *				  token_status,
 int (*gss_assist_send_token)(void *, void *, size_t),
 void *gss_assist_send_context,
 FILE * fperr)
{

  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;
  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

  *token_status = 0;
  input_token->value = data;
  input_token->length = length;

  major_status = gss_wrap(minor_status,
                          context_handle,
                          0,
                          GSS_C_QOP_DEFAULT,
                          input_token,
                          NULL,
                          output_token);

#ifdef DEBUG
  fprintf(stderr,"Wrap_send:maj:%8.8x min:%8.8x inlen:%d outlen:%d\n",
				major_status, *minor_status, 
				input_token->length = length,
				output_token->length);
#endif
  if (major_status == GSS_S_COMPLETE)
  {
	*token_status = (*gss_assist_send_token)(gss_assist_send_context,
										output_token->value,
										output_token->length);
  }
      gss_release_buffer(&minor_status1,
                          output_token);

  if (fperr && (major_status != GSS_S_COMPLETE || *token_status != 0)) {
		globus_gss_assist_display_status(stderr,
                "gss_assist_wrap_send failure:",
                major_status,
                *minor_status,
                *token_status);
  }

  if (*token_status) {
#ifdef DEBUG
	fprintf(stderr,"TOKEN STATUS: %d\n",*token_status);
#endif
	major_status = GSS_S_FAILURE;
  }
  return major_status;
}
