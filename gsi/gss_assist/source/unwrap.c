
/******************************************************************************
unwrap.c

Description:
	Globus GSSAPI Assist routine for the gss_unwrap


CVS Information:
	$Source$
	$Date$
	$Revision$
	$Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_gss_assist.h"
#include <gssapi.h>

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
Function:   globus_gss_assist_get_unwrap()
Description:

Parameters:
	minor_status - gssapi return code
	context_handle - the context 
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
globus_gss_assist_get_unwrap
(OM_uint32 *          minor_status,
 const gss_ctx_id_t   context_handle,
 char **			  data,
 size_t *			  length,
 int *				  token_status,
 int (*gss_assist_get_token)(void *, void **, size_t *),
 void *gss_assist_get_context,
 FILE * fperr)
{

  OM_uint32 major_status = GSS_S_COMPLETE;
  OM_uint32 minor_status1 = 0;

  gss_buffer_desc input_token_desc  = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    input_token       = &input_token_desc;
  gss_buffer_desc output_token_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t    output_token      = &output_token_desc;

#ifdef DEBUG
  fprintf(stderr,"UNWRAP_READ\n");
#endif

  *token_status = (*gss_assist_get_token)(gss_assist_get_context,
						&input_token->value,
						&input_token->length);

  if (*token_status == 0) {

  	major_status = gss_unwrap(minor_status,
                          context_handle,
						  input_token,
                          output_token,
						  NULL,
						  NULL);

#ifdef DEBUG
	fprintf(stderr,"unwrap: maj:%8.8x min:%8.8x inlen:%d outlen:%d\n",
			major_status, *minor_status, 
				input_token->length,
				output_token->length);
#endif
    gss_release_buffer(&minor_status1,
                          input_token);

	*data = output_token->value;
	*length = output_token->length;
  }

  if (fperr && (major_status != GSS_S_COMPLETE || *token_status != 0)) {
		globus_gss_assist_display_status(stderr,
                "gss_assist_get_unwrap failure:",
                major_status,
                *minor_status,
                *token_status);
  }

  *data = output_token->value;
  *length = output_token->length;

  if (*token_status) {
	major_status = GSS_S_FAILURE;
  }
  return major_status;
}
