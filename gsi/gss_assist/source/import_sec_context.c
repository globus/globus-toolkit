
/******************************************************************************
import_sec_context.c

Description:
	Globus GSSAPI Assist routine for the gss_import_sec_context.c


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
#include <stdio.h>

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
Function:   globus_gss_assist_import_sec_context()
Description:

Parameters:
	minor_status - gssapi return code
	context_handle - pointer to returned context 
	token_status - errors for reading the file
	fd  - file descripter number of open file  or -1
	fperr - error FILE or NULL

Returns:
	GSS_S_COMPLETE on sucess
    Other gss errors on failure.  

******************************************************************************/
OM_uint32
globus_gss_assist_import_sec_context
(OM_uint32 *          minor_status,
 gss_ctx_id_t * 	  context_handle,
 int *				  token_status,
 int  				  fdp,
 FILE *				  fperr)
{

	OM_uint32 major_status = GSS_S_COMPLETE;
	OM_uint32 minor_status1 = 0;
	gss_buffer_desc context_token = GSS_C_EMPTY_BUFFER;
	unsigned  char ibuf[4];
	int       fd = -1;
	char *    context_fd_char; 

	*minor_status = 0;
	*token_status = 0;

	if (fdp < 0)
	{
		if ((context_fd_char = getenv("GRID_SECURITY_CONTEXT_FD"))
						== NULL)
		{
			*token_status = GLOBUS_GSS_ASSIST_TOKEN_NOT_FOUND;
			goto err;
		}
		if ((fd = atoi(context_fd_char)) <= 0)
		{
			*token_status = GLOBUS_GSS_ASSIST_TOKEN_NOT_FOUND;
			goto err;
		}
	}
	else
	{
		fd = fdp;
	}

	if ((read(fd, ibuf,4)) != 4)
	{
		*token_status = GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE;
		goto err;
	}

	context_token.length = (  ( ((unsigned int) ibuf[0]) << 24)
                            | ( ((unsigned int) ibuf[1]) << 16)
                            | ( ((unsigned int) ibuf[2]) << 8)
                            |   ((unsigned int) ibuf[3]) );

	if ((context_token.value =
            (void *)malloc(context_token.length)) == NULL)
	{
		*token_status = GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
        goto err;
	}

	if ((read(fd,context_token.value,
               context_token.length)) !=context_token.length)
	{
		*token_status = GLOBUS_GSS_ASSIST_TOKEN_EOF;
		goto err;
	}
		
    major_status = gss_import_sec_context(minor_status,
                                          &context_token,
                                          context_handle);

err:
	if (fdp < 0 && fd >= 0)
	{
		(void *) close(fd);
	}

	if (*token_status) {
		major_status = GSS_S_FAILURE;
	}

    gss_release_buffer(&minor_status1,
                          &context_token);

	if (fperr && (major_status != GSS_S_COMPLETE 
					|| *token_status != 0)) 
	{
		globus_gss_assist_display_status(fperr,
                "gss_assist_import_sec_context failure:",
                major_status,
                *minor_status,
                *token_status);
		fprintf(fperr,"token_status%d\n",*token_status);
	}


  return major_status;
}
