#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file import_sec_context.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include <gssapi.h>
#include <stdio.h>

/**
 * @anchor globus_gsi_gss_assist
 * @mainpage Globus GSI GSS Assist
 *
 * The GSS Assist code provides convenience functions
 * for using the Globus GSS-API.
 */

/* @name Import Security Context
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * Import the security context from a file
 *
 * @param minor_status 
 *        GSSAPI return code.  This is a Globus Error code (or GLOBUS_SUCCESS)
 *        cast to a OM_uint32 pointer.  If an erro has occurred, the resulting
 *        error (from calling globus_error_get on this variable) needs to
 *        be freed by the caller
 * @param context_handle
 *        The imported context
 * @param token_status
 *        Errors that occurred while reading from the file
 * @param fdp
 *        the file descriptor pointing to a file containing the security
 *        context
 * @param fperr
 *        FILE * to write error messages
 * 
 * @return
 *        the major status
 */
OM_uint32
globus_gss_assist_import_sec_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t * 	                context_handle,
    int *			        token_status,
    int  				fdp,
    FILE *				fperr)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status = 0;
    gss_buffer_desc                     context_token = GSS_C_EMPTY_BUFFER;
    unsigned  char                      ibuf[4];
    int                                 fd = -1;
    char *                              context_fd_char; 
    static char *                       _function_name_ =
        "globus_gss_assist_import_sec_context";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

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

    context_token.length = (((  (unsigned int) ibuf[0]) << 24)
                            | (((unsigned int) ibuf[1]) << 16)
                            | (((unsigned int) ibuf[2]) << 8)
                            | ( (unsigned int) ibuf[3]) );

    if ((context_token.value =
         (void *) malloc(context_token.length)) == NULL)
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

    gss_release_buffer(&local_minor_status,
                       &context_token);

    if (fperr && (major_status != GSS_S_COMPLETE 
                  || *token_status != 0)) 
    {
        globus_gss_assist_display_status(
            fperr,
            "gss_assist_import_sec_context failure:",
            major_status,
            *minor_status,
            *token_status);
        fprintf(fperr, "token_status%d\n", *token_status);
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return major_status;
}
/* @} */
