/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file tokens_n.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_io.h"
#include "assist_config.h"
#include "globus_gss_assist.h"

/**
 * @name Token Get Nexus
 * @ingroup globus_gsi_gss_assist_token
 */
/* @{ */
/**
 * Use a nexus socket to get the tokens
 *
 * Additional code has been added to detect tokens which 
 * are sent without a length field. These can currently be
 * only SSL tokens. This does require some knowledge of the 
 * underlying GSSAPI, by the application, but is within the 
 * guidelines of the GSSAPI specifications. 
 *
 * The get routine will automaticly attempt this test,
 * while a new send routine will check a flag. The old send
 * routine will work as before, sending a 4-byte length.
 *
 * @param arg
 *        the globus_io_handle_t to get the token from
 * @param bufp
 *        the buffer to read the token into
 * @param the size of what gets read
 *
 * @return 
 *        0 on success
 *        > 0 is internal return
 *        < 0 is the -errno returned from nexus
 */
int
globus_gss_assist_token_get_nexus(
    void *                              arg, 
    void **                             bufp, 
    size_t *                            sizep)
{
    unsigned char                       int_buf[5];
    unsigned char *                     pp;
    unsigned char *                     bp = NULL;
    int  	                        bsize;
    int  	                        dsize;
    int    	                        size;
    void * 	                        cp;
    int                                 err = 0;
    int		                        rc;
    globus_io_handle_t *  	        handle = (globus_io_handle_t *)arg;
    static char *                       _function_name_ =
        "globus_gss_assist_token_get_nexus";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;
	
    if ((rc = _nx_read_blocking(handle, int_buf, 4)) != 0)
    {
        return_value = rc == -1 ? GLOBUS_GSS_ASSIST_TOKEN_EOF : -rc;
        goto exit;
    }
    /*
     * check if the length is missing, and we are receiving
     * a SSL token directly.
     * SSLv3 will start with a flag byte in the twenties
     * followed by major version 3 minor version 0
     * Will also accept a SSLv2 hello 2 0 
     * or a TLS  3 1
     */

    if (int_buf[0]  >= 20 && int_buf[0] <= 26
        && (((int_buf[1] == 3 && (int_buf[2] == 0) || int_buf[2] == 1))
            || (int_buf[1] == 2 && int_buf[2] == 0))
        || ((int_buf[0] & 0x80) && int_buf[2] == 1))
    {
        /* looks like a SSL token read rest of length */

        if ((rc = _nx_read_blocking(handle, &int_buf[4], 1)) != 0)
        {
            return_value = rc == -1 ? GLOBUS_GSS_ASSIST_TOKEN_EOF : -rc;
            goto exit;
        }

        GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
            3, (globus_i_gsi_gss_assist_debug_fstream,
                _GASL("reading SSL token %.2x%.2x%.2x%.2x%.2x\n"),
                int_buf[0],int_buf[1],int_buf[2],int_buf[3],int_buf[4]));

        if ((int_buf[0] & 0x80)) 
        {
            /* Looks like a sslv2 hello. 
             * Length is of following bytes in header. 
             * we read in 5, 2 length and 3 extra, 
             * so only need next dsize -3
             */
            dsize = ( ((unsigned int) int_buf[0] & 0x7f)<<8 
                      | (unsigned int) int_buf[1]) - 3;
        } else {
            dsize = (  ( ((unsigned int) int_buf[3]) << 8)
                       |   ((unsigned int) int_buf[4]) );
        }

        /* If we are using the globus_ssleay, with
         * international version, we may be using the
         * "26" type, where the length is really the hash
         * length, and there is a hash, 8 byte seq andi
         * 4 byte data length following. We need to get
         * these as well.
         */
        
        if (int_buf[0] == 26)
        {
            bsize = dsize + 12;  /* MD, seq, data-length */
            bp = (void *)malloc(bsize);
            if (!bp)
            {
                return_value = GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
                goto exit;
            }
            if ((rc = _nx_read_blocking(handle, bp, bsize)) != 0)
            {
                return_value = rc == -1 ? GLOBUS_GSS_ASSIST_TOKEN_EOF : -rc;
                goto exit;
            }
            dsize = (  ( ((unsigned int) bp[bsize-4]) << 24)
                       | ( ((unsigned int) bp[bsize-3]) << 16)
                       | ( ((unsigned int) bp[bsize-2]) << 8)
                       |   ((unsigned int) bp[bsize-1]) );
            
            size = bsize + dsize + 5;
        }
        else
        {
            size = dsize + 5;
        }
        cp = (void *)malloc(size);
        if (!cp)
        {
            return_value = GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
            goto exit;
        }
        /* reassemble token header from int_buf and bp */

        pp = cp;
        memcpy(pp,int_buf,5);
        pp += 5;
        if (bp)
        {
            memcpy(pp,bp,bsize);
            pp += bsize;
            free(bp);
            bp = NULL;
        }
        if ((rc = _nx_read_blocking(handle, pp, dsize)) != 0)
        {
            return_value = rc == -1 ? GLOBUS_GSS_ASSIST_TOKEN_EOF : -rc;
            goto exit;
        }
    }
    else
    {

        size = (  ( ((unsigned int) int_buf[0]) << 24)
                  | ( ((unsigned int) int_buf[1]) << 16)
                  | ( ((unsigned int) int_buf[2]) << 8)
                  |   ((unsigned int) int_buf[3]) );
        
        
        if (size > 1<<24 || size < 0) 
        {
            size = 80;
            err = 1;
        }

        GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
            3, (globus_i_gsi_gss_assist_debug_fstream,
                _GASL("reading token of size=%d\n", size)));

        cp = (char *) malloc(size);
        if (!cp) 
        {
            return_value = GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
            goto exit;
        }
	
        if ((rc = _nx_read_blocking(handle, (char *) cp, size)) != 0)
        {
            return_value = rc == -1 ? GLOBUS_GSS_ASSIST_TOKEN_EOF : -rc;
            goto exit;
        } 

        if (err)
        {
            /* 
             * bad formed token size, attempt to print first 80 bytes 
             * as it may be readable
             */
            
            GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
                3, (globus_i_gsi_gss_assist_debug_fstream,
                    _GASL(" bad token  %c%c%c%c%s\n"),
                    int_buf[0], int_buf[1], 
                    int_buf[2], int_buf[3], (char *) cp));
            return_value = GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE;
            goto exit;
        }
    }
    *bufp = cp;
    *sizep = size;

 exit:

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return return_value;
}
/* @} */

/**
 * @name Token Send Nexus
 * @ingroup globus_gsi_gss_assist_token
 */
/* @{ */
/**
 * Write a token to the nexus io handle. 
 * This function provides parameter types that allow 
 * it to be passed to
 * @ref globus_gss_assist_init_sec_context and 
 * @ref globus_gss_assist_accept_sec_context
 * 
 * @param arg
 *        nexus io handle to send the token on
 * @param buf
 *        the token as a buffer
 * @param size
 *        the size of the buffer
 *
 * @return
 *        0 on success
 *        >0 on error
 *        <0 on errno error (-errno)
 */
int
globus_gss_assist_token_send_nexus(
    void *                              arg,  
    void *                              buf, 
    size_t                              size)
{ 
    int                                 return_value = 0;
    globus_gss_assist_ex                ex; 
    static char *                       _function_name_ =
        "globus_gss_assist_token_send_nexus";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    ex.arg = arg;
    ex.flags = 0;

    return_value = 
        globus_gss_assist_token_send_nexus_ex((void *)&ex, buf, size);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return return_value;
}
/* @} */

/**
 * @name Token Send Nexus Without Length
 * @ingroup globus_gsi_gss_assist_token
 */
/* @{ */
/**
 * Send a token on a nexus IO handle.  Using this function
 * the length is not sent.  See 
 * @ref globus_gss_assist_token_get_nexus for further info.
 */
int
globus_gss_assist_token_send_nexus_without_length(
    void *                              arg,  
    void *                              buf, 
    size_t                              size)
{
    int                                 return_value;
    globus_gss_assist_ex                ex;
    static char *                       _function_name_ =
        "globus_gss_assist_token_send_nexus_without_length";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    ex.arg  = arg;
    ex.flags = GLOBUS_GSS_ASSIST_EX_SEND_WITHOUT_LENGTH;

    return_value = globus_gss_assist_token_send_nexus_ex((void *)&ex, 
                                                         buf, size);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return return_value;
}
/* @} */

/**
 * @name Token Send Nexus EX
 * @ingroup globus_gsi_gss_assist_token
 */
/* @{ */
/**
 * Write a token to the open file descripter.
 * will look at the flag to determine if the length field need
 * to be written.
 *
 * @param exp
 *        The globus_gss_assist_ex that the wraps the nexus IO
 *        handle to send the token on
 * @param buf
 *        the buffer holding the token
 * @param size
 *        the size of the buffer
 *
 * @return
 *        0 on success
 *        >0 on error
 *        <0 on errno error (-errno)
 */
int
globus_gss_assist_token_send_nexus_ex(
    void *                              exp,  
    void *                              buf, 
    size_t                              size)
{
    unsigned char                       int_buf[4];
    char *                              header = (char *) buf;
    int 	                        rc;
    globus_io_handle_t *                handle;
    globus_gss_assist_ex *              ex;
    static char *                       _function_name_ =
        "globus_gss_assist_token_send_nexus_ex";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    ex = (globus_gss_assist_ex *) exp;
    handle = (globus_io_handle_t *) ex->arg;

    /*
     * Will always send SSL type tokens without a length
     */

    if (!(size > 5 && header[0] <= 26 && header[0] >= 20
          && ((header[1] == 3 && (header[2] == 0 || header[1] == 1))
              || (header[1] == 2 && header[2] == 0))))
    {
        if (!(ex->flags & GLOBUS_GSS_ASSIST_EX_SEND_WITHOUT_LENGTH)) 
        {
            int_buf[0] =  size >> 24;
            int_buf[1] =  size >> 16;
            int_buf[2] =  size >>  8;
            int_buf[3] =  size;
            
            if ((rc = _nx_write_blocking(handle, int_buf, 4)) != 0) 
            {
                return_value = rc;
                goto exit;
            }
        }
    }

    if ((rc = _nx_write_blocking(handle, (char *) buf, size)) != 0)
    {
     	return_value = rc;
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return return_value;
}
/* @} */
