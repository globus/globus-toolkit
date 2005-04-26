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

/******************************************************************************
globus_gass_transfer_text.c
 
Description:
    This module implements the text conversion routines for the GASS transfer
    library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"

/*
 * Function: globus_gass_transfer_crlf_to_lf()
 * 
 * Description: Convert a byte array from 8-bit, CRLF delimited lines to
 *              7-bit LF delimited lines
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void
globus_gass_transfer_crlf_to_lf(
    globus_byte_t *				src,
    globus_size_t				src_len,
    globus_byte_t **				dst,
    globus_size_t *				dst_len)
{
    globus_size_t				i;
    globus_size_t				j;
    globus_size_t				cr_count=0;

    /* count \r\n pairs in the source string */
    for(i = 0; i < src_len-1; i++)
    {
	if(src[i] == '\r' &&
	   src[i+1] == '\n')
	{
	    cr_count++;
	}
    }
    /* malloc destination */
    *dst_len = sizeof(globus_byte_t) * (src_len - cr_count);
    *dst = (globus_byte_t *) globus_malloc(*dst_len);

    if(*dst == GLOBUS_NULL)
    {
	return;
    }

    /* copy as 7-bit ASCII, with \n deliminating lines */
    for(i = 0, j=0; i < src_len-1; i++,j++)
    {
	if(src[i] == '\r' && src[i+1] == '\n')
	{
	    (*dst)[j] = '\n';
	    i++;
	}
	else
	{
	    (*dst)[j] = src[i] & 0x7f;
	}
    }
    (*dst)[j] = src[i];
}
/* globus_gass_transfer_crlf_to_lf() */

/*
 * Function: globus_gass_transfer_crlf_to_lf()
 * 
 * Description: Convert a byte array from 8-bit, LF delimited lines to
 *              7-bit CRLF delimited lines
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void                                                        
globus_gass_transfer_lf_to_crlf(
    globus_byte_t *				src,        
    globus_size_t				src_len,
    globus_byte_t **				dst,
    globus_size_t *				dst_len)
{
    int						i;
    int						j;
    int						nl_count=0;

    /* count \n pairs in the source string */
    for(i = 0; i < src_len; i++)
    {
	if(src[i] == '\n')
	{
	    nl_count++;
	}
    }
    /* malloc destination */
    *dst_len = sizeof(globus_byte_t) * (src_len + nl_count);
    *dst = (globus_byte_t *) globus_malloc(*dst_len);

    if(*dst == GLOBUS_NULL)
    {
	return;
    }

    /* copy as 7-bit ASCII, with \r\n deliminating lines */
    for(i = 0, j=0; i < src_len; i++,j++)
    {
	if(src[i] == '\n')
	{
	    (*dst)[j] = '\r';
	    (*dst)[j+1] = '\n';
	    j++;
	}
	else
	{
	    (*dst)[j] = src[i] & 0x7f;
	}
    }
}
/* globus_gass_transfer_lf_to_crlf() */
