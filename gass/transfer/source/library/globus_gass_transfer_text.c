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
