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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gass_transfer_referral.c Referral structure accessors.
 *
 * This module implements the referral accessors for the GASS transfer
 * library
 *
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#endif

#include "globus_gass_transfer.h"

/**
 * Get the number of URLs in this referral.
 * @ingroup globus_gass_transfer_referral
 *
 * This function examines the referral to determine if the number of
 * URLs which are contained in it. Each of these URLs should either
 * point to another referral, or to a URL containing the equivalent
 * file as the original URL request which caused this referral.
 *
 * @param referral
 *        The referral structure to query.
 *
 * @return This function returns the number of URL entries in the
 * referral, or 0, if there are none.
 */
globus_size_t
globus_gass_transfer_referral_get_count(
    globus_gass_transfer_referral_t *		referral)
{
    if(referral == GLOBUS_NULL)
    {
	return 0;
    }
    else
    {
	return referral->count;
    }
}
/* globus_gass_transfer_referral_get_count() */

/**
 * Get a URL string from a referral.
 * @ingroup globus_gass_transfer_referral
 *
 * This function examines the referral to retrieve a URL string from
 * it. A valid referal will contain one or more strings. They are
 * indexed from 0 to the value returned by
 * globus_gass_transfer_referral_get_count() - 1.
 *
 * The string returned by this function must not be freed by the caller.
 * It will remain valid until the referral structure is destroyed.
 *
 * @param referral
 *        The referral structure to query.
 *
 * @param index
 *        The URL to extract from the referral.
 * @return This function returns a string pointer containing the URL,
 * or NULL if the index or referral were invalid.
 */
char *
globus_gass_transfer_referral_get_url(
    globus_gass_transfer_referral_t *		referral,
    globus_size_t				index)
{
    if(referral == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    else if(index < 0 ||
	    index >= referral->count)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return referral->url[index];
    }
}
/* globus_gass_transfer_referral_get_url() */

/**
 * Free all memory used by a referral.
 * @ingroup globus_gass_transfer_referral
 *
 * This function frees all memory used by this referral. After
 * calling this function, the strings returned by calling
 * globus_gass_transfer_referral_get_url() must not be accessed.
 * Any further attempts to extract informatoin from this referral
 * will fail.
 *
 * @param referral
 *        The referral to destroy.
 *
 * @retval GLOBUS_SUCCESS
 *         The referral was successfully destroyed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         The referral parameter was GLOBUS_NULL. It could not be
 *         destroyed.
 */
int
globus_gass_transfer_referral_destroy(
    globus_gass_transfer_referral_t *		referral)
{
    globus_size_t				i;

    if(referral == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }

    for(i = 0; i < referral->count; i++)
    {
	globus_free(referral->url[i]);
    }
    globus_free(referral->url);

    referral->url = GLOBUS_NULL;
    referral->count = 0;

    return GLOBUS_SUCCESS;
}
/* globus_gass_transfer_referral_destroy() */
