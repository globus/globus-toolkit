/******************************************************************************
globus_gass_transfer_referral.c
 
Description:
    This module implements the referral accessors for the GASS transfer library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_gass_transfer.h"

/* Referral Accessors */

/*
 * Function: globus_gass_referral_get_count()
 * 
 * Description: Get the number of URLs in this referral structure.
 * 
 * Parameters: 
 * 
 * Returns: 
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

/*
 * Function: globus_gass_referral_get_url()
 * 
 * Description: Get the indexth url from a referral
 * 
 * Parameters: 
 * 
 * Returns: 
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

/*
 * Function: globus_gass_referral_destroy()
 * 
 * Description: Free up any memory associated with an URL referral.
 * 
 * Parameters: 
 * 
 * Returns: 
 */
int
globus_gass_transfer_referral_destroy(
    globus_gass_transfer_referral_t *		referral)
{
    int i;

    if(referral == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
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
