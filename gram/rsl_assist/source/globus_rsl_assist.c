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
 * globus_rsl_assist.c
 *
 * Description:
 *   The rsl_assist library provide a set of functions to help working with
 *   an RSL.
 *   It also contains some function to access the MDS; those function will be
 *   moved to a new library "mds_assist" in future release of GLOBUS.
 *   
 * CVS Information:
 *
 *   $Source$
 *   $Date$
 *   $Revision$
 *   $Author$
 *****************************************************************************/
#include "globus_common.h"
#include "globus_rsl_assist.h"

#include <string.h>

/*
 * Function: globus_rsl_assist_attributes_canonicalize()
 *
 * Given an RSL tree (parsed RSL), walk the tree finding all attributes of
 * RSL relations (i.e. (var=value) pairs) and canonicalize them by calling the
 * ..._string_canonicalize function.
 *
 * Returns:
 *     GLOBUS_SUCCESS or GLOBUS_FAILURE.  If GLOBUS_SUCCESS is returned then
 * any and all attributes contained in the passed in RSL tree will have been
 * canonicalized.
 */
int
globus_rsl_assist_attributes_canonicalize(globus_rsl_t * rsl)
{
 
    globus_list_t *             lists=GLOBUS_NULL;
    globus_rsl_t *              an_rsl;

    /*
     * if the request is a multirequest, run this function repeatedly
     * over the list of requests
     */
    if (globus_rsl_is_boolean_multi(rsl))
    {
        lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(rsl);
        while (!globus_list_empty(lists))
        {
            an_rsl=globus_list_first(lists);
            if (globus_rsl_assist_attributes_canonicalize(an_rsl) 
                != GLOBUS_SUCCESS)
            {
                return GLOBUS_FAILURE;
            }
            lists=globus_list_rest(lists);
        }
        return GLOBUS_SUCCESS;
    }
    else if (globus_rsl_is_boolean(rsl))
    {
        lists = globus_rsl_boolean_get_operand_list(rsl);

        /* look at each operand of the boolean, and figure out if
         * it is a nested boolean, or a relation (x=y)
         */
        while(!globus_list_empty(lists))
        {
            an_rsl = globus_list_first(lists);

            /* if boolean, recursively process the request */
            if (globus_rsl_is_boolean(an_rsl))
            {
                if (globus_rsl_assist_attributes_canonicalize(an_rsl)
                       != GLOBUS_SUCCESS)
                {
                    return GLOBUS_FAILURE;
                }
            }
            else if (globus_rsl_is_relation(an_rsl))
            {
                globus_rsl_assist_string_canonicalize(
                       globus_rsl_relation_get_attribute(an_rsl));
            }
            lists = globus_list_rest(lists);
        }
        return GLOBUS_SUCCESS;
    }
    else if (globus_rsl_is_relation(rsl))
    {
        globus_rsl_assist_string_canonicalize(
               globus_rsl_relation_get_attribute(rsl));
    }
    else
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;

} /* globus_rsl_assist_attributes_canonicalize() */


/*
 * Function: globus_rsl_assist_string_canonicalize()
 *
 * Canonizing a string in this implementation means to remove any
 * underscores and moving all characters to lowercase.
 *
 * Returns: void
 */
void
globus_rsl_assist_string_canonicalize(char * ptr)
{
    char * tmp_p;

    if (ptr == GLOBUS_NULL)
        return;

    for (tmp_p=ptr; *ptr != '\0'; ptr++)
    {
        if ( *ptr == '_' )
        {
            continue;
        }

        *tmp_p = tolower(*ptr);
        tmp_p++;
    }
    *tmp_p = '\0';

    return;

} /* globus_rsl_assist_string_canonicalize() */
