/**********************************************************************

release_buffer_set.c:

Description:
    GSSAPI routine to release the contents of a buffer set

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";


#include "gssapi_ssleay.h"
#include <string.h>

/**
 * @defgroup buffer_set Functions for manipulating a buffer set
 *
 * @{
 */

/**
 * Create a empty buffer set.
 *
 * This function allocates and initializes a empty buffer set. The
 * memory allocated in this function should be freed by a call to
 * gss_release_buffer_set.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param buffer_set
 *        Pointer to a buffer set structure.
 * 
 * @return
 *        GSS_S_COMPLETE upon success
 *        GSS_S_FAILURE failure
 *
 * @see gss_add_buffer_set_member
 * @see gss_release_buffer_set
 */

OM_uint32 
GSS_CALLCONV gss_create_empty_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t *                  buffer_set)
{
    *minor_status = 0;

    /* Sanity check */
    if ((buffer_set == NULL) ||
        (minor_status == NULL))
    {
        GSSerr(GSSERR_F_CREATE_EMPTY_BUFFER_SET,
               GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }

    *buffer_set = (gss_buffer_set_desc *) malloc(
        sizeof(gss_buffer_set_desc));

    if (!*buffer_set)
    {
        GSSerr(GSSERR_F_CREATE_EMPTY_BUFFER_SET,
               GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
	
    (*buffer_set)->count = 0;
    (*buffer_set)->elements = NULL;
	
    return GSS_S_COMPLETE;
} /* gss_create_empty_buffer_set */


/**
 * Add a buffer to a buffer set.
 *
 * This function allocates a new gss_buffer_t, intializes it with the
 * values in the member_buffer parameter.
 *
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param member_buffer
 *        Buffer to insert into the buffer set.
 * @param buffer_set
 *        Pointer to a initialized buffer set structure.
 * 
 * @return
 *        GSS_S_COMPLETE upon success
 *        GSS_S_FAILURE failure
 *
 * @see gss_create_empty_buffer_set
 * @see gss_release_buffer_set
 */

OM_uint32
GSS_CALLCONV gss_add_buffer_set_member(
    OM_uint32 *                         minor_status,
    const gss_buffer_t                  member_buffer,
    gss_buffer_set_t *                  buffer_set)
{
    int                                 new_count;
    gss_buffer_t                        new_elements;
    gss_buffer_set_t                    set;
        
    /* Sanity check */
    if ((minor_status == NULL) ||
        (member_buffer == NULL) ||
        (buffer_set == NULL) ||
        (*buffer_set == GSS_C_NO_BUFFER_SET))
    {
        GSSerr(GSSERR_F_ADD_BUFFER_SET_MEMBER,
               GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
        
    set = *buffer_set;
        
    new_count = set->count + 1;
    new_elements = malloc(sizeof(gss_buffer_desc) * new_count);
        
    if (new_elements == NULL)
    {
        GSSerr(GSSERR_F_ADD_BUFFER_SET_MEMBER,
               GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }
        
    if (set->count > 0)
    {
        /* Copy existing buffers */
        memcpy(new_elements, set->elements,
               sizeof(gss_buffer_desc) * set->count);
    }
        
    /* And append new buffer */
    new_elements[set->count].value = malloc(member_buffer->length);

    if(new_elements[set->count].value == NULL)
    {
        free(new_elements);
        GSSerr(GSSERR_F_ADD_BUFFER_SET_MEMBER,
               GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        return GSS_S_FAILURE;
    }

    memcpy(new_elements[set->count].value,
           member_buffer->value,
           member_buffer->length);

    new_elements[set->count].length = member_buffer->length;
    
    if (set->elements != NULL)
    {
        free(set->elements);
    }
        
    set->count = new_count;
    set->elements = new_elements;
        
    return GSS_S_COMPLETE;
}

/**
 * Free all memory associated with a buffer set.
 *
 * This function will free all memory associated with a buffer
 * set. Note that it will also free all memory associated with the
 * buffers int the buffer set.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param buffer_set
 *        Pointer to a buffer set structure. This pointer will point
 *        at a NULL value upon return.
 * 
 * @return
 *        GSS_S_COMPLETE upon success
 *        GSS_S_FAILURE failure
 *
 * @see gss_create_empty_buffer_set
 * @see gss_add_buffer_set_member
 */

OM_uint32 
GSS_CALLCONV gss_release_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t *                  buffer_set)
{
    int                                 i;
    
    *minor_status = 0;
        
    if (buffer_set == NULL ||
        *buffer_set == GSS_C_NO_BUFFER_SET)
    {
        return GSS_S_COMPLETE ;
    }

    for(i=0;i<(*buffer_set)->count;i++)
    {
        gss_release_buffer(minor_status,
                           &(*buffer_set)->elements[i]);
    }

    free((*buffer_set)->elements);

    free(*buffer_set);

    *buffer_set = NULL;
    
    return GSS_S_COMPLETE ;

} /* gss_release_buffer_set */

/**
 * @}
 */



