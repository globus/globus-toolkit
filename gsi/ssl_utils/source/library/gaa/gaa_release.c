/**********************************************************************
 gaa_release.c:

Description:
	This file used internally by the gaa routines
**********************************************************************/
#include "globus_gaa.h"
#include "stdio.h" /* for fprintf() */

/**********************************************************************
Function:  gaa_release_buffer_contents

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_buffer_contents (uint32         *minor_status,
                    gaa_buffer_ptr  buffer)
{

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_buffer_contents:\n");
#endif /* DEBUG */

 	if (buffer == NULL || buffer == GAA_NO_BUFFER) return GAA_SUCCESS;
       
	if (buffer->value) free(buffer->value);
	buffer->length = 0;

	return GAA_SUCCESS;

} /* gaa_release_buffer_contents */
/**********************************************************************
Function:  gaa_release_buffer

Description:
	Release the buffer

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_buffer(uint32         *minor_status,
                    gaa_buffer_ptr *  buffer)
{

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_buffer:\n");
#endif /* DEBUG */

 	if (buffer == NULL || *buffer == NULL) return GAA_SUCCESS;
       
    free(*buffer);
	*buffer = NULL;

	return GAA_SUCCESS;

} /* gaa_release_buffer */

/**********************************************************************
Function:  gaa_release_options

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_options(uint32          *minor_status,
                    gaa_options_ptr  buffer)
{
#ifdef DEBUG
fprintf(stderr, "\ngaa_release_options:\n");
#endif /* DEBUG */

 	if (buffer == NULL || buffer == GAA_NO_OPTIONS) return GAA_SUCCESS;
       
	if (buffer->value) free(buffer->value);
	buffer->length = 0;

  free(buffer);

	return GAA_SUCCESS;

} /* gaa_release_options */
     
/**********************************************************************
Function:  gaa_release_data

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_data (uint32       *minor_status,
                  gaa_data_ptr  buffer)
{


#ifdef DEBUG
fprintf(stderr, "\ngaa_release_data:\n");
#endif /* DEBUG */

 	if (buffer == NULL || buffer == GAA_NO_DATA) return GAA_SUCCESS;
       
	if (buffer->str)       free(buffer->str);
	if (buffer->error_str) free(buffer->error_str);

        free(buffer);

	return GAA_SUCCESS;

} /* gaa_release_data */



/**********************************************************************

Function:   gaa_delete_sec_context()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_sec_context(uint32             *minor_status,
                       gaa_sec_context_ptr *sec_context)
{

 gaa_sec_context_ptr  *context_handle = sec_context;
 uint32                inv_minor_status = 0, inv_major_status = 0;


#ifdef DEBUG
fprintf(stderr, "\ngaa_release_sec_context:\n");
#endif /* DEBUG */

	if (*context_handle == NULL || *context_handle == GAA_NO_SEC_CONTEXT) 
	return GAA_SUCCESS ;

	/* ignore errors to allow for incomplete context handles */

	if ((*context_handle)->identity_cred!= NULL) 
        inv_major_status = gaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->identity_cred));
	

       if ((*context_handle)->authr_cred!= NULL)         
       inv_major_status = gaa_release_authr_cred(&inv_minor_status,
			      &((*context_handle)->authr_cred));
	

       if ((*context_handle)->group_membership!= NULL) 
       inv_major_status = gaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->group_membership));
      

       if ((*context_handle)->group_non_membership!= NULL) 
       inv_major_status = gaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->group_non_membership));
       

       if ((*context_handle)->attributes!= NULL) 
       inv_major_status = gaa_release_attributes(&inv_minor_status,
			      &((*context_handle)->attributes));
	

      if ((*context_handle)->unevl_cred!= NULL)
      inv_major_status = gaa_release_uneval_cred(&inv_minor_status,
			      &((*context_handle)->unevl_cred));
	

      if ((*context_handle)->connection_state!= NULL)  
      {
         inv_major_status = gaa_release_buffer_contents(&inv_minor_status,
			      (*context_handle)->connection_state);

         inv_major_status = gaa_release_buffer(&inv_minor_status,
			      &((*context_handle)->connection_state));
	  }

     free(*context_handle);
    *context_handle = GAA_NO_SEC_CONTEXT;

  return GAA_SUCCESS;

} /* gaa_delete_sec_context */

/**********************************************************************
Function:   gaa_release_identity_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_identity_cred (uint32                *minor_status,
                           gaa_identity_cred_ptr *identity_cred)

{
  gaa_identity_cred_ptr  *cred = identity_cred;
  uint32                  inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_identity_cred:\n");
#endif /* DEBUG */


	if (*cred == NULL || *cred == GAA_NO_IDENTITY_CRED) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

	if ((*cred)->principal!= NULL) 
	inv_major_status = gaa_release_principals(&inv_minor_status,
			                          &((*cred)->principal));
       
        if ((*cred)->conditions!= NULL) 
	inv_major_status = gaa_release_conditions(&inv_minor_status,
			                          &((*cred)->conditions));
	
        if ((*cred)->mech_spec_cred!= NULL) 
		{
        	inv_major_status = 
				gaa_release_buffer_contents(&inv_minor_status,
			                      (*cred)->mech_spec_cred);
			inv_major_status = gaa_release_buffer(&inv_minor_status,
						&((*cred)->mech_spec_cred));
		}
	
        if ((*cred)->next!= NULL) 
        inv_major_status = gaa_release_identity_cred(&inv_minor_status,
			                             &((*cred)->next));
    free(*cred);

   return GAA_SUCCESS;

} 

/**********************************************************************
Function:   gaa_release_authr_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_authr_cred(uint32             *minor_status,
                       gaa_authr_cred_ptr *authr_cred)

{
  gaa_authr_cred_ptr   *cred = authr_cred;
  uint32               inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_authr_cred:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_AUTHORIZATION_CRED) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

	if ((*cred)->grantor != NULL)
	inv_major_status = gaa_release_principals(&inv_minor_status,
			      &((*cred)->grantor));
	

	if ((*cred)->grantee != NULL)
	inv_major_status = gaa_release_principals(&inv_minor_status,
			      &((*cred)->grantee));
	

    /*
     *DEE what about release of objects? 
     * Since There are is no gaa_allocate_authr_cred
     * that can be fixed when this routine is actually used. 
     */

        if ((*cred)->access_rights!= NULL) 
	inv_major_status = gaa_release_rights(&inv_minor_status,
			                      &((*cred)->access_rights));
	
       if ((*cred)->mech_spec_cred!= NULL) 
       {
           inv_major_status = 
                 gaa_release_buffer_contents(&inv_minor_status,
			                     (*cred)->mech_spec_cred);
           inv_major_status = gaa_release_buffer(&inv_minor_status,
                                &((*cred)->mech_spec_cred));
       }

       if ((*cred)->next!= NULL) 
       inv_major_status = gaa_release_authr_cred(&inv_minor_status,
			                         &((*cred)->next));
       
     free(*cred);

    return GAA_SUCCESS;

} /* gaa_release_authr_cred */

/**********************************************************************
Function:   gaa_release_attributes()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_attributes(uint32             *minor_status,
                       gaa_attributes_ptr *attributes)
{

gaa_attributes_ptr  *cred = attributes;
uint32               inv_minor_status = 0, inv_major_status = 0;


#ifdef DEBUG
fprintf(stderr, "\ngaa_release_attributes:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_ATTRIBUTES) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

        if ((*cred)->mech_type != NULL) free((*cred)->mech_type);
        if ((*cred)->type      != NULL) free((*cred)->type);
        if ((*cred)->value     != NULL) free((*cred)->value);

    
        if ((*cred)->conditions!= NULL) 
	inv_major_status = gaa_release_cond_bindings(&inv_minor_status,
			      &((*cred)->conditions));

       if ((*cred)->mech_spec_cred!= NULL) 
       {
           inv_major_status = 
					gaa_release_buffer_contents(&inv_minor_status,
			           (*cred)->mech_spec_cred);
           inv_major_status =gaa_release_buffer(&inv_minor_status,
                       &((*cred)->mech_spec_cred));
       }

       if ((*cred)->next!= NULL) 
       inv_major_status = gaa_release_attributes(&inv_minor_status,
			                         &((*cred)->next));

     free(*cred);

  return GAA_SUCCESS;

} /* gaa_rlease_attributes */

/**********************************************************************
Function:   gaa_rlease_uneval_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_uneval_cred(uint32              *minor_status,
                        gaa_uneval_cred_ptr *uneval_cred)

{
  gaa_uneval_cred_ptr  *cred = uneval_cred;
  uint32                inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_uneval_cred:\n");
#endif /* DEBUG */


	if (*cred == NULL || *cred == GAA_NO_UNEVAL_CRED) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       
        if ((*cred)->grantor != NULL) 
     	inv_major_status = gaa_release_principals(&inv_minor_status,
			      &((*cred)->grantor));
       

	if ((*cred)->grantee != NULL) 
	inv_major_status = gaa_release_principals(&inv_minor_status,
			      &((*cred)->grantee));


        if ((*cred)->mech_spec_cred!= NULL) 
        {
            inv_major_status = 
                gaa_release_buffer_contents(&inv_minor_status,
			                     (*cred)->mech_spec_cred);
            inv_major_status = gaa_release_buffer(&inv_minor_status,
                                &((*cred)->mech_spec_cred));
        }

       if ((*cred)->next!= NULL) 
       inv_major_status = gaa_release_uneval_cred(&inv_minor_status,
			                          &((*cred)->next));

	free(*cred);

    return GAA_SUCCESS;

} /* gaa_rlease_unevaluated_cred */

/**********************************************************************
Function:   gaa_rlease_principals()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_principals(uint32             *minor_status,
                       gaa_principals_ptr *principals)
{

gaa_principals_ptr  *cred = principals;
uint32               inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_principals:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_PRINCIPALS) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */


       if ((*cred)->rights != NULL) 
       inv_major_status = gaa_release_rights(&inv_minor_status,
			      &((*cred)->rights));


       if ((*cred)->next != NULL) 
       inv_major_status = gaa_release_principals(&inv_minor_status,
			      &((*cred)->next));
    
       if ((*cred)->type      != NULL) free((*cred)->type);
       if ((*cred)->authority != NULL) free((*cred)->authority);
       if ((*cred)->value     != NULL) free((*cred)->value);
       
    free(*cred);

  return GAA_SUCCESS;

} /* gaa_rlease_principals */

/**********************************************************************
Function:   gaa_rlease_rights()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_rights(uint32         *minor_status,
                   gaa_rights_ptr *rights)
{

gaa_rights_ptr  *cred = rights;
uint32           inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_rights:\n");
#endif /* DEBUG */


	if (*cred == NULL || *cred == GAA_NO_RIGHTS) 
	return GAA_SUCCESS;

#ifdef DEBUG
fprintf(stderr, "rights:%p:ref:%d\n",*cred,(*cred)->reference_count);
#endif /* DEBUG */

    (*cred)->reference_count--;
    if ((*cred)->reference_count > 0) {
        *rights = NULL;
        return GAA_SUCCESS;
    }

	/* ignore errors to allow for incomplete context handles */

       
       if ((*cred)->cond_bindings != NULL)
       inv_major_status = gaa_release_cond_bindings(&inv_minor_status,
			      &((*cred)->cond_bindings));
    

       if ((*cred)->next != NULL)
       inv_major_status = gaa_release_rights(&inv_minor_status,
			      &((*cred)->next));
	
	if ((*cred)->type      != NULL) free((*cred)->type);
	if ((*cred)->authority != NULL) free((*cred)->authority);
	if ((*cred)->value     != NULL) free((*cred)->value);

       
    free(*cred);
    *rights = NULL;

  return GAA_SUCCESS;

} /* gaa_rlease_rights */

/**********************************************************************
Function:   gaa_rlease_cond_bindings()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_cond_bindings(uint32                 *minor_status,
                          gaa_cond_bindings_ptr  *cond_bind)
{
  gaa_cond_bindings_ptr  *cred = cond_bind;
  uint32                  inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_cond_bindings:\n");
#endif /* DEBUG */


	if (*cred == NULL || *cred == GAA_NO_COND_BINDINGS) 
	return GAA_SUCCESS;

#ifdef DEBUG
fprintf(stderr, "cond:%p:ref:%d\n",*cred,(*cred)->reference_count);
#endif /* DEBUG */

	(*cred)->reference_count--;
	if ((*cred)->reference_count > 0) {
	    *cond_bind = NULL;
	    return GAA_SUCCESS;
    }

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->condition != NULL)
       inv_major_status = gaa_release_conditions(&inv_minor_status,
			                         &((*cred)->condition));

       if ((*cred)->next != NULL) 
       inv_major_status = gaa_release_cond_bindings(&inv_minor_status,
			                            &((*cred)->next));
       
    free(*cred);
	*cond_bind = NULL;

  return GAA_SUCCESS;

} 

/**********************************************************************
Function:   gaa_rlease_conditions()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_conditions(uint32             *minor_status,
                       gaa_conditions_ptr *cond)
{
  gaa_conditions_ptr  *cred = cond;
  uint32               inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_conditions:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_CONDITIONS) 
	return GAA_SUCCESS;

#ifdef DEBUG
fprintf(stderr, "conditions:%p:ref:%d\n",*cred,(*cred)->reference_count);
#endif /* DEBUG */

    (*cred)->reference_count--;
    if ((*cred)->reference_count > 0) {
        *cond = NULL;
        return GAA_SUCCESS;
    }
	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->next != NULL) 
       inv_major_status = gaa_release_conditions(&inv_minor_status,
			      &((*cred)->next));
       
	if ((*cred)->type      != NULL) free((*cred)->type);
	if ((*cred)->authority != NULL) free((*cred)->authority);
	if ((*cred)->value     != NULL) free((*cred)->value);

    free(*cred);

  return GAA_SUCCESS;

} 
/**********************************************************************
Function:   gaa_rlease_answer()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_answer(uint32         *minor_status,
                   gaa_answer_ptr *answer)
{
  gaa_answer_ptr  *cred = answer;
  uint32           inv_minor_status = 0, inv_major_status = 0;


#ifdef DEBUG
fprintf(stderr, "\ngaa_release_answer:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_ANSWER) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->rights!= NULL) 
       inv_major_status = gaa_release_rights(&inv_minor_status,
			                     &((*cred)->rights));
       
    if ((*cred)->valid_time != NULL) free((*cred)->valid_time);
    free(*cred);

  return GAA_SUCCESS;

} /* gaa_rlease_answer */


/**********************************************************************
Function:   gaa_rlease_principals()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

gaa_error_code 
gaa_release_sec_attrb(uint32             *minor_status,
                      gaa_sec_attrb_ptr   *attributes)
{

gaa_sec_attrb_ptr  *cred = attributes;
uint32              inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_release_sec_attrb:\n");
#endif /* DEBUG */

	if (*cred == NULL || *cred == GAA_NO_SEC_ATTRB) 
	return GAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->next != NULL) 
       inv_major_status = gaa_release_sec_attrb(&inv_minor_status,
			      &((*cred)->next));
    
	if ((*cred)->type      != NULL) free((*cred)->type);
	if ((*cred)->authority != NULL) free((*cred)->authority);
	if ((*cred)->value     != NULL) free((*cred)->value);

    free(*cred);

  return GAA_SUCCESS;

} 

/**********************************************************************/
