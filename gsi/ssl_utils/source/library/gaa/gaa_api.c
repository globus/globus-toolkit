
/**********************************************************************
 gaa_api.c:

Description:
	This file defines GAA API functions
**********************************************************************/

/**********************************************************************
                             Include header files
**********************************************************************/

#include "globus_gaa.h" 
#include "gaa_policy_evaluator.h"
#include "gaa_utils.h"

/**********************************************************************
                       Define module specific variables
**********************************************************************/


/******************************************************************************
Function:   gaa_get_object_policy_info
Description:
	The gaa_get_object_policy_info function is called to obtain
security policy information associated with the object. In  the ACL-based
systems, this information represents object ACLs, in the capability-based 
systems, this information may contain a list of authorities allowed to grant 
capabilities. If no security information is attached to the object, then this
function can be ommited.

Parameters:
	
o  Reference to the object to be accessed 

The identifier for the object is from an application-dependent name 
space, it can be represented as unique object identifier, or symbolic 
name local to the application.

o  Pointer to the application-specific authorization database

o  Upcall function for the retrieval of the object authorization information.

   The application maintains authorization information in a form
   understood by the application.  It can be stored in a file,
   database, directory service or in some other way. The upcall 
   function provided for the GAA API retrieves this information.

Returns:

o  Mechanism-specific status code

o  A handle to the sequence of  security attributes which constitute
the security policy associated with the targeted object.

******************************************************************************/

gaa_error_code
gaa_get_object_policy_info(uint32          *minor_status,/* OUT */
                           gaa_data_ptr     object,      /* IN  */
                           gaa_data_ptr     policy_db,   /* IN  */
                           gaa_policy_ptr(*retrieve)(uint32*  minor_status, /* OUT */
                                                     gaa_data_ptr  object,  /* IN  */
                                                     gaa_data_ptr  policy_db, ... ),  /* IN  */
                           gaa_policy_ptr*  policy_handle  /* OUT */,...
                           ) 

{     
 
#ifdef DEBUG
fprintf(stderr,"\ngaa_get_object_policy_info:\n");
#endif /* DEBUG */

 *minor_status = 0;

   /* retrive policy */

 *policy_handle =  retrieve(minor_status, object, policy_db);

  if (*policy_handle == NULL) return GAA_RETRIEVE_ERROR; /* policy retrival error */
     
  return GAA_SUCCESS;
}        
   

/******************************************************************************
Function:   gaa_check_authorization

Description:
The gaa_check_authorization function tells the application
server whether the requested operation or a set of operations is authorized, 
or if additional checks are required.


Parameters:
	
o  A handle to the sequence of security attributes, returned by the
   gaa_get_object_policy_info

o  Principal's security context 

o  Operations for authorization
    It indicates operations to be performed.

o GAA API options structure 
This argument describes the behavior of the GAA API and specifies
how the other arguments should be interpreted.

Returns:

GAA_YES 0  (indicating authorization) is returned if all requested 
      operations are authorized.
 
GAA_NO  1  (indicating denial of authorization) is returned if at least one 
      operation is not authorized.

GAA_MAYBE  -1 (indicating a need for additional checks) is returned 
      if there are some unevaluated conditions and additional 
      application-specific checks are needed, or continuous
      evaluation is required. 

o  Mechanism-specific status code 

o  Detailed answer          

	

******************************************************************************/

                                       
gaa_error_code
gaa_check_authorization (uint32                 *minor_status,     /* OUT         */
                         gaa_sec_context_ptr     sc,               /* IN&OUT      */
                         gaa_policy_ptr          policy_handle,    /* IN          */
                         gaa_rights_ptr          rights,           /* IN,OPTIONAL */
                         gaa_options_ptr         options,          /* IN,OPTIONAL */ 
                         gaa_answer_ptr         *detailed_answer   /* OUT         */
                         )

{
  gaa_policy_ptr   entry  = NULL;
  gaa_error_code   answer = GAA_NO;
 
#ifdef DEBUG
fprintf(stderr, "\ngaa_check_authorization:\n");
fprintf(stderr,"issuer_name   : %s\nrights        : %s %s %s\n\npolicy handle  : %08x\n",
        sc->identity_cred->principal->value,
        rights->type, rights->authority, rights->value,
        policy_handle);
if(options) fprintf(stderr,"subject_name   : %s\n", options->value);
#endif /* DEBUG */

  *minor_status = 0;

 /* find policy associated  with the principal from security context */
 entry = gaa_find_matching_entry(minor_status, 
                                 sc->identity_cred->principal, 
                                 policy_handle);


#ifdef DEBUG
fprintf(stderr, "matching entry : %08x\n", entry);
#endif /* DEBUG */

 /* check requested righs against obtained policy */

   if(entry) 
   {
     gaa_allocate_answer(detailed_answer);

     answer = gaa_check_access_rights(sc, rights, entry->rights,
                                  *detailed_answer, options);
   } 
 return answer;
}


/******************************************************************************
Function: gaa_inquire_policy_info
  
Description: allows application to discover 
access control policies associated with the target object. 
	

Parameters:
	o  A handle to the sequence of security attributes, returned by 
   gaa_get_object_policy_info

o  Principal's security context 

Returns:

	o A list of authorized rights and corresponding conditions, if any, is 
returned.

******************************************************************************/
                                        
gaa_error_code
gaa_inquire_policy_info
       (uint32               *minor_status,  /* OUT    */
        gaa_sec_context_ptr   sc,            /* IN&OUT */
        gaa_policy_ptr        policy_handle, /* IN     */
        gaa_rights_ptr       *rights         /* OUT    */
       )
{
  gaa_policy_ptr entry = NULL;   

#ifdef DEBUG
fprintf(stderr, "\ngaa_inquire_object_policy_info:\n");
#endif /* DEBUG */

 *minor_status = 0;

 /* find policy associated  with the principal from security context */

 entry = gaa_find_matching_entry(minor_status, 
                                 sc->identity_cred->principal, 
                                 policy_handle);

 if(entry) *rights = entry->rights;

 return GAA_SUCCESS;

}

/*********************************************************************/
