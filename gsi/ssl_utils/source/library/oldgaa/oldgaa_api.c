
/**********************************************************************
 oldgaa_api.c:

Description:
	This file defines OLDGAA API functions
**********************************************************************/

/**********************************************************************
                             Include header files
**********************************************************************/

#include "globus_oldgaa.h" 
#include "oldgaa_policy_evaluator.h"
#include "oldgaa_utils.h"

/**********************************************************************
                       Define module specific variables
**********************************************************************/


/******************************************************************************
Function:   oldgaa_get_object_policy_info
Description:
	The oldgaa_get_object_policy_info function is called to obtain
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
   function provided for the OLDGAA API retrieves this information.

Returns:

o  Mechanism-specific status code

o  A handle to the sequence of  security attributes which constitute
the security policy associated with the targeted object.

******************************************************************************/

oldgaa_error_code
oldgaa_get_object_policy_info(uint32          *minor_status,/* OUT */
                           oldgaa_data_ptr     object,      /* IN  */
                           oldgaa_data_ptr     policy_db,   /* IN  */
                           oldgaa_policy_ptr(*retrieve)(uint32*  minor_status, /* OUT */
                                                     oldgaa_data_ptr  object,  /* IN  */
                                                     oldgaa_data_ptr  policy_db, ... ),  /* IN  */
                           oldgaa_policy_ptr*  policy_handle  /* OUT */,...
                           ) 

{     
 
#ifdef DEBUG
fprintf(stderr,"\noldgaa_get_object_policy_info:\n");
#endif /* DEBUG */

 *minor_status = 0;

   /* retrive policy */

 *policy_handle =  retrieve(minor_status, object, policy_db);

  if (*policy_handle == NULL) return OLDGAA_RETRIEVE_ERROR; /* policy retrival error */
     
  return OLDGAA_SUCCESS;
}        
   

/******************************************************************************
Function:   oldgaa_check_authorization

Description:
The oldgaa_check_authorization function tells the application
server whether the requested operation or a set of operations is authorized, 
or if additional checks are required.


Parameters:
	
o  A handle to the sequence of security attributes, returned by the
   oldgaa_get_object_policy_info

o  Principal's security context 

o  Operations for authorization
    It indicates operations to be performed.

o OLDGAA API options structure 
This argument describes the behavior of the OLDGAA API and specifies
how the other arguments should be interpreted.

Returns:

OLDGAA_YES 0  (indicating authorization) is returned if all requested 
      operations are authorized.
 
OLDGAA_NO  1  (indicating denial of authorization) is returned if at least one 
      operation is not authorized.

OLDGAA_MAYBE  -1 (indicating a need for additional checks) is returned 
      if there are some unevaluated conditions and additional 
      application-specific checks are needed, or continuous
      evaluation is required. 

o  Mechanism-specific status code 

o  Detailed answer          

	

******************************************************************************/

                                       
oldgaa_error_code
oldgaa_check_authorization (uint32                 *minor_status,     /* OUT         */
                         oldgaa_sec_context_ptr     sc,               /* IN&OUT      */
                         oldgaa_policy_ptr          policy_handle,    /* IN          */
                         oldgaa_rights_ptr          rights,           /* IN,OPTIONAL */
                         oldgaa_options_ptr         options,          /* IN,OPTIONAL */ 
                         oldgaa_answer_ptr         *detailed_answer   /* OUT         */
                         )

{
  oldgaa_policy_ptr   entry  = NULL;
  oldgaa_error_code   answer = OLDGAA_NO;
 
#ifdef DEBUG
fprintf(stderr, "\noldgaa_check_authorization:\n");
fprintf(stderr,"issuer_name   : %s\nrights        : %s %s %s\n\npolicy handle  : %08x\n",
        sc->identity_cred->principal->value,
        rights->type, rights->authority, rights->value,
        policy_handle);
if(options) fprintf(stderr,"subject_name   : %s\n", options->value);
#endif /* DEBUG */

  *minor_status = 0;

 /* find policy associated  with the principal from security context */
 entry = oldgaa_find_matching_entry(minor_status, 
                                 sc->identity_cred->principal, 
                                 policy_handle);


#ifdef DEBUG
fprintf(stderr, "matching entry : %08x\n", entry);
#endif /* DEBUG */

 /* check requested righs against obtained policy */

   if(entry) 
   {
     oldgaa_allocate_answer(detailed_answer);

     answer = oldgaa_check_access_rights(sc, rights, entry->rights,
                                  *detailed_answer, options);
   } 
 return answer;
}


/******************************************************************************
Function: oldgaa_inquire_policy_info
  
Description: allows application to discover 
access control policies associated with the target object. 
	

Parameters:
	o  A handle to the sequence of security attributes, returned by 
   oldgaa_get_object_policy_info

o  Principal's security context 

Returns:

	o A list of authorized rights and corresponding conditions, if any, is 
returned.

******************************************************************************/
                                        
oldgaa_error_code
oldgaa_inquire_policy_info
       (uint32               *minor_status,  /* OUT    */
        oldgaa_sec_context_ptr   sc,            /* IN&OUT */
        oldgaa_policy_ptr        policy_handle, /* IN     */
        oldgaa_rights_ptr       *rights         /* OUT    */
       )
{
  oldgaa_policy_ptr entry = NULL;   

#ifdef DEBUG
fprintf(stderr, "\noldgaa_inquire_object_policy_info:\n");
#endif /* DEBUG */

 *minor_status = 0;

 /* find policy associated  with the principal from security context */

 entry = oldgaa_find_matching_entry(minor_status, 
                                 sc->identity_cred->principal, 
                                 policy_handle);

 if(entry) *rights = entry->rights;

 return OLDGAA_SUCCESS;

}

/*********************************************************************/
