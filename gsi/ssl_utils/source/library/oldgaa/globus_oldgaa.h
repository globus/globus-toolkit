/* library/globus_oldgaa.h.  Generated automatically by configure.  */
/**********************************************************************
 globus_oldgaa.h:

Description:
	This header file used internally by the oldgaa routines
**********************************************************************/
#ifndef _OLDGAA_API_H
#define _OLDGAA_API_H_

#ifndef HAVE_SYS_TIME_H
#define HAVE_SYS_TIME_H 1
#endif

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN


/**********************************************************************
                             Include header files
**********************************************************************/
 
#ifndef NO_GLOBUS_CONFIG_H
#include <globus_config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>    /* for va_list */
#include <sys/stat.h>  /* for time_t solaris ? */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>  /* for time_t on linux etc. */
#endif

/**********************************************************************
                               Define constants
**********************************************************************/
  
/* Error number returned if an argument is invalid */

#define ERRNO_INVALID_ARGUMENT		EINVAL
                                                             
#define OLDGAA_NO_OPTIONS            ((oldgaa_options_ptr)0) 
#define OLDGAA_NO_BUFFER             ((oldgaa_buffer_ptr)0)
#define OLDGAA_EMPTY_BUFFER          {0, NULL}
#define OLDGAA_NO_DATA               ((oldgaa_data_ptr) 0)

#define OLDGAA_NO_SEC_CONTEXT        ((oldgaa_sec_context_ptr)0)
#define OLDGAA_SEC_ATTRBTS_UNBOUND   ((oldgaa_sec_attribute_list_ptr)0)
  
#define OLDGAA_NO_PRINCIPALS         ((oldgaa_principals_ptr)0) 
#define OLDGAA_NO_RIGHTS             ((oldgaa_rights_ptr) 0)
#define OLDGAA_NO_CONDITIONS         ((oldgaa_conditions_ptr)0) 
#define OLDGAA_NO_COND_BINDINGS      ((oldgaa_cond_bindings_ptr)0) 
#define OLDGAA_NO_UNEVAL_CRED        ((oldgaa_uneval_cred_ptr)0) 
#define OLDGAA_NO_ANSWER             ((oldgaa_answer_ptr)0) 
#define OLDGAA_NO_SEC_ATTRB          ((oldgaa_sec_attrb_ptr)0) 

#define OLDGAA_NO_IDENTITY_CRED      ((oldgaa_identity_cred_ptr)0)
#define OLDGAA_NO_AUTHORIZATION_CRED ((oldgaa_authr_cred_ptr)0)
#define OLDGAA_NO_ATTRIBUTES         ((oldgaa_attributes_ptr)0)

#define TRUE          1
#define FALSE         0

#define OLDGAA_NUM_ACCESS_RIGHTS     32
#define MAX_COND_LENGTH           200

/* Time-related conditions */
 
#define COND_DAY       "cond_day"
#define COND_TIME      "cond_time"
#define HOUR_SCALE_24  "hr_scale_24"


#define OLDGAA_ANYBODY               "access_id_ANYBODY"
#define OLDGAA_USER                  "access_id_USER"
#define OLDGAA_GROUP                 "access_id_GROUP"
#define OLDGAA_HOST                  "access_id_HOST"
#define OLDGAA_CA                    "access_id_CA"
#define OLDGAA_APPLICATION           "access_id_APPLICATION"
 
/* Miscellaneous conditions */

#define COND_SEC_MECH             "cond_sec_mech"
#define COND_BANNED_SUBJECTS      "cond_banned_subjects"

/* NUL is the string termination character */
#define NUL				'\0'


/* Globus-specific definitions */
    
#define AUTH_GLOBUS         "globus"
#define COND_SUBJECTS       "cond_subjects"
#define GLOBUS_RIGHTS_VALUE "CA:sign"



/* Condition flags:
  
   Each condition is marked as evaluated or not evaluated, if evaluated 
   marked as met, not met or further evaluation or enforcement is required.
   This tells application which policies must be enforced.*/

#define	COND_FLG_EVALUATED    0x01  /* condition has been evaluated */
#define	COND_FLG_MET	      0x10  /* condition has been met       */
#define	COND_FLG_ENFORCE      0x100 /* condition has to be enforced */

#define out_of_memory() oldgaa_gl__fout_of_memory(__FILE__, __LINE__); 

/************************* OLDGAA API data types ****************************/


typedef enum {

 OLDGAA_MAYBE   = -1,  /* (indicating a need for additional checks) is returned 
                        if there are some unevaluated conditions and additional 
                        application-specific checks are needed, or continuous
                        evaluation is required. */

 OLDGAA_YES     = 0, /* (indicating authorization) is returned if all requested 
                             operations are authorized. */
 OLDGAA_SUCCESS = 0,

 OLDGAA_NO  = 1,  /* (indicating denial of authorization) is returned if at
                   least one operation is not authorized. */
 OLDGAA_FAILURE,
 OLDGAA_NO_POLICY,
 OLDGAA_RETRIEVE_ERROR                       
} oldgaa_error_code;


typedef	unsigned int  uint32;


/* Define the implementation-dependent types */
 
typedef struct oldgaa_data_struct  oldgaa_data, 
                               *oldgaa_data_ptr;
struct oldgaa_data_struct { 
 char   *str;    
 char   *error_str;
 uint32  error_code;  
};

             
typedef struct oldgaa_buffer_struct  oldgaa_buffer, 
                                 *oldgaa_buffer_ptr;
struct oldgaa_buffer_struct {
   size_t     length;
   void      *value;
};
  
typedef struct oldgaa_options_struct  oldgaa_options, 
                                  *oldgaa_options_ptr;
  
struct oldgaa_options_struct {
   size_t     length;
   char      *value;
};

                              
typedef struct oldgaa_principals_struct  oldgaa_principals, 
                                     *oldgaa_principals_ptr,
                                      oldgaa_policy,
                                     *oldgaa_policy_ptr;

typedef struct oldgaa_rights_struct      oldgaa_rights, 
                                     *oldgaa_rights_ptr;


typedef struct oldgaa_cond_bindings_struct oldgaa_cond_bindings, 
                                        *oldgaa_cond_bindings_ptr;


typedef struct oldgaa_conditions_struct  oldgaa_conditions, 
                                     *oldgaa_conditions_ptr;



struct oldgaa_principals_struct {
   char*            type;
   char*            authority;
   char*            value;
   oldgaa_rights_ptr      rights;
   oldgaa_principals_ptr  next;
};


struct oldgaa_rights_struct {
   char*               type;
   char*               authority;
   char*               value;
   oldgaa_cond_bindings_ptr  cond_bindings;
   oldgaa_rights_ptr         next;
   int    reference_count;
};


struct oldgaa_cond_bindings_struct {
   oldgaa_conditions_ptr     condition;
   oldgaa_cond_bindings_ptr  next;
   int  reference_count;
};


struct oldgaa_conditions_struct {
   char*            type;
   char*            authority;
   char*            value;
   uint32              status;
   oldgaa_conditions_ptr  next;
   int  reference_count;
};




typedef struct oldgaa_sec_attrb_struct  oldgaa_sec_attrb,
                                    *oldgaa_sec_attrb_ptr;
struct oldgaa_sec_attrb_struct {
   char*                         type;
   char*                         authority;
   char*                         value;
   oldgaa_sec_attrb_ptr  next;
};


/******************* OLDGAA API Security Context Structures *******************/

/*
  The oldgaa_sec_context_struct stores information relevant to access control 
  policy, e.g. authentication and authorization credentials presented or used 
  by the peer entity (usually the client of the request), connection state 
  information.

  The context consists of:

  1) Identity

  Verified authentication information, such as principal name for a 
  particular security mechanism.

  2) Authorized credentials
   This type of credentials is used to hold delegated credentials and
   capabilities.

  3) Group membership 
   This type of credentials specifies that the grantee is a member of 
   only the listed groups.

  4) Group non-membership
   This type of credentials specifies that the grantee is NOT a member 
   of the listed groups.

  5) Attributes
   This type of credentials contains  miscellaneous attributes 
   attached to the grantee, e.g. age of the grantee, grantee's security 
   clearance.

  6) Unevaluated Credentials 
   Evaluation of the acquired credentials can be deferred till the 
   credential is needed to perform the operation.

  7) Evaluation and Retrieval Functions for Upcalls
  These functions are called to evaluate application-specific conditions,
  to request additional credentials and verify them. 
  The GSS API is an example of how this can be filled in.

  8) Connection State Information 
  Contains a mechanism-specific representation of per-connection 
  context, some of the data stored here include keyblocks, addresses. */

typedef enum  {
      OLDGAA_IDENTITY        ,
      OLDGAA_GROUP_MEMB      ,
      OLDGAA_GROUP_NON_MEMB  ,
      OLDGAA_AUTHORIZED      ,
      OLDGAA_MISCELLANEOUS     
} oldgaa_cred_type;



typedef struct oldgaa_sec_context_struct  oldgaa_sec_context, 
                                      *oldgaa_sec_context_ptr;

typedef struct oldgaa_identity_cred_struct  oldgaa_identity_cred,
                                        *oldgaa_identity_cred_ptr;

typedef struct oldgaa_authr_cred_struct  oldgaa_authr_cred, 
                                     *oldgaa_authr_cred_ptr;

typedef struct oldgaa_attributes_struct  oldgaa_attributes,
                                     *oldgaa_attributes_ptr;

typedef struct oldgaa_uneval_cred_struct   oldgaa_uneval_cred,
                                       *oldgaa_uneval_cred_ptr;


struct oldgaa_sec_context_struct {
   oldgaa_identity_cred_ptr    identity_cred;
   oldgaa_authr_cred_ptr       authr_cred;
   oldgaa_identity_cred_ptr    group_membership;
   oldgaa_identity_cred_ptr    group_non_membership;
   oldgaa_attributes_ptr       attributes;
   oldgaa_uneval_cred_ptr      unevl_cred; 
   oldgaa_buffer_ptr           connection_state; 
 
   void  
   (*condition_evaluation)(oldgaa_sec_context_ptr, oldgaa_options_ptr, 
                           oldgaa_conditions_ptr, ...);
                 
   void 
   (*pull_cred)(oldgaa_sec_context_ptr, ...);

   void 
   (*cred_evaluate)(oldgaa_sec_context_ptr, ...);
 };



struct oldgaa_identity_cred_struct {
   oldgaa_principals_ptr    principal;
   oldgaa_conditions_ptr    conditions; 
   oldgaa_buffer_ptr        mech_spec_cred; 
   oldgaa_identity_cred_ptr next;
};


struct oldgaa_authr_cred_struct{
   oldgaa_principals_ptr   grantor;
   oldgaa_principals_ptr   grantee;
   oldgaa_buffer           objects;
   oldgaa_rights_ptr       access_rights;
   oldgaa_buffer_ptr       mech_spec_cred;  
   oldgaa_authr_cred_ptr   next;
};


struct oldgaa_attributes_struct {
   char*                mech_type;
   char*                type;
   char*                value;
   oldgaa_cond_bindings_ptr   conditions; 
   oldgaa_buffer_ptr          mech_spec_cred; 
   oldgaa_attributes_ptr      next;
};


struct oldgaa_uneval_cred_struct {
   oldgaa_cred_type             cred_type;
   oldgaa_principals_ptr        grantor;
   oldgaa_principals_ptr        grantee;
   oldgaa_buffer_ptr            mech_spec_cred;  
   void (*cred_verification )(oldgaa_sec_context_ptr, va_list ap); 
   oldgaa_uneval_cred_ptr  next;
};



/********************** OLDGAA API answer data structures *******************/


typedef struct oldgaa_time_period_struct  oldgaa_time_period,
                                      *oldgaa_time_period_ptr;
struct oldgaa_time_period_struct{
   time_t    start_time; /* NULL for unconstrained start time */
   time_t    end_time;   /* NULL for unconstrained end time */
};



/* oldgaa_answer_struct contains:

   o  valid_time:  
      Authorization valid time period.
      The time period during which the authorization is granted is 
      returned as condition to be checked by the application. 
      Expiration time is calculated based on time-related restrictions
      expressed by the security attributes and restrictions in the 
      authentication, authorization and delegated credentials.  

   o rights:
 
      The requested operations are returned marked as granted or denied
      along with a list of corresponding conditions, if any. 
     

  */

typedef struct oldgaa_answer_struct oldgaa_answer, *oldgaa_answer_ptr;

struct oldgaa_answer_struct{
   oldgaa_time_period_ptr valid_time; 
   oldgaa_rights_ptr      rights;
};



/**********************************************************************
                               Function prototypes
**********************************************************************/
      
/* The oldgaa_get_object_policy_infofunction is called to obtain security policy 
   information associated with the protected object.*/

oldgaa_error_code  
oldgaa_get_object_policy_info(uint32*         minor_status,        /* OUT */
                           oldgaa_data_ptr    object,              /* IN  */
                           oldgaa_data_ptr    policy_db,            /* IN  */
                           oldgaa_policy_ptr(*retrieve)(uint32*  minor_status, /* OUT */
                                                     oldgaa_data_ptr  object,  /* IN  */
                                                     oldgaa_data_ptr  policy_db, ... ),  /* IN  */
                           oldgaa_policy_ptr* policy   /* OUT */, ...);


/* The oldgaa_check_authorization function tells the application
   server whether the requested operation or a set of operations is authorized, 
   or if additional checks are required. */
                     
oldgaa_error_code
oldgaa_check_authorization 
       (uint32              *minor_status,        /* OUT    */
        oldgaa_sec_context_ptr  sec_context,         /* IN&OUT */
        oldgaa_policy_ptr       policy_handle,       /* IN     */
        oldgaa_rights_ptr       check_access_rights, /* IN     */
        oldgaa_options_ptr      oldgaa_options,         /* IN, OPTIONAL */
        oldgaa_answer_ptr      *detailed_answer      /* OUT    */
       );   


/* The oldgaa_inquire_policy_info function allows application to discover 
access control policies associated with the target object.  */
                                                           
oldgaa_error_code
oldgaa_inquire_policy_info
       (uint32               *minor_status,  /* OUT    */
        oldgaa_sec_context_ptr   sec_context,   /* IN&OUT */
        oldgaa_policy_ptr        policy_handle, /* IN     */
        oldgaa_rights_ptr       *rights         /* OUT    */
      );   
 


/************************* Allocation functions *******************************/

oldgaa_error_code  
oldgaa_allocate_buffer (oldgaa_buffer_ptr*  buffer_addr   /* IN  */);

oldgaa_error_code
oldgaa_allocate_principals (oldgaa_principals_ptr* buffer_addr);

oldgaa_error_code
oldgaa_allocate_conditions (oldgaa_conditions_ptr* buffer_addr);

oldgaa_error_code
oldgaa_allocate_rights (oldgaa_rights_ptr* buffer_addr   /* IN  */);

oldgaa_error_code
oldgaa_allocate_cond_bindings (oldgaa_cond_bindings_ptr* buffer_addr   /* IN  */);

oldgaa_error_code
oldgaa_allocate_sec_attb_list (oldgaa_sec_attrb_ptr* buffer_addr   /* IN  */);

oldgaa_error_code  
oldgaa_allocate_sec_context (oldgaa_sec_context_ptr*  buffer_addr);

oldgaa_error_code
oldgaa_allocate_identity_cred(oldgaa_identity_cred_ptr*  buffer_addr  /* IN&OUT */);

oldgaa_error_code
oldgaa_allocate_answer(oldgaa_answer_ptr *ptr);

oldgaa_sec_context_ptr
oldgaa_globus_allocate_sec_context(char *signer);

oldgaa_rights_ptr
oldgaa_globus_allocate_rights();


/************************* Release functions *******************************/

oldgaa_error_code 
oldgaa_release_buffer (uint32  *minor_status,
                             oldgaa_buffer_ptr * buffer);

oldgaa_error_code 
oldgaa_release_buffer_contents (uint32  *minor_status,
                             oldgaa_buffer_ptr  buffer);

oldgaa_error_code 
oldgaa_release_sec_context(uint32             *minor_status,
                       oldgaa_sec_context_ptr *sec_context);

oldgaa_error_code 
oldgaa_release_identity_cred (uint32                *minor_status,
                           oldgaa_identity_cred_ptr *identity_cred);

oldgaa_error_code 
oldgaa_release_authr_cred(uint32             *minor_status,
                       oldgaa_authr_cred_ptr *authr_cred);

oldgaa_error_code 
oldgaa_release_attributes(uint32             *minor_status,
                       oldgaa_attributes_ptr *attributes);

oldgaa_error_code 
oldgaa_release_options(uint32          *minor_status,
                    oldgaa_options_ptr  buffer);
oldgaa_error_code 
oldgaa_release_uneval_cred(uint32              *minor_status,
                        oldgaa_uneval_cred_ptr *uneval_cred);

oldgaa_error_code 
oldgaa_release_principals(uint32             *minor_status,
                       oldgaa_principals_ptr *principals);

oldgaa_error_code 
oldgaa_release_rights(uint32         *minor_status,
                   oldgaa_rights_ptr *rights);

oldgaa_error_code 
oldgaa_release_cond_bindings(uint32                 *minor_status,
                          oldgaa_cond_bindings_ptr  *cond_bind);

oldgaa_error_code 
oldgaa_release_conditions(uint32              *minor_status,
                       oldgaa_conditions_ptr  *conditions);

oldgaa_error_code  
oldgaa_release_answer(uint32         *minor_status,
                   oldgaa_answer_ptr *answer);

oldgaa_error_code
oldgaa_release_data(uint32           *minor_status,
                 oldgaa_data_ptr      buffer);

oldgaa_error_code 
oldgaa_release_sec_attrb(uint32             *minor_status,
                      oldgaa_sec_attrb_ptr   *attributes);

EXTERN_C_END

#endif /* _OLDGAA_API_H_ */



