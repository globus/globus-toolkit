/* library/globus_gaa.h.  Generated automatically by configure.  */
/**********************************************************************
 globus_gaa.h:

Description:
	This header file used internally by the gaa routines
**********************************************************************/
#ifndef _GAA_API_H
#define _GAA_API_H_

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
                                                             
#define GAA_NO_OPTIONS            ((gaa_options_ptr)0) 
#define GAA_NO_BUFFER             ((gaa_buffer_ptr)0)
#define GAA_EMPTY_BUFFER          {0, NULL}
#define GAA_NO_DATA               ((gaa_data_ptr) 0)

#define GAA_NO_SEC_CONTEXT        ((gaa_sec_context_ptr)0)
#define GAA_SEC_ATTRBTS_UNBOUND   ((gaa_sec_attribute_list_ptr)0)
  
#define GAA_NO_PRINCIPALS         ((gaa_principals_ptr)0) 
#define GAA_NO_RIGHTS             ((gaa_rights_ptr) 0)
#define GAA_NO_CONDITIONS         ((gaa_conditions_ptr)0) 
#define GAA_NO_COND_BINDINGS      ((gaa_cond_bindings_ptr)0) 
#define GAA_NO_UNEVAL_CRED        ((gaa_uneval_cred_ptr)0) 
#define GAA_NO_ANSWER             ((gaa_answer_ptr)0) 
#define GAA_NO_SEC_ATTRB          ((gaa_sec_attrb_ptr)0) 

#define GAA_NO_IDENTITY_CRED      ((gaa_identity_cred_ptr)0)
#define GAA_NO_AUTHORIZATION_CRED ((gaa_authr_cred_ptr)0)
#define GAA_NO_ATTRIBUTES         ((gaa_attributes_ptr)0)

#define TRUE          1
#define FALSE         0

#define GAA_NUM_ACCESS_RIGHTS     32
#define MAX_COND_LENGTH           200

/* Time-related conditions */
 
#define COND_DAY       "cond_day"
#define COND_TIME      "cond_time"
#define HOUR_SCALE_24  "hr_scale_24"


#define GAA_ANYBODY               "access_id_ANYBODY"
#define GAA_USER                  "access_id_USER"
#define GAA_GROUP                 "access_id_GROUP"
#define GAA_HOST                  "access_id_HOST"
#define GAA_CA                    "access_id_CA"
#define GAA_APPLICATION           "access_id_APPLICATION"
 
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

#define out_of_memory() gaa_gl__fout_of_memory(__FILE__, __LINE__); 

/************************* GAA API data types ****************************/


typedef enum {

 GAA_MAYBE   = -1,  /* (indicating a need for additional checks) is returned 
                        if there are some unevaluated conditions and additional 
                        application-specific checks are needed, or continuous
                        evaluation is required. */

 GAA_YES     = 0, /* (indicating authorization) is returned if all requested 
                             operations are authorized. */
 GAA_SUCCESS = 0,

 GAA_NO  = 1,  /* (indicating denial of authorization) is returned if at
                   least one operation is not authorized. */
 GAA_FAILURE,
 GAA_NO_POLICY,
 GAA_RETRIEVE_ERROR                       
} gaa_error_code;


typedef	unsigned int  uint32;


/* Define the implementation-dependent types */
 
typedef struct gaa_data_struct  gaa_data, 
                               *gaa_data_ptr;
struct gaa_data_struct { 
 char   *str;    
 char   *error_str;
 uint32  error_code;  
};

             
typedef struct gaa_buffer_struct  gaa_buffer, 
                                 *gaa_buffer_ptr;
struct gaa_buffer_struct {
   size_t     length;
   void      *value;
};
  
typedef struct gaa_options_struct  gaa_options, 
                                  *gaa_options_ptr;
  
struct gaa_options_struct {
   size_t     length;
   char      *value;
};

                              
typedef struct gaa_principals_struct  gaa_principals, 
                                     *gaa_principals_ptr,
                                      gaa_policy,
                                     *gaa_policy_ptr;

typedef struct gaa_rights_struct      gaa_rights, 
                                     *gaa_rights_ptr;


typedef struct gaa_cond_bindings_struct gaa_cond_bindings, 
                                        *gaa_cond_bindings_ptr;


typedef struct gaa_conditions_struct  gaa_conditions, 
                                     *gaa_conditions_ptr;



struct gaa_principals_struct {
   char*            type;
   char*            authority;
   char*            value;
   gaa_rights_ptr      rights;
   gaa_principals_ptr  next;
};


struct gaa_rights_struct {
   char*               type;
   char*               authority;
   char*               value;
   gaa_cond_bindings_ptr  cond_bindings;
   gaa_rights_ptr         next;
   int    reference_count;
};


struct gaa_cond_bindings_struct {
   gaa_conditions_ptr     condition;
   gaa_cond_bindings_ptr  next;
   int  reference_count;
};


struct gaa_conditions_struct {
   char*            type;
   char*            authority;
   char*            value;
   uint32              status;
   gaa_conditions_ptr  next;
   int  reference_count;
};




typedef struct gaa_sec_attrb_struct  gaa_sec_attrb,
                                    *gaa_sec_attrb_ptr;
struct gaa_sec_attrb_struct {
   char*                         type;
   char*                         authority;
   char*                         value;
   gaa_sec_attrb_ptr  next;
};


/******************* GAA API Security Context Structures *******************/

/*
  The gaa_sec_context_struct stores information relevant to access control 
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
      GAA_IDENTITY        ,
      GAA_GROUP_MEMB      ,
      GAA_GROUP_NON_MEMB  ,
      GAA_AUTHORIZED      ,
      GAA_MISCELLANEOUS     
} gaa_cred_type;



typedef struct gaa_sec_context_struct  gaa_sec_context, 
                                      *gaa_sec_context_ptr;

typedef struct gaa_identity_cred_struct  gaa_identity_cred,
                                        *gaa_identity_cred_ptr;

typedef struct gaa_authr_cred_struct  gaa_authr_cred, 
                                     *gaa_authr_cred_ptr;

typedef struct gaa_attributes_struct  gaa_attributes,
                                     *gaa_attributes_ptr;

typedef struct gaa_uneval_cred_struct   gaa_uneval_cred,
                                       *gaa_uneval_cred_ptr;


struct gaa_sec_context_struct {
   gaa_identity_cred_ptr    identity_cred;
   gaa_authr_cred_ptr       authr_cred;
   gaa_identity_cred_ptr    group_membership;
   gaa_identity_cred_ptr    group_non_membership;
   gaa_attributes_ptr       attributes;
   gaa_uneval_cred_ptr      unevl_cred; 
   gaa_buffer_ptr           connection_state; 
 
   void  
   (*condition_evaluation)(gaa_sec_context_ptr, gaa_options_ptr, 
                           gaa_conditions_ptr, ...);
                 
   void 
   (*pull_cred)(gaa_sec_context_ptr, ...);

   void 
   (*cred_evaluate)(gaa_sec_context_ptr, ...);
 };



struct gaa_identity_cred_struct {
   gaa_principals_ptr    principal;
   gaa_conditions_ptr    conditions; 
   gaa_buffer_ptr        mech_spec_cred; 
   gaa_identity_cred_ptr next;
};


struct gaa_authr_cred_struct{
   gaa_principals_ptr   grantor;
   gaa_principals_ptr   grantee;
   gaa_buffer           objects;
   gaa_rights_ptr       access_rights;
   gaa_buffer_ptr       mech_spec_cred;  
   gaa_authr_cred_ptr   next;
};


struct gaa_attributes_struct {
   char*                mech_type;
   char*                type;
   char*                value;
   gaa_cond_bindings_ptr   conditions; 
   gaa_buffer_ptr          mech_spec_cred; 
   gaa_attributes_ptr      next;
};


struct gaa_uneval_cred_struct {
   gaa_cred_type             cred_type;
   gaa_principals_ptr        grantor;
   gaa_principals_ptr        grantee;
   gaa_buffer_ptr            mech_spec_cred;  
   void (*cred_verification )(gaa_sec_context_ptr, va_list ap); 
   gaa_uneval_cred_ptr  next;
};



/********************** GAA API answer data structures *******************/


typedef struct gaa_time_period_struct  gaa_time_period,
                                      *gaa_time_period_ptr;
struct gaa_time_period_struct{
   time_t    start_time; /* NULL for unconstrained start time */
   time_t    end_time;   /* NULL for unconstrained end time */
};



/* gaa_answer_struct contains:

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

typedef struct gaa_answer_struct gaa_answer, *gaa_answer_ptr;

struct gaa_answer_struct{
   gaa_time_period_ptr valid_time; 
   gaa_rights_ptr      rights;
};



/**********************************************************************
                               Function prototypes
**********************************************************************/
      
/* The gaa_get_object_policy_infofunction is called to obtain security policy 
   information associated with the protected object.*/

gaa_error_code  
gaa_get_object_policy_info(uint32*         minor_status,        /* OUT */
                           gaa_data_ptr    object,              /* IN  */
                           gaa_data_ptr    policy_db,            /* IN  */
                           gaa_policy_ptr(*retrieve)(uint32*  minor_status, /* OUT */
                                                     gaa_data_ptr  object,  /* IN  */
                                                     gaa_data_ptr  policy_db, ... ),  /* IN  */
                           gaa_policy_ptr* policy   /* OUT */, ...);


/* The gaa_check_authorization function tells the application
   server whether the requested operation or a set of operations is authorized, 
   or if additional checks are required. */
                     
gaa_error_code
gaa_check_authorization 
       (uint32              *minor_status,        /* OUT    */
        gaa_sec_context_ptr  sec_context,         /* IN&OUT */
        gaa_policy_ptr       policy_handle,       /* IN     */
        gaa_rights_ptr       check_access_rights, /* IN     */
        gaa_options_ptr      gaa_options,         /* IN, OPTIONAL */
        gaa_answer_ptr      *detailed_answer      /* OUT    */
       );   


/* The gaa_inquire_policy_info function allows application to discover 
access control policies associated with the target object.  */
                                                           
gaa_error_code
gaa_inquire_policy_info
       (uint32               *minor_status,  /* OUT    */
        gaa_sec_context_ptr   sec_context,   /* IN&OUT */
        gaa_policy_ptr        policy_handle, /* IN     */
        gaa_rights_ptr       *rights         /* OUT    */
      );   
 


/************************* Allocation functions *******************************/

gaa_error_code  
gaa_allocate_buffer (gaa_buffer_ptr*  buffer_addr   /* IN  */);

gaa_error_code
gaa_allocate_principals (gaa_principals_ptr* buffer_addr);

gaa_error_code
gaa_allocate_conditions (gaa_conditions_ptr* buffer_addr);

gaa_error_code
gaa_allocate_rights (gaa_rights_ptr* buffer_addr   /* IN  */);

gaa_error_code
gaa_allocate_cond_bindings (gaa_cond_bindings_ptr* buffer_addr   /* IN  */);

gaa_error_code
gaa_allocate_sec_attb_list (gaa_sec_attrb_ptr* buffer_addr   /* IN  */);

gaa_error_code  
gaa_allocate_sec_context (gaa_sec_context_ptr*  buffer_addr);

gaa_error_code
gaa_allocate_identity_cred(gaa_identity_cred_ptr*  buffer_addr  /* IN&OUT */);

gaa_error_code
gaa_allocate_answer(gaa_answer_ptr *ptr);

gaa_sec_context_ptr
gaa_globus_allocate_sec_context(char *signer);

gaa_rights_ptr
gaa_globus_allocate_rights();


/************************* Release functions *******************************/

gaa_error_code 
gaa_release_buffer (uint32  *minor_status,
                             gaa_buffer_ptr * buffer);

gaa_error_code 
gaa_release_buffer_contents (uint32  *minor_status,
                             gaa_buffer_ptr  buffer);

gaa_error_code 
gaa_release_sec_context(uint32             *minor_status,
                       gaa_sec_context_ptr *sec_context);

gaa_error_code 
gaa_release_identity_cred (uint32                *minor_status,
                           gaa_identity_cred_ptr *identity_cred);

gaa_error_code 
gaa_release_authr_cred(uint32             *minor_status,
                       gaa_authr_cred_ptr *authr_cred);

gaa_error_code 
gaa_release_attributes(uint32             *minor_status,
                       gaa_attributes_ptr *attributes);

gaa_error_code 
gaa_release_options(uint32          *minor_status,
                    gaa_options_ptr  buffer);
gaa_error_code 
gaa_release_uneval_cred(uint32              *minor_status,
                        gaa_uneval_cred_ptr *uneval_cred);

gaa_error_code 
gaa_release_principals(uint32             *minor_status,
                       gaa_principals_ptr *principals);

gaa_error_code 
gaa_release_rights(uint32         *minor_status,
                   gaa_rights_ptr *rights);

gaa_error_code 
gaa_release_cond_bindings(uint32                 *minor_status,
                          gaa_cond_bindings_ptr  *cond_bind);

gaa_error_code 
gaa_release_conditions(uint32              *minor_status,
                       gaa_conditions_ptr  *conditions);

gaa_error_code  
gaa_release_answer(uint32         *minor_status,
                   gaa_answer_ptr *answer);

gaa_error_code
gaa_release_data(uint32           *minor_status,
                 gaa_data_ptr      buffer);

gaa_error_code 
gaa_release_sec_attrb(uint32             *minor_status,
                      gaa_sec_attrb_ptr   *attributes);

EXTERN_C_END

#endif /* _GAA_API_H_ */



