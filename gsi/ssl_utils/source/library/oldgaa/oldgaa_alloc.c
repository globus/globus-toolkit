/**********************************************************************
 oldgaa_alloc.c:

Description:
	This file used internally by the oldgaa routines
**********************************************************************/

#include "globus_oldgaa.h"


/*****************************************************************************/

oldgaa_error_code  
oldgaa_allocate_buffer (oldgaa_buffer_ptr*  buffer_addr   /* IN  */)
{
  oldgaa_buffer_ptr  buffer;

  buffer = (oldgaa_buffer_ptr) malloc(sizeof(oldgaa_buffer));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->length  = 0; 
       buffer->value   = NULL;    
      *buffer_addr     = buffer;
    
       return OLDGAA_SUCCESS;
}

/*****************************************************************************/

oldgaa_error_code  
oldgaa_allocate_data(oldgaa_data_ptr* buffer_addr /* IN  */)
{
  oldgaa_data_ptr  buffer;

  buffer = (oldgaa_data_ptr) malloc(sizeof(oldgaa_data));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->str         = NULL; 
       buffer->error_str   = NULL;
       buffer->error_code  = 0;

      *buffer_addr = buffer;
    
       return OLDGAA_SUCCESS;
}
/*****************************************************************************/

oldgaa_error_code  
oldgaa_allocate_options (oldgaa_options_ptr*  buffer_addr   /* IN  */)
{
  oldgaa_options_ptr  buffer;

  buffer = (oldgaa_options_ptr) malloc(sizeof(oldgaa_options));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->length  = 0; 
       buffer->value   = NULL;    
      *buffer_addr     = buffer;
    
       return OLDGAA_SUCCESS;
}

/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_principals (oldgaa_principals_ptr* buffer_addr)
{
 oldgaa_principals_ptr list = NULL;

  list = (oldgaa_principals_ptr) malloc(sizeof(oldgaa_principals));
  if (!list) out_of_memory();
    

     /* Initialize and fill in default values */

              
     list->type      = NULL;            
     list->authority = NULL;               
     list->value     = NULL;
     list->rights    = NULL;
     list->next      = NULL;             
    *buffer_addr     = list;

     return OLDGAA_SUCCESS;
}

/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_conditions (oldgaa_conditions_ptr* buffer_addr)
{
 oldgaa_conditions_ptr list = NULL;

  list = (oldgaa_conditions_ptr) malloc(sizeof(oldgaa_conditions));
  if (!list) out_of_memory();
    
     /* Initialize and fill in default values */

     list->type      = NULL;   
     list->authority = NULL;  
     list->value     = NULL;
     list->status    = 0;
     list->next      = NULL;         
     list->reference_count = 0;
    *buffer_addr     = list;

     return OLDGAA_SUCCESS;
}


/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_rights (oldgaa_rights_ptr* buffer_addr   /* IN  */)
{
 oldgaa_rights_ptr list = NULL;

  list = (oldgaa_rights_ptr) malloc(sizeof(oldgaa_rights));
  if (!list) out_of_memory();
    
#ifdef DEBUG
fprintf(stderr,"oldgaa_allocate_rights:%p\n",list);
#endif
     /* Initialize and fill in default values */

     list->type          = NULL;          
     list->authority     = NULL;          
     list->value         = NULL;
     list->cond_bindings = NULL;
     list->next          = NULL;           
     list->reference_count = 0;
    *buffer_addr         = list;

     return OLDGAA_SUCCESS;
}


/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_cond_bindings (oldgaa_cond_bindings_ptr* buffer_addr   /* IN  */)
{
 oldgaa_cond_bindings_ptr list = NULL;

  list = (oldgaa_cond_bindings_ptr) malloc(sizeof(oldgaa_cond_bindings));
  if (!list) out_of_memory();
    
#ifdef DEBUG
fprintf(stderr,"oldgaa_allocate_cond_bindings:%p\n",list);
#endif
     /* Initialize and fill in default values */
  
     list->condition = NULL;
     list->next      = NULL;           
	 list->reference_count = 0;
    *buffer_addr     = list;

     return OLDGAA_SUCCESS;
}


/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_sec_attrb (oldgaa_sec_attrb_ptr* buffer_addr   /* IN  */)
{
 oldgaa_sec_attrb_ptr list = NULL;

  list = (oldgaa_sec_attrb_ptr) malloc(sizeof(oldgaa_sec_attrb));
  if (!list) out_of_memory();
    
     /* Initialize and fill in default values */
        
     list->type      = NULL;            
     list->authority = NULL;        
     list->value     = NULL;
     list->next      = NULL;          
    *buffer_addr     = list;

     return OLDGAA_SUCCESS;
}


/*****************************************************************************/

oldgaa_error_code  
oldgaa_allocate_sec_context (oldgaa_sec_context_ptr*  buffer_addr)

{   
    oldgaa_sec_context_ptr   buffer; 
    oldgaa_identity_cred_ptr ident;

    buffer = (oldgaa_sec_context_ptr) malloc(sizeof(oldgaa_sec_context));
    if (!buffer) out_of_memory();
      
    /* Initialize and fill in default values */
   
       oldgaa_allocate_identity_cred(&ident);    
      
       buffer->identity_cred         = ident;

       buffer->authr_cred            = NULL;
       buffer->group_membership      = NULL;
       buffer->group_non_membership  = NULL;
       buffer->attributes            = NULL;
       buffer->unevl_cred            = NULL;
       buffer->connection_state      = NULL;

       buffer->condition_evaluation  = NULL;
       buffer->pull_cred             = NULL;
       buffer->cred_evaluate         = NULL;
           
      *buffer_addr = buffer;

       return OLDGAA_SUCCESS;
}

                     
/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_identity_cred(oldgaa_identity_cred_ptr*  buffer_addr  /* IN&OUT */)

{  
   oldgaa_buffer_ptr         ptr        = NULL;
   oldgaa_principals_ptr     principals = NULL;
   oldgaa_conditions_ptr     conditions = NULL;
   oldgaa_identity_cred_ptr  buffer     = NULL;

   buffer = (oldgaa_identity_cred_ptr) malloc(sizeof(oldgaa_identity_cred));
   if (!buffer) out_of_memory();
      

    /* Initialize and fill in default values */

       oldgaa_allocate_principals(&principals);
          
       buffer->principal  = principals;

       oldgaa_allocate_conditions(&conditions);
	   conditions->reference_count++;
          
       buffer->conditions  = conditions;
    
       oldgaa_allocate_buffer(&ptr);
          
       buffer->mech_spec_cred = ptr;
       buffer->next = NULL;

  
  *buffer_addr = buffer;

   return OLDGAA_SUCCESS;
   
}


/*****************************************************************************/

oldgaa_error_code
oldgaa_allocate_answer(oldgaa_answer_ptr *ptr)
{
  oldgaa_time_period_ptr time   = NULL;
  oldgaa_answer_ptr      buffer = NULL;

  /* Initialize and fill in default values */
 
  time  = (oldgaa_time_period_ptr) malloc(sizeof(oldgaa_time_period));
  if (!time) out_of_memory();

  time->start_time = 0;
  time->end_time   = 0;

  buffer = (oldgaa_answer_ptr) malloc(sizeof(oldgaa_answer));
  if (!buffer) out_of_memory();
      
  buffer->valid_time = time;
  buffer->rights     = NULL;

 *ptr = buffer;

  return OLDGAA_SUCCESS;
}

/*****************************************************************************/


