/**********************************************************************
 gaa_alloc.c:

Description:
	This file used internally by the gaa routines
**********************************************************************/

#include "globus_gaa.h"


/*****************************************************************************/

gaa_error_code  
gaa_allocate_buffer (gaa_buffer_ptr*  buffer_addr   /* IN  */)
{
  gaa_buffer_ptr  buffer;

  buffer = (gaa_buffer_ptr) malloc(sizeof(gaa_buffer));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->length  = 0; 
       buffer->value   = NULL;    
      *buffer_addr     = buffer;
    
       return GAA_SUCCESS;
}

/*****************************************************************************/

gaa_error_code  
gaa_allocate_data(gaa_data_ptr* buffer_addr /* IN  */)
{
  gaa_data_ptr  buffer;

  buffer = (gaa_data_ptr) malloc(sizeof(gaa_data));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->str         = NULL; 
       buffer->error_str   = NULL;
       buffer->error_code  = 0;

      *buffer_addr = buffer;
    
       return GAA_SUCCESS;
}
/*****************************************************************************/

gaa_error_code  
gaa_allocate_options (gaa_options_ptr*  buffer_addr   /* IN  */)
{
  gaa_options_ptr  buffer;

  buffer = (gaa_options_ptr) malloc(sizeof(gaa_options));
  if (!buffer) out_of_memory();
    
    /* Initialize and fill in default values */

       buffer->length  = 0; 
       buffer->value   = NULL;    
      *buffer_addr     = buffer;
    
       return GAA_SUCCESS;
}

/*****************************************************************************/

gaa_error_code
gaa_allocate_principals (gaa_principals_ptr* buffer_addr)
{
 gaa_principals_ptr list = NULL;

  list = (gaa_principals_ptr) malloc(sizeof(gaa_principals));
  if (!list) out_of_memory();
    

     /* Initialize and fill in default values */

              
     list->type      = NULL;            
     list->authority = NULL;               
     list->value     = NULL;
     list->rights    = NULL;
     list->next      = NULL;             
    *buffer_addr     = list;

     return GAA_SUCCESS;
}

/*****************************************************************************/

gaa_error_code
gaa_allocate_conditions (gaa_conditions_ptr* buffer_addr)
{
 gaa_conditions_ptr list = NULL;

  list = (gaa_conditions_ptr) malloc(sizeof(gaa_conditions));
  if (!list) out_of_memory();
    
     /* Initialize and fill in default values */

     list->type      = NULL;   
     list->authority = NULL;  
     list->value     = NULL;
     list->status    = 0;
     list->next      = NULL;         
     list->reference_count = 0;
    *buffer_addr     = list;

     return GAA_SUCCESS;
}


/*****************************************************************************/

gaa_error_code
gaa_allocate_rights (gaa_rights_ptr* buffer_addr   /* IN  */)
{
 gaa_rights_ptr list = NULL;

  list = (gaa_rights_ptr) malloc(sizeof(gaa_rights));
  if (!list) out_of_memory();
    
#ifdef DEBUG
fprintf(stderr,"gaa_allocate_rights:%p\n",list);
#endif
     /* Initialize and fill in default values */

     list->type          = NULL;          
     list->authority     = NULL;          
     list->value         = NULL;
     list->cond_bindings = NULL;
     list->next          = NULL;           
     list->reference_count = 0;
    *buffer_addr         = list;

     return GAA_SUCCESS;
}


/*****************************************************************************/

gaa_error_code
gaa_allocate_cond_bindings (gaa_cond_bindings_ptr* buffer_addr   /* IN  */)
{
 gaa_cond_bindings_ptr list = NULL;

  list = (gaa_cond_bindings_ptr) malloc(sizeof(gaa_cond_bindings));
  if (!list) out_of_memory();
    
#ifdef DEBUG
fprintf(stderr,"gaa_allocate_cond_bindings:%p\n",list);
#endif
     /* Initialize and fill in default values */
  
     list->condition = NULL;
     list->next      = NULL;           
	 list->reference_count = 0;
    *buffer_addr     = list;

     return GAA_SUCCESS;
}


/*****************************************************************************/

gaa_error_code
gaa_allocate_sec_attrb (gaa_sec_attrb_ptr* buffer_addr   /* IN  */)
{
 gaa_sec_attrb_ptr list = NULL;

  list = (gaa_sec_attrb_ptr) malloc(sizeof(gaa_sec_attrb));
  if (!list) out_of_memory();
    
     /* Initialize and fill in default values */
        
     list->type      = NULL;            
     list->authority = NULL;        
     list->value     = NULL;
     list->next      = NULL;          
    *buffer_addr     = list;

     return GAA_SUCCESS;
}


/*****************************************************************************/

gaa_error_code  
gaa_allocate_sec_context (gaa_sec_context_ptr*  buffer_addr)

{   
    gaa_sec_context_ptr   buffer; 
    gaa_identity_cred_ptr ident;

    buffer = (gaa_sec_context_ptr) malloc(sizeof(gaa_sec_context));
    if (!buffer) out_of_memory();
      
    /* Initialize and fill in default values */
   
       gaa_allocate_identity_cred(&ident);    
      
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

       return GAA_SUCCESS;
}

                     
/*****************************************************************************/

gaa_error_code
gaa_allocate_identity_cred(gaa_identity_cred_ptr*  buffer_addr  /* IN&OUT */)

{  
   gaa_buffer_ptr         ptr        = NULL;
   gaa_principals_ptr     principals = NULL;
   gaa_conditions_ptr     conditions = NULL;
   gaa_identity_cred_ptr  buffer     = NULL;

   buffer = (gaa_identity_cred_ptr) malloc(sizeof(gaa_identity_cred));
   if (!buffer) out_of_memory();
      

    /* Initialize and fill in default values */

       gaa_allocate_principals(&principals);
          
       buffer->principal  = principals;

       gaa_allocate_conditions(&conditions);
	   conditions->reference_count++;
          
       buffer->conditions  = conditions;
    
       gaa_allocate_buffer(&ptr);
          
       buffer->mech_spec_cred = ptr;
       buffer->next = NULL;

  
  *buffer_addr = buffer;

   return GAA_SUCCESS;
   
}


/*****************************************************************************/

gaa_error_code
gaa_allocate_answer(gaa_answer_ptr *ptr)
{
  gaa_time_period_ptr time   = NULL;
  gaa_answer_ptr      buffer = NULL;

  /* Initialize and fill in default values */
 
  time  = (gaa_time_period_ptr) malloc(sizeof(gaa_time_period));
  if (!time) out_of_memory();

  time->start_time = 0;
  time->end_time   = 0;

  buffer = (gaa_answer_ptr) malloc(sizeof(gaa_answer));
  if (!buffer) out_of_memory();
      
  buffer->valid_time = time;
  buffer->rights     = NULL;

 *ptr = buffer;

  return GAA_SUCCESS;
}

/*****************************************************************************/


