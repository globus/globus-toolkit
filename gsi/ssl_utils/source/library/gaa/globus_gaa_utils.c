/**********************************************************************
 globus_gaa-utils.c:

Description:
        Globus-GAA routines
**********************************************************************/


/**********************************************************************
                             Include header files
**********************************************************************/

#include "globus_gaa.h"
#include "globus_gaa_utils.h" 

#include "gaa_utils.h"
#include "config.h"

#include <string.h>	/* for strerror() */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h> 

/**********************************************************************
                       Define module specific variables
**********************************************************************/

static  int     end_of_file;
static  char   *parse_error  = NULL;
static  uint32  m_status     = 0;


/**********************************************************************
  GAA Cleanup Functions 
 **********************************************************************/

gaa_error_code
gaa_globus_cleanup(gaa_sec_context_ptr *gaa_sc,
                   gaa_rights_ptr      *rights,
                   gaa_options_ptr      options,
                   gaa_answer_ptr      *answer,  
                   gaa_data_ptr         policy_db, 
                   gaa_sec_attrb_ptr   *attributes)
{
  gaa_error_code gaa_status;
  uint32         minor_status;
        
 if(gaa_sc)    gaa_status = gaa_release_sec_context(&minor_status, gaa_sc); 
 if(rights)    gaa_status = gaa_release_rights(&minor_status, rights);   
 if(options)   gaa_status = gaa_release_options(&minor_status, options);  
 if(answer)    gaa_status = gaa_release_answer(&minor_status, answer);
 if(policy_db) gaa_status = gaa_release_data(&minor_status, policy_db);
 if(attributes)gaa_status = gaa_release_sec_attrb(&minor_status, attributes); 

 return gaa_status;
}



/**********************************************************************
  GAA Initialization Functions 
 **********************************************************************/

gaa_error_code
gaa_globus_initialize(gaa_sec_context_ptr *gaa_sc,
                      gaa_rights_ptr      *rights,
                      gaa_options_ptr     *options,
                      gaa_data_ptr        *policy_db, 
                      char                *signer, 
                      char                *subject,
                      char                *path)
{ 
  int error=0;

 /* Allocate and fill in GAA-Globus data structures */

 if(gaa_sc) *gaa_sc = gaa_globus_allocate_sec_context(signer); 
 if(rights) *rights = gaa_globus_allocate_rights();
    
 if(options) 
   {
      gaa_allocate_options(options);
    (*options)->value  = gaa_strcopy(subject, (*options)->value);  
    (*options)->length = strlen(subject); 
   }

 if(policy_db)
   {       
     gaa_allocate_data(policy_db);
   
     if(path) (*policy_db)->str = gaa_strcopy(path,(*policy_db)->str);
     else
     error = get_default_policy_file(*policy_db);
   }

   if(error)return GAA_FAILURE;
   else
   return GAA_SUCCESS;
}


/**********************************************************************

Function: gaa_globus_allocate_sec_context

Description:
	Allocates GAA security context and fills in globus-specific 
        information.

Parameters:
	signer, pointer to string with name of credential signer.

Returns:
	Pointer to a gaa_sec_context if successful
**********************************************************************/

gaa_sec_context_ptr
gaa_globus_allocate_sec_context(char *signer)
{
  gaa_sec_context_ptr sc = NULL;
  
  gaa_allocate_sec_context(&sc);
  
  if(strcmp(signer, GAA_ANYBODY) == 0) 
    {
      sc->identity_cred->principal->type = gaa_strcopy(GAA_ANYBODY, 
                                    sc->identity_cred->principal->type);

      sc->identity_cred->principal->authority = gaa_strcopy(" ",
                                    sc->identity_cred->principal->authority);

      sc->identity_cred->principal->value = gaa_strcopy(" ", 
                                    sc->identity_cred->principal->value);
    }
  else
    {
     sc->identity_cred->principal->type = gaa_strcopy(GAA_CA, 
                                    sc->identity_cred->principal->type);
   
     sc->identity_cred->principal->authority = gaa_strcopy(GAA_X509_AUTHORITY, 
                                    sc->identity_cred->principal->authority);
    
     sc->identity_cred->principal->value = gaa_strcopy(signer, 
                                    sc->identity_cred->principal->value); 
    }

  return sc;
}

/**********************************************************************

Function: gaa_globus_allocate_rights() 

Description:
	Allocates GAA rights stracture and fills in globus-specific 
        information..

Parameters:
	none

Returns:
	Pointer to a gaa_rights if successful
**********************************************************************/

gaa_rights_ptr
gaa_globus_allocate_rights()
{
 gaa_rights_ptr rights = NULL;

 gaa_allocate_rights(&rights);
 rights->reference_count++;
      
 rights->type       = gaa_strcopy(POSITIVE_RIGHTS,     rights->type);
 rights->authority  = gaa_strcopy(AUTH_GLOBUS,         rights->authority);
 rights->value      = gaa_strcopy(GLOBUS_RIGHTS_VALUE, rights->value);

 return rights;

}

/**********************************************************************
  Policy Retrieving Functions 
 **********************************************************************/

/**********************************************************************

Function: gaa_globus_policy_retrieve() 

Description:
        Upcall function for the retrieval of the object policy.

Parameters:
        object,    pointer to string with name of protected object, 
                   can be NULL
	policy_db, pointer to string with name of policy file

Returns:
	Pointer to a policy_file_context_ptr if successful
	NULL on error, setting errno.

**********************************************************************/

gaa_policy_ptr 
gaa_globus_policy_retrieve(uint32      *minor_status,
                           gaa_data_ptr object,
                           gaa_data_ptr policy_db, ...)
{ 
 policy_file_context_ptr   pcontext      = NULL; 
 gaa_policy_ptr            policy_handle = NULL;
 int                       error_type    =  1;

#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_policy_retrieve:\n");
#endif /* DEBUG */

 *minor_status = 0;

  pcontext = (policy_file_context_ptr)gaa_globus_policy_file_open(policy_db->str);

  if (pcontext)  /* parse policy */
 {
  if(gaa_globus_parse_policy(pcontext, 
		             &policy_handle) == GAA_SUCCESS)
  {
#ifdef DEBUG
	{
		gaa_principals_ptr pp;
		gaa_rights_ptr     rp;
		gaa_cond_bindings_ptr bp;
		gaa_conditions_ptr    cp;

		pp = policy_handle;
		while (pp) {
			fprintf(stderr,"principal:%p\n",pp);
			rp = pp->rights;
			while(rp) {
				fprintf(stderr,"   rights:%p ref:%d\n", 
						rp, rp->reference_count);
				bp = rp->cond_bindings;
				while(bp) {
					fprintf(stderr,"      cond_bindings:%p ref:%d\n",
							bp, bp->reference_count);
					cp = bp->condition;
					while (cp) {
						fprintf(stderr,"         condition:%p ref:%d\n",
								cp, cp->reference_count);
						cp = cp->next;
					}
					bp = bp->next;
				}
				rp = rp->next;
			}
		pp = pp->next;
		}
	}
#endif

     return policy_handle;
  }
  else error_type = 0; 
 }

  /* error handling */
 
   if(error_type) /* policy retrieve error */
     {          
        policy_db->error_code = ERROR_WHILE_RETRIEVING_POLICY;
        policy_db->error_str  = gaa_strcopy("error retrieving file ",
                                            policy_db->error_str);
        policy_db->error_str  = strcat(policy_db->error_str, policy_db->str);       

     }
    else          /* policy parsing error */
     { 
       policy_db->error_str  = pcontext->parse_error;
       policy_db->error_str  = strcat(policy_db->error_str, pcontext->str); 

       policy_db->error_code = m_status;

     }
  
    *minor_status = m_status;

    return NULL;
}
 
/**********************************************************************/

static
int
get_default_policy_file(gaa_data_ptr policy_db)
{
  char *ca_policy_file_path  = NULL;
  char *cert_dir             = NULL;
  char *ca_policy_filename   = GRID_CA_POLICY_FILENAME;

  cert_dir = getenv("X509_CERT_DIR");

  if (cert_dir)
  {
    ca_policy_file_path = malloc(strlen(cert_dir) +
				 strlen(ca_policy_filename) +
				 2 /* for '/' and NUL */);

   if(!ca_policy_file_path) out_of_memory();

  }


  if (ca_policy_file_path)
  {
    struct stat stat_buf;

    sprintf(ca_policy_file_path, "%s/%s", cert_dir, ca_policy_filename);

    policy_db->str = gaa_strcopy(ca_policy_file_path, policy_db->str) ;

  }
  
 if (!ca_policy_file_path)
  {    	   
   policy_db->error_str = 
   gaa_strcopy("Can not find default policy location. X509_CERT_DIR is not defined.\n",
                policy_db->error_str);
   policy_db->error_code = ERROR_WHILE_GETTING_DEFAULT_POLICY_LOCATION;

   return 1;
  }
 
  return 0; 
}



/**********************************************************************

Function: gaa_globus_policy_file_open() 

Description:
	Open the specified policy file for reading, returning a
	context.

Parameters:
	filename, pointer to string with name of policy file

Returns:
	Pointer to a policy_file_context if successful
	NULL on error, setting errno.

**********************************************************************/

policy_file_context_ptr 
gaa_globus_policy_file_open(const char *filename)
{
  char *		   open_mode = "r";
  policy_file_context_ptr  pcontext  = NULL;

#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_policy_file_open:\n");
#endif /* DEBUG */

  /* Check arguments */
  if (filename == NULL)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    return NULL;
  }

  /* allocate and fill in pcontext structure */
  pcontext = malloc(sizeof(*pcontext));
  if (!pcontext) out_of_memory();

  pcontext->stream      = NULL;
  pcontext->parse_error = NULL;
  pcontext->str         = NULL;

  gaa_handle_error(&(pcontext->parse_error),"not defined");
  gaa_handle_error(&(pcontext->str),"not defined");


  pcontext->stream = fopen(filename, open_mode);

  if (pcontext->stream == NULL)
  {
    free(pcontext);
    return NULL;
  }
 

  return pcontext;

} /* policy_file_open() */



/**********************************************************************

Function: gaa_globus_policy_file_close()

Description:
	Close the policy file and deallocate memory assigned to the
	context.

Parameters:
	pcontext, pointer to the context

Returns:
	Nothing

**********************************************************************/

void
gaa_globus_policy_file_close(policy_file_context_ptr  pcontext)
{

#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_policy_file_close:\n");
#endif /* DEBUG */

  if (pcontext)
  {
    if(pcontext->stream) fclose(pcontext->stream);

    free(pcontext->str);
    free(pcontext->parse_error);
    free(pcontext);
  }
} 


/**********************************************************************
  Policy Parsing Functions 
 **********************************************************************/
/**********************************************************************/

static
int
gaa_globus_help_read_string(policy_file_context_ptr  pcontext, 
                            char                    *str, 
                            const char              *message)
{

 if (gaa_globus_read_string(pcontext, str, NULL)) return 1;

 if (end_of_file == TRUE) 
     {       
       gaa_handle_error(&(pcontext->parse_error), message);
       return 1;         
     }  
     	 
 return 0;
}



/**********************************************************************

Function: gaa_globus_read_string

Description:
	Read a string from a given stream up to and including the newline
	and return it in an allocated buffer.

Parameters:
	pcontext, handle to a structure, containing the stream to read from.

	str, pointer to string to be filled in.

	errstring, pointer to the pointer to be filled in with
	a pointer to a string describing an error that occurs.
	May be NULL.

Returns:
        0 on success
        1 on error

**********************************************************************/

static
int
gaa_globus_read_string (policy_file_context_ptr  pcontext,
                        char                    *str,
                        char                    **errstring)
{   
  if (fscanf(pcontext->stream, "%s",str) == EOF) 
  {
    end_of_file = TRUE; 
    return 0; 
  }

  gaa_handle_error(&(pcontext->str),str); /* set the string value to
                             report it in the case there is an error */

  
  if (str[0]== STRING_DELIMITER) /* get strings with white spaces */
  {
   if(gaa_globus_get_string_with_whitespaces(pcontext, str) == -1)
    {
      gaa_handle_error(&(pcontext->parse_error),
		        "error while reading string");      
      return 1;
    }
  }


  if (str[0]== COMMENT) /* omit comment line */
  { 
    if(gaa_globus_omit_comment_line(pcontext))
    {
     gaa_handle_error(&(pcontext->parse_error),
		       "error while reading string"); 
     return 1;
    }

    if(gaa_globus_read_string(pcontext, str, errstring))
    {
      
     gaa_handle_error(&(pcontext->parse_error),
		      "error while reading string"); 
     return 1;
    }
  } 
  
 return 0;

}

/**********************************************************************

Function: gaa_globus_get_string_with_whitespaces

Description:
	Read a string from a given stream up to it finds STRING_DELIMITER.

Parameters:
	pcontext, handle to a structure, containing the stream to read from.

	str, pointer to string to be filled in.

Returns:
        0 on success
       -1 on error

**********************************************************************/
static
int
gaa_globus_get_string_with_whitespaces(policy_file_context_ptr  pcontext,
                                       char                    *str)
{
 int  i, len = strlen(str);
 int  chr;

 for (i=0; i<len-1; i++) str[i] = str[i+1]; /* get rid of ' in the 
                                               begining of str */
 if(str[i-1] == STRING_DELIMITER) 
 {
   str[i-1] = NUL; /* clean up the tailing ' */
   return 0;
  }

                   
  while(i < MAX_STRING_SIZE) /* read chars from the stream 
                            untill see STRING_DELIMITER */
  {  
     chr = fgetc(pcontext->stream); 

     if(chr == EOF)  
    {     
      end_of_file = TRUE;

      gaa_handle_error(&(pcontext->parse_error),
		 "gaa_globus_get_string_with_white_spaces: Missing string delimiter \'");
      return -1;
    }        
      if (chr == STRING_DELIMITER) break;
      else { str[i] = chr; i++; }
  }


  if(i >= MAX_STRING_SIZE)/* string is too long */
    {
      gaa_handle_error(&(pcontext->parse_error),
		 "get_string_with_white_spaces: String is too long");
      return -1;
    }

  str[i] = NUL; /* terminate the string */

  return 0;
}

/**********************************************************************

Function: gaa_globus_omit_comment_line

Description:
	omit comment from the stream

Parameters:
	pcontext, handle to a structure, containing the stream to read from.

Returns:
        0 on success
       -1 on error

**********************************************************************/

static
int
gaa_globus_omit_comment_line(policy_file_context_ptr  pcontext)
{
 int chr;  
 
 while((chr = fgetc(pcontext->stream))!= EOF)
  {         
     if (chr == END_OF_LINE) break;          
  }

  if (chr == EOF) end_of_file = TRUE;

  return 0;
}   



/**********************************************************************

Function: gaa_globus_parse_policy() 

Description:
        Parses the policy file, filling gaa_policy structure. The format of
        the [olicy file is described in ?

Parameters:
        minor_status, mechanism-specific status code
        pcontext, handle to a structure, containing the stream to read from.
        policy_handle, pointer to gaa_policy structure to be filled in. 
                   
Returns:
	GAA_SUCCESS or GAA_RETREIVE_ERROR

**********************************************************************/

gaa_error_code  
gaa_globus_parse_policy (policy_file_context_ptr  pcontext,
                         gaa_policy_ptr          *policy_handle)

{
  gaa_policy_ptr        ptr_policy       = NULL;
  gaa_conditions_ptr    all_conditions   = NULL;
/*
 *DEE all_conditions is only used in this routine to look for
 * duplicate conditions.
 */
  gaa_principals_ptr    start_principals = NULL;
  gaa_rights_ptr        start_rights     = NULL;
  gaa_cond_bindings_ptr cond_bind        = NULL;
  gaa_error_code        gaa_error;

  char                  str[MAX_STRING_SIZE] = {NUL};
  int                   cond_present     = FALSE;
  int                   new_entry        = TRUE; 
  int                   line_number;
 
  end_of_file    = 0;
  *policy_handle = NULL;
	 
#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_parse_policy:\n");
#endif /* DEBUG */
 
  while (!end_of_file)    
 { 
  if (new_entry == TRUE) /* start parsing new entry */
  {
   cond_present = FALSE;
   new_entry    = FALSE;

  /* get principals */
                        
    if(gaa_globus_parse_principals(pcontext,
                        policy_handle,
                        str,
                        &start_principals) != GAA_SUCCESS)
     { 
      gaa_handle_error(&(pcontext->parse_error),
		 "gaa_globus_parse_policy: error while parsing principal: ");
      m_status = ERROR_WHILE_PARSING_PRINCIPALS;

      goto err;
     }

  }/* if (new_entry == TRUE) */

     /* continue parsing an entry */

     /* get rights */

       gaa_error = gaa_globus_parse_rights(pcontext,                              
                                           str,
                                          &start_rights,         
                                          &cond_present,
                                          &new_entry);
    if(gaa_error != GAA_SUCCESS)
     {       
        gaa_handle_error(&(pcontext->parse_error),
		 "gaa_globus_parse_policy: error while parsing right: ");       
        m_status = ERROR_WHILE_PARSING_RIGHTS;
       goto err;

    }

    /* bind paresed rights for this entry to the paresed principals 
      from this entry */

    gaa_bind_rights_to_principals(start_principals, start_rights);
 
   /* get conditions, if any */
  
   if(cond_present == TRUE)
  {
    gaa_error = gaa_globus_parse_conditions(pcontext,
                                &all_conditions,
                                 str,
                                &cond_bind,
                                &new_entry);
   
   if (gaa_error != GAA_SUCCESS)               
   {
     gaa_handle_error(&(pcontext->parse_error),
		 "gaa_globus_parse_policy: error while parsing condition: ");
  
     m_status = ERROR_WHILE_PARSING_CONDITIONS; 
     goto err;

   }
  
  /* bind paresed conditions for this entry to the paresed rights 
    from this entry */

  else  gaa_bind_rights_to_conditions(start_rights, cond_bind);   
   
 } /* if(cond_present == TRUE) */
  
 
 }/* end of while */

/* 
 * Since the conditions are now all bound to cond_bindings, 
 * we can remove the next chain pointers so they don't get
 * in the way during free if there are other chains 
 * using conditions. 
 */

  {
	gaa_conditions_ptr   c1p, c2p;

	c1p = all_conditions;
    while(c1p)
    {
	  c2p = c1p->next;
      c1p->next = NULL;
	  c1p = c2p;
    }
  }
	
  if (pcontext) gaa_globus_policy_file_close(pcontext);

  return GAA_SUCCESS;

 err:

 gaa_release_principals(&m_status, policy_handle);
 gaa_globus_policy_file_close(pcontext);

 return GAA_RETRIEVE_ERROR;
      
}

/**********************************************************************

Function: gaa_globus_parse_principals() 

Description:
        Parses the policy file, filling gaa_rincipals structure. 

Parameters:
        pcontext, handle to a structure, containing the stream to read from.
        policy, pointer to gaa_policy structure to be filled in. 
        tmp_str, contains a string which will be evaluated and in the end,
               new value is stored here.
        start, stores a pointer to gaa_principals structure of the set
        of principals which will be read by this invokation. This is needed
        by the  bind_rights_to_principals function.       
Returns:
       GAA_SUCCESS or GAA_PARSE_ERROR

**********************************************************************/


gaa_error_code
gaa_globus_parse_principals(policy_file_context_ptr  pcontext,
                            gaa_policy_ptr          *policy,
                            char                    *tmp_str /* IN&OUT */,
                            gaa_principals_ptr      *start)
{
  char               str[MAX_STRING_SIZE],*type;
  int                first     = TRUE, ret_val;
  gaa_principals_ptr principal = NULL;

#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_parse principals:\n");
#endif /* DEBUG */

 if (*policy == NULL) /* first principal in the policy file */
  {
   if (gaa_globus_help_read_string(pcontext, str,"parse principals: Empty policy"))
   return GAA_RETRIEVE_ERROR;   
  }
 else strcpy(str, tmp_str); /* get the value of read principal from tmp_str */

do 
  {   /* get principal's type */

   if(strcmp(str, GAA_ANYBODY) == 0) /* do not check for authority and value */  
      type = GAA_ANYBODY;        
   else
    if(strcmp(str,GAA_USER) == 0)
       type = GAA_USER;
    else 
      if(strcmp(str,GAA_CA) == 0)
          type = GAA_CA;
     else 
      if (strcmp(str,GAA_GROUP) == 0)
          type = GAA_GROUP;
       else 
         if(strcmp(str,GAA_HOST) == 0)
            type = GAA_HOST;
           else 
             if(strcmp(str,GAA_APPLICATION) == 0)
                type = GAA_APPLICATION;
             else 
             {
               gaa_handle_error(&(pcontext->parse_error), 
                                "parse_principals: Bad principal type");
               return GAA_RETRIEVE_ERROR;
             }
          
    gaa_allocate_principals(&principal);

    if (type) 
    principal->type  = gaa_strcopy(type, principal->type);
        
    if(strcmp(type, GAA_ANYBODY)== 0) /* fill in default values */
     {   
       principal->authority = gaa_strcopy(" ", principal->authority);
       principal->value     = gaa_strcopy(" ", principal->value);
     }
   else /* read defyining authority and value from the policy */
    {  
      if (gaa_globus_help_read_string(pcontext, str,
                         "parse_principals: Missing principal defining authority"))
      return GAA_RETRIEVE_ERROR;
        
      if (str) /* expecting defining authority */ 
      principal->authority = gaa_strcopy(str, principal->authority);     

      if (gaa_globus_help_read_string(pcontext, str,
                         "parse_principals: Missing principals value"))
      return GAA_RETRIEVE_ERROR;
        
      if (str) /* expecting value */ 
      principal->value = gaa_strcopy(str, principal->value);
       
   
   } /* end of if(type != "access_id_ANYBODY")*/ 

    if (*policy == NULL) *policy = principal;

    if(first == TRUE){ *start = principal;  first = FALSE; } 

   gaa_add_principal(policy, principal); /* add new principal to the list */

    if (gaa_globus_help_read_string(pcontext, str,
                         "parse_principals: Missing rights"))
    return GAA_RETRIEVE_ERROR;

    strcpy(tmp_str, str); /* return the read string */

   if( !strcmp(str,POSITIVE_RIGHTS) ||
       !strcmp(str,NEGATIVE_RIGHTS) )  /* operation set starts */  
   return GAA_SUCCESS;    

  } while(!end_of_file);
   
   return  GAA_SUCCESS;
}


/**********************************************************************

Function: gaa_globus_parse_rights() 

Description:
        Parses the policy file, filling gaa_rights structure. 

Parameters:
        pcontext, handle to a structure, containing the stream to read from.
        tmp_str,  contains a string which will be evaluated and in the end,
                  new value is stored here.
        start,    stores a pointer to gaa_rights structure of the set
                  of rights which will be read by this invokation. This is needed
                  by the  bind_rights_to_conditions function.
                  cond_present, indicates if condition set starts
        end_of_entry, indicates if new entry starts     
Returns:
       GAA_SUCCESS or GAA_RETRIEVE_ERROR

**********************************************************************/

gaa_error_code
gaa_globus_parse_rights(policy_file_context_ptr  pcontext,
                        char                    *tmp_str,
                        gaa_rights_ptr          *start,
                        int                     *cond_present,
                        int                     *end_of_entry)
{
  char            str[MAX_STRING_SIZE];
  int             first  = TRUE, ret_val;
  gaa_rights_ptr  rights = NULL;
  
#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_parse rights:\n");
#endif /* DEBUG */

  strcpy(str, tmp_str); 

do{
  if( (gaa_strings_match(str,POSITIVE_RIGHTS) ||
       gaa_strings_match(str,NEGATIVE_RIGHTS))== FALSE)  /* expecting operation
                                                        set starts */
        {
          gaa_handle_error(&(pcontext->parse_error), "Bad right type");
          return GAA_RETRIEVE_ERROR;
	}
 
  
    /* allocate fill in the gaa_rights structure */

    gaa_allocate_rights(&rights);
    if (str)
    rights->type = gaa_strcopy(str, rights->type);
      
    if (gaa_globus_help_read_string(pcontext, str,
                        "parse_rights: Missing right authority"))
    return GAA_RETRIEVE_ERROR;  
 
    if (str) /* expecting defining authority */ 
    rights->authority = gaa_strcopy(str, rights->authority);
     
    if(gaa_globus_help_read_string(pcontext, str,
                        "parse_rights: Missing right value"))
    return GAA_RETRIEVE_ERROR;  
  
    if (str)/* expecting value */      
    rights->value = gaa_strcopy(str, rights->value);
       
    if(first == TRUE){ *start = rights; first = FALSE; } 
    else gaa_add_rights(start, rights);

    if (gaa_globus_read_string(pcontext, str, NULL))     
    return GAA_RETRIEVE_ERROR;
      
    strcpy(tmp_str, str); /* return the read string */
       
       if(!strncmp(str,COND_PREFIX, 5))  /* condition set starts */
       {
        *cond_present = TRUE;
         return GAA_SUCCESS;   
       }
   
       if(!strncmp(str,PRINCIPAL_ACCESS_PREFIX, 6) ||
          !strncmp(str,PRINCIPAL_GRANTOR_PREFIX, 7))  /* new entry starts */        
       {
        *end_of_entry = TRUE;      
         return GAA_SUCCESS; 
       }     

 } while(!end_of_file);

   return GAA_SUCCESS;
}


/**********************************************************************
Function: gaa_globus_parse_conditions() 

Description:
        Parses the policy file, filling gaa_conditions structure. 

Parameters:
        pcontext,   handle to a structure, containing the stream to read from.
        conditions, pointer to gaa_conditions structure to be filled in. 
        tmp_str,    contains a string which will be evaluated and in the end,
                    new value is stored here.
        list,       stores a pointer to gaa_cond_bindings structure of the set
                    of conditions which will be read by this invokation. 
                    This is needed by the bind_rights_to_conditions function.
        end_of_entry, indicates if new entry starts     
Returns:
       GAA_SUCCESS or GAA_RETRIEVE_ERROR


**********************************************************************/

gaa_error_code
gaa_globus_parse_conditions(policy_file_context_ptr  pcontext,
                            gaa_conditions_ptr      *conditions,                  
                            char                    *tmp_str,
                            gaa_cond_bindings_ptr   *list, 
                            int                     *end_of_entry )
{
  char                  str[MAX_STRING_SIZE];
  int                   first = TRUE, ret_val;
  gaa_conditions_ptr    cond;
  gaa_cond_bindings_ptr cond_bind;
  uint32        inv_minor_status = 0, inv_major_status = 0;

#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_parse conditions:\n");
#endif /* DEBUG */

  strcpy(str, tmp_str); 
  
do
{
   if(strncmp(str,"cond_", 5) != 0)/* expecting condition set starts */
       {
          gaa_handle_error(&(pcontext->parse_error),"Bad condition type");
          return GAA_RETRIEVE_ERROR;
       }

 /* allocate fill in the gaa_conditions structure */

   gaa_allocate_conditions(&cond);
   if (str) cond->type = gaa_strcopy(str,cond->type) ;
    
   if (gaa_globus_help_read_string(pcontext, str,
                        "parse_conditions: Missing condition authority"))
   return GAA_RETRIEVE_ERROR;

   if (str) cond->authority = gaa_strcopy(str, cond->authority);
   
   if (gaa_globus_help_read_string(pcontext, str,
                       "parse_conditions: Missing condition value"))
   return GAA_RETRIEVE_ERROR;

   if (str) cond->value = gaa_strcopy(str, cond->value);
    
   gaa_allocate_cond_bindings(&cond_bind);

   if(*conditions == NULL) { *conditions = cond; }
   cond_bind->condition =gaa_add_condition(conditions, cond);
   cond_bind->condition->reference_count++;
#ifdef DEBUG
   fprintf(stderr,"binding cond_bind:%p->conditions:%p\n",
			cond_bind, cond_bind->condition);
#endif
   /* If we don't add it to the list, then we need to free it! */
   if (cond_bind->condition != cond)
   {
#ifdef DEBUG
	 fprintf(stderr,"Duplicate conditions, free:%p\n",cond);
#endif
	 cond->reference_count++; /* keep all the ducks in a row */
	 gaa_release_conditions(&inv_minor_status, &cond);
   }

   if(first == TRUE){ *list = cond_bind; first = FALSE; } 
   else  gaa_add_cond_binding(list, cond_bind);
 
   if (gaa_globus_read_string(pcontext, str, NULL))    
   return GAA_RETRIEVE_ERROR;
      
   if(end_of_file == TRUE)  return  GAA_SUCCESS;
    
   strcpy(tmp_str, str); /* return the read string */

    if(!strncmp(str,PRINCIPAL_ACCESS_PREFIX, 6) ||
       !strncmp(str,PRINCIPAL_GRANTOR_PREFIX, 7))  /* new entry starts */        
       {
        *end_of_entry = TRUE;      
         return GAA_SUCCESS; 
       }  

    if(!strncmp(str,POS_RIGHTS_PREFIX, 3) ||
       !strncmp(str,NEG_RIGHTS_PREFIX, 3)) /* new rights set starts */          
    return GAA_SUCCESS;
     

 } while (!end_of_file);

   return  GAA_SUCCESS;
}


/*****************************************************************************/
  
void
gaa_globus_print_rights(gaa_rights_ptr rights)
{
 gaa_rights_ptr        ptr = rights;
 gaa_cond_bindings_ptr cond;

 while(ptr != NULL)
    {  
       fprintf(stderr, "ACCESS RIGHT\n");
       fprintf(stderr, "type      : %s\n",   ptr->type);   
       fprintf(stderr, "authority : %s\n",   ptr->authority);
       fprintf(stderr, "value     : %s\n\n", ptr->value);

      cond = ptr->cond_bindings; 

      while(cond != NULL)
      {
       fprintf(stderr, "CONDITION\n");
       fprintf(stderr, "type      : %s\n",     cond->condition->type);   
       fprintf(stderr, "authority : %s\n",     cond->condition->authority);
       fprintf(stderr, "value     : %s\n",     cond->condition->value);
       fprintf(stderr, "status    : %08x\n\n", cond->condition->status);

       cond = cond->next;
      }

      ptr = ptr->next;
    }

}

/**********************************************************************/
void
gaa_globus_print_attributes(gaa_sec_attrb_ptr attributes)
{
 gaa_sec_attrb_ptr        ptr = attributes;


 while(ptr != NULL)
    {  
       fprintf(stderr, "ATTRIBUTE\n");
       fprintf(stderr, "type      : %s\n",   ptr->type);   
       fprintf(stderr, "authority : %s\n",   ptr->authority);
       fprintf(stderr, "value     : %s\n\n", ptr->value);

       ptr = ptr->next; 
    }
}

/**********************************************************************/

gaa_error_code
gaa_globus_get_trusted_ca_list(gaa_sec_attrb_ptr *attributes,
                               gaa_policy_ptr     policy_handle,
                               gaa_rights_ptr     rights)
{
  gaa_error_code     gaa_status    = GAA_SUCCESS;
  uint32             minor_status  = 0;
  gaa_principals_ptr principal= NULL;     
   
#ifdef DEBUG
fprintf(stderr, "\ngaa_globus_get_trusted_ca_list:\n");
#endif /* DEBUG */


  gaa_allocate_principals(&principal);
  principal->type      = gaa_strcopy(GAA_CA,             principal->type);   
  principal->authority = gaa_strcopy(GAA_X509_AUTHORITY, principal->authority);
  /* principal->value     = gaa_strcopy("\"*\"",            principal->value); */

  gaa_status = gaa_get_authorized_principals(attributes, 
                                             policy_handle,
                                             principal, 
                                             rights);

 gaa_status = gaa_release_principals(&minor_status, &principal);

 return gaa_status;   

}


/**********************************************************************/
