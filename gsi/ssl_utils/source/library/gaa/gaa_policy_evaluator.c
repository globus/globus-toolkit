
/**********************************************************************
 gaa_policy_evaluator.c:

Description:
	This file is used internally by the gaa routines
**********************************************************************/

/**********************************************************************
                             Include header files
**********************************************************************/
#include <stdio.h>	/* File reading and writing */
#include <errno.h>	/* For errno */
#include <stdlib.h>	/* For malloc() */
#include <string.h> 	/* strerror() and other string functions */

#include "globus_gaa.h" 
#include "gaa_utils.h"
#include "globus_gaa_utils.h"
#include "gaa_policy_evaluator.h"


/**********************************************************************
                       Define module specific variables
**********************************************************************/

#define STRING_LENGTH			80

/**********************************************************************

Function: gaa_find_matching_entry

Description:
	Finds policy corresponding to the given principal.

Parameters:
        minor_status, mechanism-specific error code.
	ptr, pointer to principal.
        policy, pointer to policy.
      
Returns:
	Pointer to a gaa_policy structure if successful

**********************************************************************/


gaa_policy_ptr    
gaa_find_matching_entry(uint32             *minor_status, 
                        gaa_principals_ptr  ptr, 
                        gaa_policy_ptr      policy)          
{
  gaa_policy_ptr entry = policy;

  /* Check arguments */
  if (!ptr)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    *minor_status = -1;
  } 

  while(entry)
 { 
  if(gaa_strings_match(entry->type, GAA_ANYBODY)) return entry;
 
 /* do exact match */
 if(gaa_compare_principals(ptr, entry))  return entry;

 #ifdef PRINCIPALS_REGEX_MATCH
{
  char    **subject_regexes = NULL; /* NULL terminated list of regexes */
  int i;

#ifdef DEBUG
fprintf(stderr, "%s %s\n", ptr->value, entry->value);
#endif /* DEBUG */

   subject_regexes = gaa_parse_regex(entry->value);

   if(subject_regexes) 
     {        
        if(gaa_check_reg_expr(ptr->value, subject_regexes))  
          {
          for (i=0; subject_regexes[i] != NULL; i++)
            free(subject_regexes[i]);
          free(subject_regexes);
          return entry;
		  }
        for (i=0; subject_regexes[i] != NULL; i++)
          free(subject_regexes[i]);
        free(subject_regexes);
     } 
}  
#endif /* #ifdef PRINCIPALS_REGEX_MATCH  */
   
 entry = entry->next;
 }

 return NULL;

}

/**********************************************************************

Function: gaa_check_access_rights

Description:
         Checks if the requested access rights are granted. It checks
         conditions, if any.

Parameters:


Returns:
        GAA atatus
	
**********************************************************************/


gaa_error_code
gaa_check_access_rights(gaa_sec_context_ptr sc,
                    gaa_rights_ptr      requested_rights,
                    gaa_rights_ptr      rights,
                    gaa_answer_ptr      detailed_answer,
                    gaa_options_ptr     options)
{
 gaa_error_code gaa_status;
 int            was_no = FALSE, was_maybe = FALSE; 

#ifdef DEBUG
fprintf(stderr, "\ngaa_check_access_rights:\n");
#endif /* DEBUG */

  /* check if the requested rights match rights in the policy */

 if (!gaa_compare_rights(requested_rights, rights))
 return GAA_NO; /* now we have just one type of rights: CA:sign */
 
#ifdef DEBUG
fprintf(stderr, "right is granted\n");
#endif /* DEBUG */
  
  detailed_answer->rights = rights; 
  rights->reference_count++;
  
   if(rights->cond_bindings) /* operation is allowed and there are
                                          some conditions */
  
   {
#ifdef DEBUG
fprintf(stderr, "there are some conditions\n");
#endif /* DEBUG */

 gaa_status = gaa_evaluate_conditions(sc,
                                         rights->cond_bindings,
                                         options);

    if(gaa_status == GAA_NO)    was_no    = TRUE;
    if(gaa_status == GAA_MAYBE) was_maybe = TRUE;

   }

  if(was_no)    return GAA_NO;
  if(was_maybe) return GAA_MAYBE;

  return GAA_YES;  /* operation is allowed and either there are NO any 
                     or all conditions are met */
}

/*****************************************************************************/

gaa_error_code
gaa_get_authorized_principals(gaa_sec_attrb_ptr *attributes,
                              gaa_policy_ptr     policy,
                              gaa_principals_ptr principal,
                              gaa_rights_ptr     rights)

{
  gaa_policy_ptr    entry  = policy;
  gaa_error_code    answer = GAA_SUCCESS;
  int               was_anybody    = 0;
  int               was_neg_rights = 0;
  int               number_of_entries = 1;
  gaa_sec_attrb_ptr attrb = NULL;
  uint32            minor_status;
  gaa_error_code    gaa_status = GAA_SUCCESS;

#ifdef DEBUG
fprintf(stderr, "\ngaa_get_authorized_principals:\n");
#endif /* DEBUG */

  minor_status = 0;

/* Check arguments */
  if (!policy && !attributes)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    minor_status = -1;
    return GAA_FAILURE;
  }
 
  
   while(entry)
  {    
    if(gaa_strings_match(entry->type, GAA_ANYBODY) &&
       gaa_compare_rights(entry->rights, rights)) was_anybody = 1;
     

   if(gaa_strings_match(entry->type,      principal->type)   &&
      gaa_strings_match(entry->authority, principal->authority))
  {
    if(gaa_compare_rights(entry->rights, rights))
       {
         gaa_allocate_sec_attrb(&attrb);
         attrb->type      = gaa_strcopy(entry->type,      attrb->type);
         attrb->authority = gaa_strcopy(entry->authority, attrb->authority);
         attrb->value     = gaa_strcopy(entry->value,     attrb->value);

       if(*attributes == NULL) { *attributes = attrb; }

         gaa_add_attribute(attributes, attrb);
         number_of_entries++;      
       }
    else 
      {
     if(gaa_strings_match(entry->rights->type,      NEGATIVE_RIGHTS)   &&
        gaa_strings_match(entry->rights->authority, rights->authority) &&
        gaa_strings_match(entry->rights->value,     rights->value) ) was_neg_rights = 1;
     }

     
  }

   entry = entry->next;

  } /* end of while */

    if(was_anybody && (number_of_entries == 1)) /* return ANYBODY only if it is the only entry of this type */
      {
         gaa_allocate_sec_attrb(&attrb);
         attrb->type      = gaa_strcopy(GAA_ANYBODY, attrb->type);
         attrb->authority = gaa_strcopy(" ",         attrb->authority);
         attrb->value     = gaa_strcopy(" ",         attrb->value);

         if (*attributes == NULL) *attributes = attrb;
         else gaa_add_attribute(attributes, attrb);
       }
           
return  gaa_status;        
}

/**********************************************************************

Function: gaa_evaluate_conditions() 

Description:
	Walks throug condition list and evaluates each condition.

Parameters:
	security context, condition list and options

Returns:
	GAA_YES   if all conditions are met.
	GAA_NO    if at least one is not met.
	GAA_MAYBE if some conditions are not evaluated.

**********************************************************************/

gaa_error_code 
gaa_evaluate_conditions(gaa_sec_context_ptr    sc, 
                        gaa_cond_bindings_ptr  conditions,
                        gaa_options_ptr        options)
{  
   gaa_error_code         gaa_status = GAA_NO;
   gaa_cond_bindings_ptr  cond       = conditions;
   int                    was_no     = FALSE, was_maybe = FALSE; 
 
#ifdef DEBUG
fprintf(stderr, "\ngaa_evaluate_conditions:\n");
#endif /* DEBUG */

 while(cond)/* walk throug condition list */
   {
     gaa_status = GAA_MAYBE;
   
     gaa_status =  evaluate_condition(sc, cond->condition, options);

     if(gaa_status == GAA_NO)    was_no    = TRUE;
     if(gaa_status == GAA_MAYBE) was_maybe = TRUE;

     cond = cond->next;
   }

 if(was_no)    return GAA_NO;
  if(was_maybe) return GAA_MAYBE;

  return GAA_YES; 

}



gaa_error_code
gaa_evaluate_day_cond(gaa_conditions_ptr condition, 
                  gaa_options_ptr    options)

{
   int            retval, j=0;
   gaa_error_code gaa_status = GAA_NO;

   char *day = NULL, *str1 = NULL, *str2 = NULL, cond[MAX_COND_LENGTH] = {NUL};
   char *current_day = NULL;
   char *value;

   strcpy(cond, condition->value);

     /* get current day */ 
     current_day = get_day();
     day = gaa_strcopy(current_day, day); 
     free(current_day);
    
     /* get first day delimiter */     
     str1 = gaa_strcopy(get_value(&j, cond, '-'), str1);

     /* get second day delimiter */
     value = get_value(&j, cond, NUL);
     str2 = gaa_strcopy(value, str2);
     free(value);

     retval = check_day(str1, str2, day);
 
     if(retval == -1) return GAA_MAYBE; /* unsupported day format */

     if(retval == 1) gaa_status = GAA_YES;
   
   return gaa_status; 

}

/**********************************************************************

Function: gaa_evaluate_regex_cond() 

Description:
	Walks throug condition list and evaluates each condition.

Parameters:
	security context, condition list and options

Returns:
	GAA_YES   if all conditions are met.
	GAA_NO    if at least one is not met.
	GAA_MAYBE if some conditions are not evaluated.

**********************************************************************/

gaa_error_code
gaa_evaluate_regex_cond(gaa_conditions_ptr condition, 
                        gaa_options_ptr    options)
{
  char          **subject_regexes = NULL; /* NULL terminated list of regexes */
  int i;
  gaa_error_code  gaa_status      = GAA_NO;

#ifdef DEBUG
fprintf(stderr, "gaa_evaluate_rege_cond:\n");
#endif /* DEBUG */

   subject_regexes = gaa_parse_regex(condition->value);

   if(!subject_regexes) return GAA_FAILURE;
           
     if(gaa_check_reg_expr(options->value, subject_regexes))  
      gaa_status = GAA_YES;

     for (i=0; subject_regexes[i] != NULL; i++)
       free(subject_regexes[i]);
     free(subject_regexes);
   
return gaa_status;

}

/*****************************************************************************/

gaa_error_code
gaa_evaluate_time_cond(gaa_conditions_ptr condition, 
                       gaa_options_ptr    options)

{
   int   j = 0;
   gaa_error_code gaa_status = GAA_NO;

   int   hr, min, sec;
   int   cond_hr, cond_min, cond_sec;
   char  cond[MAX_COND_LENGTH] = {NUL};

   strcpy(cond, condition->value);

  if(gaa_strings_match(condition->authority, HOUR_SCALE_24))
   {  
     char *hr_str;
     char *min_str;
     char *sec_str;
     char *value;

     /* current hour    */ 
     hr_str = get_hr_24();
     hr  = atoi(hr_str);
     free(hr_str);

     /* current minutes */  
     min_str = get_minutes();
     min = atoi(min_str);
     free(min_str);

     /* current seconds */ 
     sec_str = get_seconds();
     sec = atoi(sec_str);
     free(sec_str);

     /* get hours from condition value */    
     value = get_value(&j, cond, ':');
     cond_hr = atoi(value);
     free(value);

     if (hr < cond_hr) return GAA_NO;
    
     /* get minutes from condition value */
     value = get_value(&j, cond, ':');
     cond_min = atoi(value);
     free(value);

     /* get seconds from condition value */
     value = get_value(&j, cond, '-');
     cond_sec = atoi(value);
     free(value);

  
    if (cond_hr == hr) /* if hours are equal, check minutes */
    {
      if (min < cond_min) return GAA_NO;

      if (cond_min == min) /* if minutes are equal, check seconds */
	{
          if (sec < cond_sec) return GAA_NO;
          else goto success;
	}
    }

      /* hours are greater, check second time value */

     /* get hours from condition value */
     value = get_value(&j, cond, ':');
     cond_hr = atoi(value);
     free(value);

     if  (cond_hr < hr) return GAA_NO;

    /* get minutes from condition value */
     value = get_value(&j, cond, ':');
     cond_min = atoi(value);
     free(value);

    /* get seconds from condition value */
     value = get_value(&j, cond, ':');
     cond_sec = atoi(value);
     free(value);


    if (cond_hr == hr) /* if hours are equal, check minutes */
    {
      if (cond_min < min) return GAA_NO;

      if (cond_min == min) /* if minutes are equal, check seconds */
	{
          if (cond_sec <  sec) return GAA_NO;
          else  goto success;
	}
    }


 success:

   return GAA_YES;
   }

 return GAA_MAYBE; /* unsupported time format */

}

/*****************************************************************************/


gaa_error_code
gaa_evaluate_sech_mech_cond(gaa_principals_ptr  principal,
                        gaa_conditions_ptr  condition, 
                        gaa_options_ptr     options)

{ 
   gaa_error_code gaa_status = GAA_NO;

   if (gaa_strings_match(condition->value, principal->authority))
   gaa_status = GAA_YES;
         
   return gaa_status; 

}



/**********************************************************************
             Helpers Static Functions         
 **********************************************************************/


/**********************************************************************

Function: evaluate_condition() 

Description:
	Invokes apropriate evaluation function for each condition.

Parameters:
	security context, condition list and options

Returns:
	GAA_YES   if condition is met.
	GAA_NO    if condition is not met.
	GAA_MAYBE if evaluation function was not found.

**********************************************************************/

static
gaa_error_code
evaluate_condition(gaa_sec_context_ptr sc, 
                   gaa_conditions_ptr  condition,
                   gaa_options_ptr     options)
{  
  gaa_error_code gaa_status = GAA_MAYBE;
 
#ifdef DEBUG
fprintf(stderr, "evaluate_condition: %s %s %s\n", 
        condition->type,
        condition->authority,
        condition->value);
#endif /* DEBUG */
 

  if(!strcmp(condition->type,      COND_SUBJECTS) && 
     !strcmp(condition->authority, AUTH_GLOBUS))    
     gaa_status = gaa_evaluate_regex_cond(condition, options);

  if(!strcmp(condition->type,      COND_BANNED_SUBJECTS) && 
     !strcmp(condition->authority, AUTH_GLOBUS))
    {    
     gaa_status = gaa_evaluate_regex_cond(condition, options);
     if(gaa_status == GAA_YES) gaa_status = GAA_NO;
    }

#ifdef GAA_COND_DAY
     if(!strcmp(condition->type, COND_DAY))
     gaa_status = gaa_evaluate_day_cond(condition, options);
#endif

#ifdef GAA_COND_TIME
     if(!strcmp(condition->type, COND_TIME))
     gaa_status = gaa_evaluate_time_cond(condition, options);
#endif

#ifdef GAA_COND_SEC_MECH
     if(!strcmp(condition->type, COND_SEC_MECH))
     gaa_status = gaa_evaluate_sech_mech_cond(sc->identity_cred->principal,
                                              condition, options);
#endif

   /* check if condition evaluation function for upcall was passed in the security context */
  if(sc->condition_evaluation) 
    sc->condition_evaluation(sc, options, condition, &gaa_status);

  if(gaa_status != GAA_MAYBE)
  condition->status |= COND_FLG_EVALUATED; /* evaluated */

  if(gaa_status == GAA_YES)
  condition->status |= COND_FLG_MET;       /* met */ 

return gaa_status;

}

/*****************************************************************************/
static
char *
get_day()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();

  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%A",t);

  return str; 
}
 

/*****************************************************************************/
static
char *
get_hr_24()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();

  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%H",t);

  return str; 
} 
/*****************************************************************************/
static
char *
get_hr_12()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();

  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%I",t);

  return str; 
}


/*****************************************************************************/
static
char *
get_minutes()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();


  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%M",t);

  return str; 
} 
/*****************************************************************************/
static
char *
get_seconds()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();

  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%S",t);

  return str; 
} 

/*****************************************************************************/
static
char *
get_am_pm()
{
  time_t     tt;
  struct tm *t;
  char      *str;

  str = malloc(STRING_LENGTH + 1 /* for NUL */);
  if (!str)
      out_of_memory();

  time(&tt); 
  t = localtime(&tt); 
  strftime(str,STRING_LENGTH,"%p",t);

  return str; 
} 
/*****************************************************************************/
static
int
day_to_val(char *str)
{ 
 
 if (gaa_regex_matches_string(str, "Su") ||
     gaa_regex_matches_string(str, "su")) return 1;

 if (gaa_regex_matches_string(str, "Mo") || 
     gaa_regex_matches_string(str, "mo")) return 2;

 if (gaa_regex_matches_string(str, "Tu") ||
     gaa_regex_matches_string(str, "tu")) return 3;
  
 if (gaa_regex_matches_string(str, "We") ||
     gaa_regex_matches_string(str, "we")) return 4;
        
 if (gaa_regex_matches_string(str, "Th") ||
     gaa_regex_matches_string(str, "th")) return 5;
       
 if (gaa_regex_matches_string(str, "Fr") ||
     gaa_regex_matches_string(str, "fr")) return 6;
     
 if (gaa_regex_matches_string(str, "Sa") ||
     gaa_regex_matches_string(str, "sa")) return 7;
                     
 return 0;
}


/*****************************************************************************/
static
int
check_day(char *str1, char *str2, char *day)

{
 int val, val1, val2;

 val  = day_to_val(day);  /* current day          */
 val1 = day_to_val(str1); /* first day delimiter  */
 val2 = day_to_val(str2); /* second day delimiter */

 if (!val1) return -1;

 if((val == val1) ||
    (val == val2) ||
    ((val1 < val2) && (val > val1) && (val < val2)) ||
    ((val1 > val2) && val2 && ((val > val1) || (val < val2)))
   ) return 1;
 
 return 0;

} 
 

/*****************************************************************************/

static
char*
get_value(int *jj, const char *cond, const char delimiter)
 {
  int  i,j  = *jj, length = strlen(cond);
  char *str = NULL;

  str = malloc(length + 1 /* for NUL */);
  if(!str) out_of_memory();

  for(i=0; j <= length; i++)
	{ 
          str[i] = cond[j];
          j++; 
          if((cond[j] == delimiter)) { j++; /* omit delimiter */ break; }   
	}

 str[i+1] = NUL; /* terminate the string */
 *jj = j;
 return str;
  } 
           
/*****************************************************************************/


