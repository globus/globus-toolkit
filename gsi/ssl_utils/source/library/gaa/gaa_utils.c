/**********************************************************************
 gaa_utils.c:

Description:
	This file is used internally by the gaa routines
**********************************************************************/


/**********************************************************************
                             Include header files
**********************************************************************/
#include <stdlib.h>     /* For malloc or free */
#include <math.h>       /* for pow()          */

#include <stdio.h>      /* File reading and writing */
#include <string.h> 
#include <errno.h>	/* For errno */

#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "globus_gaa.h" 
#include "gaa_utils.h"

#include "gnu_regex.h"


/**********************************************************************
                       Define module specific variables
**********************************************************************/

int	       string_count = 0;
int	       string_max   = 0;
static char   *parse_error  = NULL;


/******************************************************************************

Function:   gaa_gaa_handle_error
Description:
	Given and error message and a pointer to a pointer to be
	allocated handle the allocation and setting of the pointer.

Parameters:
	errstring, pointer to a pointer to be set to the allocated
	error message. May be NULL.

	message, the error message.

Returns:
	Nothing

******************************************************************************/

void
gaa_handle_error(char       **errstring,
                 const char *const message)
{
    /* If this fails we're hosed so don't bother checking */
    if (errstring)
      {
      if (errstring == NULL) *errstring = strdup(message);
      else
        {
        *errstring = (char *)realloc(*errstring, strlen(message)+1);
        if (*errstring != NULL) strcpy(*errstring, message);
        }
      }
   
} /* gaa_handle_error() */

/**********************************************************************

Function: gaa_strings_match() 

Description:
	Compare two strings.

Parameters:
	string1 and string2, pointers to two strings.

Returns:
	1 if strings match.
	0 if strings don't match.
       -1 on error, setting errno.

**********************************************************************/

int
gaa_strings_match(
  const char * const			string1,
  const char * const 			string2)
{
  /* Check arguments */
  if (!string1 || !string2)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    return -1;
  }

  return (strcmp(string1, string2) == 0);
} /* strings_match() */


/*****************************************************************************
 * gaa_strcopy - copy a string allocating space if necessary
 *
 *     GAA_STRCOPY takes a conventional string, S, as an argument, and a pointer to
 *     a second  string, R, which is to be replaced by S.  If R is long enough
 *     to hold S, S is copied.  Otherwise, new space is allocated, and R is
 *     freed.  S is then copied to the newly allocated space.  If S is
 *     NULL, then R is freed and NULL is returned.
 *
 *     In any event, GAA_STRCOPY returns a pointer to the new copy of S,
 *     or a NULL pointer.
 *****************************************************************************/

char *
gaa_strcopy(const char *s, char *r)
{
    int	slen;
 
     if(!s && r) {
        free(r);
        return(NULL);
    }
    else if (!s) return(NULL);

    if(r) free(r);

    slen = strlen(s) + 1;
   
    r = (char *) malloc(slen);
    if (!r) out_of_memory();
   
    strcpy(r,s);
    return(r);

}

/**********************************************************************
  Compare elements
 **********************************************************************/

int
gaa_compare_principals(gaa_principals_ptr element,
                   gaa_principals_ptr new)
{
  /* Do the principal's names match? */

 if(gaa_strings_match(element->type,      new->type)     &&
    gaa_strings_match(element->authority, new->authority) &&
    gaa_strings_match(element->value,     new->value) )
 return TRUE;   
 else return FALSE;
}  


/****************************************************************************-*/


int
gaa_compare_rights(gaa_rights_ptr element, gaa_rights_ptr new)
{
  if(gaa_strings_match(element->type,      new->type)     &&
     gaa_strings_match(element->authority, new->authority) &&
     gaa_strings_match(element->value,     new->value) )
  return TRUE;
  else return FALSE;
}

/****************************************************************************-*/


int
gaa_compare_conditions(gaa_conditions_ptr element, 
                   gaa_conditions_ptr new)
{
  if(gaa_strings_match(element->type,      new->type)     &&
     gaa_strings_match(element->authority, new->authority) &&
     gaa_strings_match(element->value,     new->value) )
  return TRUE;
  else return FALSE;
}
    
/****************************************************************************-*/

int
gaa_compare_sec_attrbs(gaa_sec_attrb_ptr element, 
                       gaa_sec_attrb_ptr new)
{
  if(gaa_strings_match(element->type,      new->type)     &&
     gaa_strings_match(element->authority, new->authority) &&
     gaa_strings_match(element->value,     new->value) )
  return TRUE;
  else return FALSE;
}
  
/**********************************************************************
  Add new element to a list
 **********************************************************************/

gaa_principals_ptr
gaa_add_principal(gaa_policy_ptr   *list, 
                  gaa_principals_ptr new)
{
  gaa_principals_ptr element;

  element = *list;

   if (gaa_compare_principals(element, new)) return element; /* found
      this principal in the list */ 

    while(element->next ) 
    {
     element = element->next;
     if (gaa_compare_principals(element, new)) return element; /* found
                                                   this principal in the list */    
    }

    element->next = new; /* add new element to the end of the list */
    return new;
}    


/*****************************************************************************/

gaa_rights_ptr
gaa_add_rights(gaa_rights_ptr *list, 
           gaa_rights_ptr  new)
{
  gaa_rights_ptr element;

  element = *list; 

  while(element->next!= NULL) element = element->next;   
  element->next = new;

  return new; 
}  

/*****************************************************************************/
gaa_cond_bindings_ptr
gaa_add_cond_binding(gaa_cond_bindings_ptr *list,
                 gaa_cond_bindings_ptr  new)
{
  gaa_cond_bindings_ptr element;

  element = *list;
 
  while(element->next!= NULL) element = element->next;
   
  element->next = new;

  return new; 
}  


/*****************************************************************************/


gaa_conditions_ptr
gaa_add_condition(gaa_conditions_ptr *list, 
                  gaa_conditions_ptr  new)
{
  gaa_conditions_ptr element;
 
  element = *list;

/*
 *DEE This code does not make sence. It will add new
 *to the end of the list, but will leave it hanging
 *if its the same as one already on the list. 
 */

  if (gaa_compare_conditions(element, new)) 
	{
		return element; /* found this condition in the list */ 
	}
    while(element->next) 
    {       
      element = element->next;
      if (gaa_compare_conditions(element, new)) 
		{
			return element; /* found this condition in the list */
		}
    }
     element->next = new; /* add new element to the end of the list */

     return new;
}    

/**********************************************************************
  Add new element to a list
 **********************************************************************/

gaa_sec_attrb_ptr
gaa_add_attribute(gaa_sec_attrb_ptr *list, gaa_sec_attrb_ptr new)
{
  gaa_sec_attrb_ptr element;

  element = *list;

   if (gaa_compare_sec_attrbs(element, new)) return element; /* found
      this attribute in the list */ 

    while(element->next) 
    {
     element = element->next;
     if (gaa_compare_sec_attrbs(element, new)) return element; /* found
                                                   this attribute in the list */    
    }

    element->next = new; /* add new element to the end of the list */
    return new;
}    


/**********************************************************************
  Bindings
 **********************************************************************/

int
gaa_bind_rights_to_principals(gaa_principals_ptr start, 
                          gaa_rights_ptr     rights)
{
 gaa_principals_ptr element = start;

 while(element != NULL)
  {  
    element->rights = rights;
	rights->reference_count++;

#ifdef DEBUG
fprintf(stderr,"gaa_bind_rights_to_principals:Principal:%p->rights:%p\n",
		element, rights);
#endif
    element         = element->next;
  }
 
 return GAA_SUCCESS;
}  


/*****************************************************************************/

void
gaa_bind_rights_to_conditions(gaa_rights_ptr        start,
                              gaa_cond_bindings_ptr cond_bind)
{
 gaa_rights_ptr element = start;

/*DEE - Looks like all the rights will point to this cond_bind*/
/* With Globus we only have 1, so should not be a problem */
 while(element)
  {   
    element->cond_bindings = cond_bind;
	cond_bind->reference_count++;
#ifdef DEBUG
fprintf(stderr,"gaa_bind_rights_to_conditions:rights:%p->cond_bind:%p\n",
		element, cond_bind);
#endif
    element                = element->next;
  }
}  

/**********************************************************************
  Regex Handling Functions
 **********************************************************************/

/**********************************************************************

Function: gaa_check_reg_expr() 

Description:
	Goes throug the list of reg expressions and looks for a match
        to the given rex expression.

Parameters:
	reg_expr pointer to a reg expression and reg_expr_list, pointers to
        a reg expression list

Returns:
	1 if regex match.
	0 if regex don't match.
	-1 on error, setting errno.

**********************************************************************/
int
gaa_check_reg_expr(char  *reg_expr, 
                   char **reg_expr_list)
{ 
 char **pregex;

#ifdef DEBUG
fprintf(stderr, "\ngaa_check_reg_expr:\n");
#endif /* DEBUG */

/* Check arguments */
  if (!reg_expr || !reg_expr_list)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    return -1;
  }

/* walk through the regexes and see if we match any */
      for (pregex = reg_expr_list;
	  *pregex != NULL;
	   pregex++)
      {
#ifdef DEBUG
fprintf(stderr, "reg_exp  %s\n*pregex %s\n\n", reg_expr, *pregex);
#endif /* DEBUG */
   
       if (gaa_regex_matches_string(reg_expr, *pregex) == 1)
       return 1; /* We have a match */		
      }

  return 0;
}



/**********************************************************************

Function: gaa_regex_matches_string()

Description:
	Determine if a regex matches a given string.

Parameters:
	string, the string to check

	regex, the regex to compare

Returns:
	1 if match.
	0 if don't match.
       -1 on error, setting errno.

**********************************************************************/

int
gaa_regex_matches_string(const char * const  string,
                         const char * const  regex)
{
  /* Compiled regex */
  regex_t				preg;

  /* Regex compilation flags */
  int					cflags = 0;

  /* Regex comparison flags */
  int					eflags = 0;

  /* Our result (1 == match) */
  int					result = 0;


  /* Check arguments */
  if (!string || !regex)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    return -1;
  }

  if (gaa_regex_regcomp(&preg, regex, cflags) != 0)
    return -1;

  result = (gaa_regex_regexec(&preg, string,
			       0, NULL, /* We don't care about matches */
			       eflags) == 0);

  gaa_regex_regfree(&preg);

  return result;

} /* gaa_regex_matches_string() */



/**********************************************************************

Function: gaa_parse_regex() 

Description:
	Walks throug condition list and evaluates each condition.

Parameters:
        condition, pointer to gaa_conditions structure

Returns:
       list of regex

**********************************************************************/

char **
gaa_parse_regex(char * str)
                
{
  char **subject_regexes = NULL; 
  int    num_regexes     = 0;      /* Number of subject regexes we've parse */
  char   new_str[MAX_STRING_SIZE]; /* Pointer to the string*/
  int    i      = 0,               /* Pointer to our current location in str */
         j,                        /* Pointer to our current location in new_str */
         length = strlen(str);			
  int    end = FALSE;			

#ifdef DEBUG
fprintf(stderr, "\ngaa_parse_regex:\n");
#endif /* DEBUG */

 
  /* Now read and parse all the subject regexes */
  subject_regexes = calloc(num_regexes + 1 /* for NULL */,
			   sizeof(char *));

  if (!subject_regexes) out_of_memory();
 		
  subject_regexes[0] = NULL;


  if (QUOTING != str[i]) strcpy(new_str, str);

  while(1)
  {
    char  *uncnv_regex;  /* Pointer to unconverted regex */   
    char  *cnv_regex;    /* Pointer to converted regex */   
    char **tmp_regexes;  /* Temporary holder for pointer to list of regexes */


   if(!end)
    {     
     while((str[i] == WHITESPACE)||
           (str[i] == TAB)       ||
           (str[i] == QUOTING)) i++;   

     j=0;
        
     /*   while((str[i] != WHITESPACE) &&
            (str[i] != TAB))*/

     while(1)
     {                
       if (str[i] == QUOTING)
      { 
        if (i == length-1) end = TRUE;   
        break;
      }

        if (i > length-1)
      { 
        end = TRUE;   
        break;
      }
    
       new_str[j]=str[i]; 
       i++; j++;
      }

     new_str[j]= NUL;
       
    } /* end of if(compound) */

    if (gaa_rfc1779_name_parse(new_str,
			      &uncnv_regex,
			       NULL) != 0)

    {
      gaa_handle_error(&parse_error,
		   "gaa_globus_parse_conditions: error parsing rfc1779 name");
      return NULL;
    }

    cnv_regex = gaa_to_regex(uncnv_regex);

    free(uncnv_regex);

    if (cnv_regex == NULL)
    {
     gaa_handle_error(&parse_error,
		  "gaa_globus_parse_conditions: error parsing regular expression"); 
     return NULL;
    }

    num_regexes++;
    tmp_regexes = realloc(subject_regexes,
			  (num_regexes + 1) * sizeof(char *));

    if (tmp_regexes == NULL)
    {
      gaa_handle_error(&parse_error, "gaa_globus_parse_conditions: out of memory");
      free(cnv_regex);
      return NULL;
    }

    subject_regexes = tmp_regexes;

    subject_regexes[num_regexes - 1] = cnv_regex;
    subject_regexes[num_regexes] = NULL;

    if (end)break;
   
  }

  if (num_regexes == 0)
 
  {
    /* No subject regexes were found */
  
    gaa_handle_error(&parse_error,
   		    "gaa_globus_parse_conditions: no subject regexes found");
    return NULL;

  }

 return subject_regexes;

}


/**********************************************************************

Function:	gaa_to_regex()

Description:    
	Convert a shell-style regex to a regex suitable
	to feed into the posix regex commands.

	Specifically:

	'*' is converted to '.*'

	'?' is converted to '.'

	'.', '^', '\, and '$' are escaped by preceding them
	with a backslash
			
	'^' is prepended to the string and '$' is appended so that the
	resulting regex will force a complete match.

Parameters:
	glob_regex, a pointer to the glob-style regex string.

Returns:
	a pointer to allocated regex string
	NULL on error (errno is set).
		
**********************************************************************/

static
char *
gaa_to_regex(const char * const glob_regex)
{
  char *converted_regex;
  const char *globp;
  char *convertedp;
  int length;


  /* Sanity check arguments */
  if (glob_regex == NULL)
  {
    errno = ERRNO_INVALID_ARGUMENT;
    return NULL;
  }

  /*
   * Make a buffer large enough to hold the largest possible converted
   * regex from the string
   */
  length = 
    strlen(glob_regex) * 2 /* maximum size is twice current */
    + 2 /* for '^' and '$' */
    + 1 /* for NUL */;

   converted_regex = malloc(length);

  if (!converted_regex) out_of_memory();

  convertedp = converted_regex;

  *convertedp++ = '^';

  for (globp = glob_regex;
       *globp != '\0';
       globp++)
  {

    switch(*globp)
    {

    case '*':
      /* '*' converts to '.*' */
      *convertedp++ = '.';
      *convertedp++ = '*';
      break;

    case '?':
      /* '?' converts to '.' */
      *convertedp++ = '.';
      break;

    case '.':
    case '^':
    case '$':
    case '\\':
      /* These are escaped by prepending a backslash */
      *convertedp++ = '\\';
      *convertedp++ = *globp;
      break;

    default:
      /* Anything else is copied verbatim */
      *convertedp++ = *globp;
    }
  }
    
  *convertedp++ = '$';

  *convertedp = '\0';

  return converted_regex;

} /* gaa_to_regex() */


/**********************************************************************/
