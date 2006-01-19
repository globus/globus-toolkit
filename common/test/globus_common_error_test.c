/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include "globus_common.h"

#define MAX_ERROR_NUM 33

const globus_object_type_t *
switch_type (int class)
{
  const globus_object_type_t * type;

#define num_t(n,t) case n: type = GLOBUS_ERROR_TYPE_ ## t; break;

  switch (class) {
num_t(0,BASE);
num_t(1,NO_AUTHENTICATION);
num_t(2,NO_CREDENTIALS);
num_t(3,NO_TRUST);
num_t(4,INVALID_CREDENTIALS);
num_t(5,ACCESS_FAILED);
num_t(6,NO_AUTHORIZATION);
num_t(7,NOT_AVAILABLE);
num_t(8,DEPLETED);
num_t(9,QUOTA_DEPLETED);
num_t(10,OFFLINE);
num_t(11,NAME_UNKNOWN);
num_t(12,ABORTED);
num_t(13,USER_CANCELLED);
num_t(14,INTERNAL_ERROR);
num_t(15,SYSTEM_ABORTED);
num_t(16,BAD_DATA);
num_t(17,NULL_REFERENCE);
num_t(18,TYPE_MISMATCH);
num_t(19,BAD_FORMAT);
num_t(21,OUT_OF_RANGE);
num_t(22,TOO_LARGE);
num_t(23,TOO_SMALL);
num_t(24,COMMUNICATION_FAILED);
num_t(25,UNREACHABLE);
num_t(26,PROTOCOL_MISMATCH);
num_t(27,PROTOCOL_VIOLATED);
num_t(28,INVALID_USE);
num_t(29,ALREADY_DONE);
num_t(30,ALREADY_REGISTERED);
num_t(31,ALREADY_CANCELLED);
num_t(32,NOT_INITIALIZED);

  default:
    type = GLOBUS_ERROR_TYPE_BASE;
    break;
  }

  return type;
}

globus_result_t
throw_error (int class)
{
  const globus_object_type_t * type;
  globus_object_t * error;

  if (class==0) return GLOBUS_SUCCESS;

  type = switch_type (class);
  error = globus_object_construct (type);

  return globus_error_put (error);
}




int main ()
{
  int i;

  globus_module_activate (GLOBUS_COMMON_MODULE);

  for (i=0; i<=MAX_ERROR_NUM; i++) 
  {
    globus_result_t result;

    result = throw_error (i);
  }

  for (i=0; i<=MAX_ERROR_NUM; i++) 
  {
    globus_result_t result;

    result = throw_error (i);

    if (result==GLOBUS_SUCCESS) 
	{
      fprintf (stdout, "result %d: GLOBUS_SUCCESS\n", i);
    }
    else 
	{
      char * string;
      globus_object_t * error, *error2;
      const globus_object_type_t * type;
      int j;

      error = globus_error_get (result);
      string = globus_object_printable_to_string (error);
/*       fprintf (stdout, "result %d (%ld) A: %x \"%s\"\n", i, (int) result, (long) (void *) error, (string ? string : "")); */
      globus_free (string);

      for (j=0; j<=MAX_ERROR_NUM; j++) 
	  {
		type = switch_type (j);
/* 	fprintf (stdout, "result %d A: %s type %d\n", */
/* 		 i,  */
/* 		 (globus_object_type_match (globus_object_get_type(error), type) == GLOBUS_TRUE  */
/* 		  ? "matches" : "does not match") */
/* 		 , j); */
      }

      error2 = globus_object_upcast (error, GLOBUS_ERROR_TYPE_BASE);
      string = globus_object_printable_to_string (error2);
/*       fprintf (stdout, "result %d (%ld) B: %x \"%s\"\n", i, (int) result, (long) (void *) error2, (string ? string : "")); */
/*       fprintf (stdout, "result %d (%ld) B: has type %x\n", i, (int) result, */
/* 	       (long) (void *) globus_object_get_type (error2)); */
/*       fprintf (stdout, "result %d (%ld) B: has parent type %x\n", i, (int) result, */
/* 	       (long) (void *) globus_object_type_get_parent_type (globus_object_get_type (error2))); */
/*       fprintf (stdout, "result %d (%ld) B: has grandparent type %x\n", i, (int) result, */
/* 	       (long) (void *) globus_object_type_get_parent_type (globus_object_type_get_parent_type (globus_object_get_type(error2)))); */
      globus_free (string);
      for (j=0; j<7; j++) 
	  {
		type = switch_type (j);
		/* 	fprintf (stdout, "result %d B: %s type %d\n", */
		/* 		 i,  */
		/* 		 (globus_object_type_match (globus_object_get_type(error2), type) == GLOBUS_TRUE  */
		/* 		  ? "matches" : "does not match") */
		/* 		 , j); */
      }
      globus_object_free (error); 
	  error = NULL;

      error = globus_error_get (result);
      string = globus_object_printable_to_string (error);
/*       fprintf (stdout, "result %d (%ld) C: %x \"%s\"\n", i, (int) result, (long) (void *) error, (string ? string : "")); */
      globus_free (string);
      globus_object_free (error); 
	  error = NULL;

/*       fprintf (stdout , "\n\n"); */
	} /* end else*/
  } /* end for */

  globus_module_deactivate (GLOBUS_COMMON_MODULE);

  return 0;
}
