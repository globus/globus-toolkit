/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_object.h"
#include "globus_libc.h"

static globus_mutex_t                   s_object_ref_mutex;

static int s_object_init (void)
{
    return globus_mutex_init(&s_object_ref_mutex, GLOBUS_NULL);
}

static int s_object_destroy (void)
{
    return globus_mutex_destroy(&s_object_ref_mutex);
}

#include "version.h"
globus_module_descriptor_t globus_i_object_module =
{
  "globus_object",
  s_object_init,
  s_object_destroy,
  GLOBUS_NULL,
  GLOBUS_NULL,
  &local_version
};


globus_bool_t
globus_object_type_assert_valid (const globus_object_type_t * type)
{
  while ( type != NULL ) 
  {
    if ( type->parent_type != NULL ) 
	{
    }
    else 
	{
      /* validate static/dynamic tag */
      assert ( type->copy_func == NULL );
      assert ( type->destructor == NULL );
    }

    type = type->parent_type;
  }

  return GLOBUS_TRUE;
}


globus_bool_t
globus_object_assert_valid (const globus_object_t * object)
{
  if ( object!=NULL ) 
  {
    globus_object_type_assert_valid (object->type);

    while (object!=NULL) 
	{
      assert ( object->type != NULL );

      if ( object->parent_object != NULL ) 
	  {
		/* validate object/type lattice */
		assert ( object->type->parent_type
			== object->parent_object->type );
      }
      else 
	  {
		/* validate object/type lattice */
		assert ( object->type->parent_type == NULL );

		/* validate static/dynamic tag */
		assert ( (object->instance_data == NULL) 
			|| (object->instance_data == (void *) 0x01 ) );
      }

      /* validate parent object */
      object = object->parent_object;
    }
  }

  return GLOBUS_TRUE;
}


/**********************************************************************
 * Object Creation API
 **********************************************************************/

globus_object_t *
globus_object_construct (const globus_object_type_t * create_type)
{
  globus_object_t * parent_object = NULL;
  globus_object_t * new_object = NULL;

  if ( create_type==NULL )
    return NULL;

  if ( create_type->parent_type!=NULL ) {
    parent_object = globus_object_construct (create_type->parent_type);
    if (parent_object==NULL) return NULL;
  }
  else {
    parent_object = NULL;
  }

  new_object = ((globus_object_t *) 
		globus_malloc (sizeof(globus_object_t)));
  if (new_object==NULL) {
    globus_object_free (parent_object);
    return NULL;
  }

  new_object->type          = create_type;
  new_object->parent_object = parent_object;
  new_object->ref_count     = 1;

  if ( create_type->parent_type == NULL ) {
    /* root types carry static/dynamic tag */
    new_object->instance_data = (void *) 0x01; /* dynamic tag */
  }
  else {
    /* default initialization for non-root types */
    new_object->instance_data = (void *) NULL;
  }

  return new_object;
}


globus_object_t *
globus_object_initialize_base (globus_object_t * object)
{
  return object;
}

extern globus_object_t *
globus_object_construct_base ()
{
  return globus_object_construct (GLOBUS_OBJECT_TYPE_BASE);
}

globus_object_t *
globus_object_copy (const globus_object_t * object)
{
  globus_object_t * copy;
  globus_object_t * parent_copy;

  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return NULL;

  if ( object==NULL ) return NULL;

  if ( object->parent_object != NULL ) {
    parent_copy = globus_object_copy (object->parent_object);
    if (parent_copy==NULL) {
      return NULL;
    }
  }
  else {
    parent_copy = NULL;
  }

  copy = globus_malloc (sizeof(globus_object_t));
  if ( copy==NULL ) {
    globus_object_free (parent_copy);
    return NULL;
  }

  copy->type = object->type;
  copy->parent_object = parent_copy;
  copy->ref_count     = 1;
  
  if ( object->type->parent_type == NULL ) {
    /* root types carry static/dynamic tag */
    copy->instance_data = (void *) 0x01; /* dynamic tag */
  }
  else if ( object->type->copy_func != NULL ) {
    /* default initialization for non-root types */
    copy->instance_data = (void *) NULL;
    /* possibly override default */
    (object->type->copy_func) (object->instance_data,
			       &(copy->instance_data));
  }
  else {
    /* default initialization for non-root types */
    copy->instance_data = (void *) NULL;
  }

  return copy;
}

void
globus_object_reference(globus_object_t * object)
{
    globus_mutex_lock(&s_object_ref_mutex);
    {
        ++object->ref_count;
    }
    globus_mutex_unlock(&s_object_ref_mutex);
}

void
globus_object_free (globus_object_t * object)
{
  int                                   ref_count;
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return;

  if ( object==NULL ) return;

  if ( globus_object_is_static (object) == GLOBUS_TRUE ) return;
    
  globus_mutex_lock(&s_object_ref_mutex);
  {
    ref_count = --object->ref_count;
  }
  globus_mutex_unlock(&s_object_ref_mutex);
    
  if(ref_count == 0)
  {
      if ( object->type->destructor != NULL ) 
      {
        (object->type->destructor) (object->instance_data);
      }
    
      if ( object->parent_object != NULL ) 
      {
        globus_object_free (object->parent_object);
        object->parent_object = NULL;
      }
    
      object->type = NULL;
      object->instance_data = NULL;
    
      globus_free (object);
  }
}


globus_object_t *
globus_object_initialize_printable (globus_object_t * object)
{
  return object;
}

globus_object_t *
globus_object_construct_printable ()
{
  return globus_object_construct (GLOBUS_OBJECT_TYPE_PRINTABLE);
}


/**********************************************************************
 * Standard Object Type
 **********************************************************************/

static char *
s_string_copy (char * string)
{
  char * ns;
  int i, l;

  if ( string == NULL ) return NULL;

  l = strlen (string);

  ns = globus_malloc (sizeof(char *) * (l + 1));
  if ( ns == NULL ) return NULL;

  for (i=0; i<l; i++) {
    ns[i] = string[i];
  }
  ns[l] = '\00';

  return ns;
}


static char *
globus_l_object_printable_string_func (globus_object_t * printable)
{
  return s_string_copy ("<content unknown>");
}


const globus_object_type_t GLOBUS_OBJECT_TYPE_BASE_DEFINITION
= globus_object_type_static_initializer (NULL,         /* no parent */
					 NULL,         /* no data copy */
					 NULL,         /* no data destroy */
					 NULL          /* no class data */);

const globus_object_type_t GLOBUS_OBJECT_TYPE_PRINTABLE_DEFINITION
= globus_object_printable_type_static_initializer (
				   GLOBUS_OBJECT_TYPE_BASE,
				   NULL,         /* no data copy */
				   NULL,         /* no data destroy */
				   globus_l_object_printable_string_func);

/**********************************************************************
 * Basic Static Object Value
 **********************************************************************/

globus_object_t GLOBUS_OBJECT_BASE_STATIC_PROTOTYPE
= globus_object_static_initializer (GLOBUS_OBJECT_TYPE_BASE,
				    NULL /* BASE type has no parent */);

globus_object_t GLOBUS_OBJECT_PRINTABLE_STATIC_PROTOTYPE
= globus_object_static_initializer (GLOBUS_OBJECT_TYPE_PRINTABLE,
				    GLOBUS_OBJECT_BASE_PROTOTYPE);

/**********************************************************************
 * Object Manipulation API
 **********************************************************************/

const globus_object_type_t *
globus_object_get_type (const globus_object_t * object)
{
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return NULL;

  if ( (object==NULL) ) {
    return NULL;
  }

  return object->type;
}

const globus_object_type_t *
globus_object_type_get_parent_type (const globus_object_type_t * type)
{
  if ( (type==NULL) ) {
    return NULL;
  }

  return type->parent_type;
}

globus_bool_t
globus_object_is_static (const globus_object_t * object)
{
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return GLOBUS_FALSE;

  globus_object_assert_valid (object);

  if ( object==NULL ) return GLOBUS_FALSE;

  if ( object->type->parent_type == NULL ) {
    if ( object->instance_data == NULL ) {
      /* static tag */
      return GLOBUS_TRUE;
    }
    else {
      /* dynamic tag */
      return GLOBUS_FALSE;
    }
  }
  else {
    return globus_object_is_static ( object->parent_object );
  }
}

void *
globus_object_type_get_class_data (const globus_object_type_t * type)
{
  if ( type == NULL ) return NULL;

  return type->class_data;
}

extern globus_object_t *
globus_object_upcast (globus_object_t            * object,
		      const globus_object_type_t * desired_type)
{
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return NULL;
  
  if (desired_type==NULL) return NULL;
  
  while ( (object!=NULL) && (object->type!=desired_type) ) {
    object = object->parent_object;
  }
  
  if ( object!=NULL ) {
     return object;
   }
   else {
    return NULL;
  }
}
 

void
globus_object_set_local_instance_data (globus_object_t * object,
				       void *            instance_data)
{
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return;

  if (object==NULL) return;

  object->instance_data = instance_data;

  return;
}

void *
globus_object_get_local_instance_data (const globus_object_t * object)
{
  if ( globus_object_assert_valid (object) 
       == GLOBUS_FALSE ) return NULL;

  if ( object==NULL ) return NULL;

  return object->instance_data;
}

extern globus_bool_t
globus_object_type_match (const globus_object_type_t * subtype,
			  const globus_object_type_t * supertype)
{
  if ( supertype == NULL ) return GLOBUS_FALSE;

  while ( (subtype!=NULL) && (subtype!=supertype) ) {
    subtype = subtype->parent_type;
  }

  if ( subtype!=NULL ) {
    return GLOBUS_TRUE;
  }
  else {
    return GLOBUS_FALSE;
  }
}
globus_object_printable_string_func_t
globus_object_printable_get_string_func (globus_object_t * printable)
{
    if ( globus_object_type_match (globus_object_get_type(printable),
				   GLOBUS_OBJECT_TYPE_PRINTABLE)
	 != GLOBUS_TRUE )
    {
	return NULL;
    }
    else 
    {
	while ( (printable != NULL) &&
		(globus_object_type_get_class_data (
		    globus_object_get_type(printable))
		 == NULL) ) 
	{
	    printable = globus_object_upcast(
		printable, 
		globus_object_type_get_parent_type (
		    globus_object_get_type(printable)));
	}
	return ((globus_object_printable_string_func_t) 
		globus_object_type_get_class_data (
		    globus_object_get_type(printable)));
    }
}


char *
globus_object_printable_to_string (globus_object_t * printable)
{
  if ( globus_object_printable_get_string_func (printable) != NULL ) {
    return (globus_object_printable_get_string_func (printable)) (printable);
  }
  else return NULL;
}



