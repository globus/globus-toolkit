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


#ifndef GLOBUS_OBJECT_H
#define GLOBUS_OBJECT_H


#include "globus_common_include.h"

EXTERN_C_BEGIN

/**********************************************************************
 * Object API Types
 *   globus_object_type_t          --   class definitions
 *   globus_object_t               --   class instances
 **********************************************************************/

typedef void (*globus_object_copy_func_t) (void *  src_instance_data,
					   void ** dst_instance_data);

typedef void (*globus_object_destructor_func_t) (void * instance_data);

typedef struct globus_object_type_s {
  const struct globus_object_type_s * const   parent_type;
  globus_object_copy_func_t const             copy_func;
  globus_object_destructor_func_t const       destructor;
  void * const                                class_data;
} globus_object_type_t;

typedef struct globus_object_s {
  const globus_object_type_t *   type;
  struct globus_object_s *       parent_object;
  void *                         instance_data;
  int                            ref_count;
} globus_object_t;

typedef char * (*globus_object_printable_string_func_t)
     (globus_object_t * error);


/**********************************************************************
 * Object Creation API
 **********************************************************************/

extern globus_object_t *
globus_object_construct (const globus_object_type_t * create_type);
/* returns new object, or 
 * returns NULL on any failure */

extern globus_object_t *
globus_object_initialize_base (globus_object_t * object);

extern globus_object_t *
globus_object_construct_base ();

#define globus_object_static_initializer(object_type,                      \
                                         parent_prototype)                 \
{                                                                          \
  (object_type),                                                           \
  (parent_prototype),                                                      \
  ((void *) NULL),                                                         \
  1                                                                        \
}

extern globus_object_t *
globus_object_copy (const globus_object_t * object);
/* returns fresh copy, or
 * returns NULL on error or if object is NULL */

void
globus_object_reference(globus_object_t * object);

extern void
globus_object_free (globus_object_t * object);
/* does nothing if object is NULL or globus_object_is_static(object) is true
 */

#define globus_object_type_static_initializer(parent_type,                 \
                                              copy_func,                   \
                                              destructor,                  \
                                              class_data)                  \
{                                                                          \
  (parent_type),                                                           \
  (copy_func),                                                             \
  (destructor),                                                            \
  (class_data)                                                             \
}

#define globus_object_printable_type_static_initializer(pt,cf,df,s) \
        globus_object_type_static_initializer((pt),(cf),(df),(void *)(s))

extern globus_object_t *
globus_object_initialize_printable (globus_object_t * object);

extern globus_object_t *
globus_object_construct_printable ();


/**********************************************************************
 * Standard Object Type
 **********************************************************************/

extern const globus_object_type_t GLOBUS_OBJECT_TYPE_BASE_DEFINITION;
#define GLOBUS_OBJECT_TYPE_BASE (&GLOBUS_OBJECT_TYPE_BASE_DEFINITION)

extern const globus_object_type_t
GLOBUS_OBJECT_TYPE_PRINTABLE_DEFINITION;
#define GLOBUS_OBJECT_TYPE_PRINTABLE \
      (&GLOBUS_OBJECT_TYPE_PRINTABLE_DEFINITION)

/**********************************************************************
 * Basic Static Object Value
 **********************************************************************/

extern globus_object_t GLOBUS_OBJECT_BASE_STATIC_PROTOTYPE;
#define GLOBUS_OBJECT_BASE_PROTOTYPE (&GLOBUS_OBJECT_BASE_STATIC_PROTOTYPE)

extern globus_object_t 
GLOBUS_OBJECT_PRINTABLE_STATIC_PROTOTYPE; 
#define GLOBUS_OBJECT_PRINTABLE_PROTOTYPE \
      (&GLOBUS_OBJECT_PRINTABLE_STATIC_PROTOTYPE)

/**********************************************************************
 * Object Manipulation API
 **********************************************************************/

extern const globus_object_type_t *
globus_object_get_type (const globus_object_t * object);
/* returns type of object, or
 * returns NULL if object is NULL */

extern const globus_object_type_t *
globus_object_type_get_parent_type (const globus_object_type_t * type);
/* returns parent type of type, or
 * returns NULL if type is NULL */

extern globus_bool_t
globus_object_is_static (const globus_object_t * object);
/* returns GLOBUS_TRUE if either object is initialized by 
 *    globus_object_initialize_static() or
 * returns GLOBUS_FALSE otherwise */

extern void *
globus_object_type_get_class_data (const globus_object_type_t * type);
/* returns class data (may be NULL), or 
 * returns NULL if object is NULL */

extern globus_bool_t
globus_object_type_match (const globus_object_type_t * subtype,
			  const globus_object_type_t * supertype);
/* returns GLOBUS_TRUE iff subtype is an ancestor of supertype,
 * returns GLOBUS_FALSE otherwise */

extern globus_object_t *
globus_object_upcast (globus_object_t *      object,
		      const globus_object_type_t * desired_type);
/* returns object representing the desired_type portion of the object if
 * the object was constructed as an instance of desired_type (or one of its
 *    descendants), or
 * returns NULL otherwise.
 * objects returned are shared subsets of the original object. */

extern void
globus_object_set_local_instance_data (globus_object_t * object,
				       void *            instance_data);
/* does nothing if object is NULL */

extern void *
globus_object_get_local_instance_data (const globus_object_t * object);
/* returns instance data of object (may be NULL), or
 * returns NULL if object is NULL */


extern char *
globus_object_printable_to_string (globus_object_t * object);

extern globus_object_printable_string_func_t 
globus_object_printable_get_string_func (globus_object_t * object);

#include "globus_module.h"

extern globus_module_descriptor_t globus_i_object_module;

#define GLOBUS_OBJECT_MODULE (&globus_i_object_module)

EXTERN_C_END

#endif /* GLOBUS_OBJECT_H */




