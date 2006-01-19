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
#include "globus_io.h"
#include "globus_gss_assist.h"

char *
globus_i_io_error_string_func ( globus_object_t * error )
{
    char * string;
    const globus_object_type_t * type;
    char * tmp;

    type = globus_object_get_type(error);

    if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR))
    {
        char * function;

        function = globus_io_error_internal_error_get_function(error);
        if(function)
        {
            string = _IOSL("an internal error_occurred in %s");
            tmp = globus_malloc(strlen(string) + strlen(function)+1);

            sprintf(tmp, string, function);

            return tmp;
        }
        string = _IOSL("an internal error_occurred in globus_io");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED))
    {
        globus_io_handle_t * handle;

        handle = globus_io_error_registration_error_get_handle(error);

        if(handle)
        {
            string = _IOSL("the handle %p was already registered for reading");
            tmp = globus_malloc(strlen(string) + 64 + 1);
            sprintf(tmp, string, handle);

            return tmp;
        }
        string = _IOSL("the handle was already registered for reading");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED))
    {
        globus_io_handle_t * handle;

        handle = globus_io_error_registration_error_get_handle(error);

        if(handle)
        {
            string = _IOSL("the handle %p was already registered for writing");
            tmp = globus_malloc(strlen(string) + 64 + 1);
            sprintf(tmp, string, handle);

            return tmp;
        }
        string = _IOSL("the handle was already registered for writing");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED))
    {
        globus_io_handle_t * handle;

        handle = globus_io_error_registration_error_get_handle(error);

        if(handle)
        {
            string = _IOSL("the handle %p was already registered for exception events");
            tmp = globus_malloc(strlen(string) + 64 + 1);
            sprintf(tmp, string, handle);

            return tmp;
        }
        string = _IOSL("the handle was already registered for exception events");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED))
    {
        globus_io_handle_t * handle;

        handle = globus_io_error_registration_error_get_handle(error);

        if(handle)
        {
            string = _IOSL("the handle %p was already registered for closing");
            tmp = globus_malloc(strlen(string) + 64 + 1);
            sprintf(tmp, string, handle);

            return tmp;
        }
        string = _IOSL("the handle was already registered for closing");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR))
    {
        globus_io_handle_t * handle;

        handle = globus_io_error_registration_error_get_handle(error);

        if(handle)
        {
            string = _IOSL("a registration operation failed for handle %p");
            tmp = globus_malloc(strlen(string) + 64 + 1);
            sprintf(tmp, string, handle);

            return tmp;
        }
        string = _IOSL("a registration operation failed");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER))
    {
        int position;
        char * func;

        position = globus_io_error_bad_parameter_get_position(error);
        func = globus_io_error_bad_parameter_get_function(error);

        if(func)
        {
            string = _IOSL("a NULL parameter was passed as argument %d to %s");
            tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
            sprintf(tmp, string, position, func);

            return tmp;
        }
        string = _IOSL("a NULL parameter");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_BAD_POINTER))
    {
        int position;
        char * func;

        position = globus_io_error_bad_parameter_get_position(error);
        func = globus_io_error_bad_parameter_get_function(error);

        if(func)
        {
            string = _IOSL("a bad pointer was passed as argument %d to %s");
            tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
            sprintf(tmp, string, position, func);

            return tmp;
        }
        string = _IOSL("a bad pointer");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE))
    {
        char * attribute;

        attribute = globus_io_error_immutable_attribute_get_attribute_name(error);
        if(attribute)
        {
            string = _IOSL("an attempt to change the immutable attribute %s");
            
            tmp = globus_malloc(strlen(string) + strlen(attribute) + 1);

            sprintf(tmp, string, attribute);

            return tmp;
        }
        string = _IOSL("an attempt to change an immutable attribute");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_TYPE))
    {
        int position;
        char * func;
        char * type_name;

        position = globus_io_error_bad_parameter_get_position(error);
        func = globus_io_error_bad_parameter_get_function(error);
        type_name = globus_io_error_invalid_type_get_required_type_string(error);

        if(func != GLOBUS_NULL &&
           type_name != GLOBUS_NULL)
        {
            string = _IOSL("argument %d to %s should be of type %s\n");
            
            tmp = globus_malloc(strlen(string) + strlen(func) + strlen(type_name)+ 1);

            sprintf(tmp, string, position, func, type_name);

            return tmp;
        }
        string = _IOSL("an argument of incorrect type for an operation\n");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH))
    {
        char * attr1;
        char * attr2;

        attr1 = globus_io_error_attribute_mismatch_get_attr1(error);
        attr2 = globus_io_error_attribute_mismatch_get_attr2(error);

        if(attr1 && attr2)
        {
            string = _IOSL("attribute %s is incompatible with %s");

            tmp = globus_malloc(strlen(string) + strlen(attr1) + strlen(attr2) + 1);
            sprintf(tmp, string, attr1, attr2);

            return tmp;
        }

        string = _IOSL("an attempt to apply incompatible attributes");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND))
    {
        char *name;

        name = globus_io_error_invalid_name_get_unresolvable_name(error);

        if(name)
        {
            string = _IOSL("the name %s could not be resolved");

            tmp = globus_malloc(strlen(string) + strlen(name) + 1);

            sprintf(tmp, string, name);

            return tmp;
        }
        string = _IOSL("a host name could not be resolved");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_NAME))
    {
        char *name;

        name = globus_io_error_invalid_name_get_unresolvable_name(error);

        if(name)
        {
            string = _IOSL("the name %s could not be used");

            tmp = globus_malloc(strlen(string) + strlen(name) + 1);

            sprintf(tmp, string, name);
        }

        string = _IOSL("a name could not be used");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT))
    {
        string = _IOSL("the process has insufficient permissions to use the desired port");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_PORT_IN_USE))
    {
        string = _IOSL("the requested port was already in use");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_PORT))
    {
        string = _IOSL("the requested port could not be used");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED))
    {
        int position;
        char * func;

        position = globus_io_error_bad_parameter_get_position(error);
        func = globus_io_error_bad_parameter_get_function(error);

        if(func)
        {
            string = _IOSL("an uninitialied data structure was passed as argument %d to %s");
            tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
            sprintf(tmp, string, position, func);

            return tmp;
        }
        string = _IOSL("an uninitialized data structure");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER))
    {
        int position;
        char * func;

        position = globus_io_error_bad_parameter_get_position(error);
        func = globus_io_error_bad_parameter_get_function(error);

        if(func)
        {
            string = _IOSL("a bad parameter was passed as argument %d to %s");
            tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
            sprintf(tmp, string, position, func);

            return tmp;
        }
        string = _IOSL("a bad parameter was passed to this function");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE))
    {
        int save_errno;

        save_errno = 
            globus_io_error_system_failure_get_save_errno(error);

        if(save_errno)
        {
            string = _IOSL("a system call failed (%s)");

            tmp = globus_malloc(
                strlen(string) 
                + strlen(globus_libc_system_error_string(save_errno))
                + 1);
            sprintf(tmp, string, globus_libc_system_error_string(save_errno));
            
            return tmp;
        }
        string = _IOSL("a system call failed");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_EOF))
    {
        string = _IOSL("an end-of-file was reached");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IO_CANCELLED))
    {
        string = _IOSL("an I/O operation was cancelled");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IO_FAILED))
    {
        string = _IOSL("an I/O operation failed");
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);

        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);

            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("authentication failed:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("an authentication operation failed");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);

        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);

            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("unauthorized identity:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }

        else
        {
            string = _IOSL("an unauthorized identity");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);

        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);

            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("authorization failed:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("an authorization operation failed");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);

        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);

            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("protection failed:"),
                                                  maj_stat,
                                                  min_stat,
                                                           0);
            return string;
        }
        else
        {
            string = _IOSL("a protection operation failed");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NO_SEC_CONTEXT))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);

        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);

            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("no security context:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("no security context");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_CONTEXT_EXPIRED))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);
            
        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);
            
            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("security context expired:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("a security context expired");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_CREDENTIALS_EXPIRED))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);
            
        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);
            
            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("credential expired:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("a security credential expired");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NO_CREDENTIALS))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);
            
        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);
            
            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("no credentials:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("no credentials");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_CREDENTIALS))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);
            
        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);
            
            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("invalid credentials:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("invalid credentials");
        }
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED))
    {
        OM_uint32 maj_stat;
        OM_uint32 min_stat;

        maj_stat = globus_io_error_security_failed_get_maj_stat(error);
            
        if(GSS_ERROR(maj_stat))
        {
            min_stat = globus_io_error_security_failed_get_min_stat(error);
            
            globus_gss_assist_display_status_str (&string,
                                                  _IOSL("security failure:"),
                                                  maj_stat,
                                                  min_stat,
                                                  0);
            return string;
        }
        else
        {
            string = _IOSL("a security operation failed");
        }
    }
    else
    {
        string = _IOSL("an unknown error occurred");
    }

    return globus_libc_strdup(string);
}

/* the following code all generated by running the script
 * ./globus_error_hierarchy.h.sh definitions globus_io_error_hierarchy.idl
 */

typedef struct globus_io_error_security_failed_instance_s {
  globus_io_handle_t *   handle;
  int   maj_stat;
  int   min_stat;
  int   token_stat;
} globus_io_error_security_failed_instance_t;

static globus_io_error_security_failed_instance_t *
globus_l_io_error_security_failed_instance_data (globus_object_t *error)
{
  globus_io_error_security_failed_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_security_failed_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_security_failed_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->handle = NULL;
    instance_data->maj_stat = -1;
    instance_data->min_stat = -1;
    instance_data->token_stat = -1;
    return instance_data;
  }
}

static void globus_l_io_error_security_failed_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_security_failed_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_security_failed_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_security_failed_instance_t));
  dst = ((globus_io_error_security_failed_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->handle = src->handle;
  dst->maj_stat = src->maj_stat;
  dst->min_stat = src->min_stat;
  dst->token_stat = src->token_stat;
}

static void globus_l_io_error_security_failed_destroy (void *datavp)
{
  globus_io_error_security_failed_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_security_failed_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BASE_DEFINITION),
        globus_l_io_error_security_failed_copy,
        globus_l_io_error_security_failed_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern globus_object_t *
globus_io_error_construct_security_failed (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED);

  error = globus_io_error_initialize_security_failed (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern globus_object_t *
globus_io_error_initialize_security_failed (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_io_error_security_failed_set_handle (error, handle);
  globus_io_error_security_failed_set_maj_stat (error, maj_stat);
  globus_io_error_security_failed_set_min_stat (error, min_stat);
  globus_io_error_security_failed_set_token_stat (error, token_stat);

  return globus_io_error_initialize_base (
    error,
    source,
    cause);
}

/* return the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern globus_io_handle_t *
globus_io_error_security_failed_get_handle (globus_object_t * error)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->handle);
  }
  else return NULL;
}

/* set the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern void
globus_io_error_security_failed_set_handle (
    globus_object_t * error,
    globus_io_handle_t * value)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    instance_data->handle = value;
  }
}

/* return the maj_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern int
globus_io_error_security_failed_get_maj_stat (globus_object_t * error)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->maj_stat);
  }
  else return -1;
}

/* set the maj_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern void
globus_io_error_security_failed_set_maj_stat (
    globus_object_t * error,
    int value)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    instance_data->maj_stat = value;
  }
}

/* return the min_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern int
globus_io_error_security_failed_get_min_stat (globus_object_t * error)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->min_stat);
  }
  else return -1;
}

/* set the min_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern void
globus_io_error_security_failed_set_min_stat (
    globus_object_t * error,
    int value)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    instance_data->min_stat = value;
  }
}

/* return the token_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern int
globus_io_error_security_failed_get_token_stat (globus_object_t * error)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->token_stat);
  }
  else return -1;
}

/* set the token_stat instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED   */
extern void
globus_io_error_security_failed_set_token_stat (
    globus_object_t * error,
    int value)
{
  globus_io_error_security_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_security_failed_instance_data (error);
  if (instance_data != NULL) {
    instance_data->token_stat = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED   */
extern globus_object_t *
globus_io_error_construct_authentication_failed (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED);

  error = globus_io_error_initialize_authentication_failed (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED   */
extern globus_object_t *
globus_io_error_initialize_authentication_failed (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED   */
extern globus_object_t *
globus_io_error_construct_authorization_failed (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED);

  error = globus_io_error_initialize_authorization_failed (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED   */
extern globus_object_t *
globus_io_error_initialize_authorization_failed (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


typedef struct globus_io_error_unauthorized_identity_instance_s {
  char *   identity;
} globus_io_error_unauthorized_identity_instance_t;

static globus_io_error_unauthorized_identity_instance_t *
globus_l_io_error_unauthorized_identity_instance_data (globus_object_t *error)
{
  globus_io_error_unauthorized_identity_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_unauthorized_identity_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_unauthorized_identity_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->identity = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_unauthorized_identity_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_unauthorized_identity_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_unauthorized_identity_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_unauthorized_identity_instance_t));
  dst = ((globus_io_error_unauthorized_identity_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->identity = src->identity;
}

static void globus_l_io_error_unauthorized_identity_destroy (void *datavp)
{
  globus_io_error_unauthorized_identity_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_unauthorized_identity_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED_DEFINITION),
        globus_l_io_error_unauthorized_identity_copy,
        globus_l_io_error_unauthorized_identity_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY   */
extern globus_object_t *
globus_io_error_construct_unauthorized_identity (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat,
    char * identity)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY);

  error = globus_io_error_initialize_unauthorized_identity (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat,
    identity);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY   */
extern globus_object_t *
globus_io_error_initialize_unauthorized_identity (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat,
    char * identity)
{
  globus_io_error_unauthorized_identity_set_identity (error, identity);

  return globus_io_error_initialize_authorization_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}

/* return the identity instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY   */
extern char *
globus_io_error_unauthorized_identity_get_identity (globus_object_t * error)
{
  globus_io_error_unauthorized_identity_instance_t * instance_data;
  instance_data
   = globus_l_io_error_unauthorized_identity_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->identity);
  }
  else return NULL;
}

/* set the identity instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_UNAUTHORIZED_IDENTITY   */
extern void
globus_io_error_unauthorized_identity_set_identity (
    globus_object_t * error,
    char * value)
{
  globus_io_error_unauthorized_identity_instance_t * instance_data;
  instance_data
   = globus_l_io_error_unauthorized_identity_instance_data (error);
  if (instance_data != NULL) {
    instance_data->identity = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION   */
extern globus_object_t *
globus_io_error_construct_bad_protection (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION);

  error = globus_io_error_initialize_bad_protection (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION   */
extern globus_object_t *
globus_io_error_initialize_bad_protection (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_NO_SEC_CONTEXT_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_NO_SEC_CONTEXT   */
extern globus_object_t *
globus_io_error_construct_no_sec_context (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_NO_SEC_CONTEXT);

  error = globus_io_error_initialize_no_sec_context (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_NO_SEC_CONTEXT   */
extern globus_object_t *
globus_io_error_initialize_no_sec_context (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_CONTEXT_EXPIRED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_CONTEXT_EXPIRED   */
extern globus_object_t *
globus_io_error_construct_context_expired (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_CONTEXT_EXPIRED);

  error = globus_io_error_initialize_context_expired (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_CONTEXT_EXPIRED   */
extern globus_object_t *
globus_io_error_initialize_context_expired (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_CREDENTIALS_EXPIRED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_CREDENTIALS_EXPIRED   */
extern globus_object_t *
globus_io_error_construct_credentials_expired (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_CREDENTIALS_EXPIRED);

  error = globus_io_error_initialize_credentials_expired (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_CREDENTIALS_EXPIRED   */
extern globus_object_t *
globus_io_error_initialize_credentials_expired (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_NO_CREDENTIALS_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_NO_CREDENTIALS   */
extern globus_object_t *
globus_io_error_construct_no_credentials (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_NO_CREDENTIALS);

  error = globus_io_error_initialize_no_credentials (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_NO_CREDENTIALS   */
extern globus_object_t *
globus_io_error_initialize_no_credentials (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_INVALID_CREDENTIALS_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_CREDENTIALS   */
extern globus_object_t *
globus_io_error_construct_invalid_credentials (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_INVALID_CREDENTIALS);

  error = globus_io_error_initialize_invalid_credentials (
    newerror,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_CREDENTIALS   */
extern globus_object_t *
globus_io_error_initialize_invalid_credentials (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int maj_stat,
    int min_stat,
    int token_stat)
{

  return globus_io_error_initialize_security_failed (
    error,
    source,
    cause,
    handle,
    maj_stat,
    min_stat,
    token_stat);
}


typedef struct globus_io_error_io_failed_instance_s {
  globus_io_handle_t *   handle;
} globus_io_error_io_failed_instance_t;

static globus_io_error_io_failed_instance_t *
globus_l_io_error_io_failed_instance_data (globus_object_t *error)
{
  globus_io_error_io_failed_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_IO_FAILED);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_io_failed_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_io_failed_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->handle = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_io_failed_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_io_failed_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_io_failed_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_io_failed_instance_t));
  dst = ((globus_io_error_io_failed_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->handle = src->handle;
}

static void globus_l_io_error_io_failed_destroy (void *datavp)
{
  globus_io_error_io_failed_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_io_failed_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_IO_FAILED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BASE_DEFINITION),
        globus_l_io_error_io_failed_copy,
        globus_l_io_error_io_failed_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_IO_FAILED   */
extern globus_object_t *
globus_io_error_construct_io_failed (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_IO_FAILED);

  error = globus_io_error_initialize_io_failed (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_IO_FAILED   */
extern globus_object_t *
globus_io_error_initialize_io_failed (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_io_error_io_failed_set_handle (error, handle);

  return globus_io_error_initialize_base (
    error,
    source,
    cause);
}

/* return the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_IO_FAILED   */
extern globus_io_handle_t *
globus_io_error_io_failed_get_handle (globus_object_t * error)
{
  globus_io_error_io_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_io_failed_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->handle);
  }
  else return NULL;
}

/* set the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_IO_FAILED   */
extern void
globus_io_error_io_failed_set_handle (
    globus_object_t * error,
    globus_io_handle_t * value)
{
  globus_io_error_io_failed_instance_t * instance_data;
  instance_data
   = globus_l_io_error_io_failed_instance_data (error);
  if (instance_data != NULL) {
    instance_data->handle = value;
  }
}


typedef struct globus_io_error_system_failure_instance_s {
  int   save_errno;
} globus_io_error_system_failure_instance_t;

static globus_io_error_system_failure_instance_t *
globus_l_io_error_system_failure_instance_data (globus_object_t *error)
{
  globus_io_error_system_failure_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_system_failure_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_system_failure_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->save_errno = -1;
    return instance_data;
  }
}

static void globus_l_io_error_system_failure_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_system_failure_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_system_failure_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_system_failure_instance_t));
  dst = ((globus_io_error_system_failure_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->save_errno = src->save_errno;
}

static void globus_l_io_error_system_failure_destroy (void *datavp)
{
  globus_io_error_system_failure_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_system_failure_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_IO_FAILED_DEFINITION),
        globus_l_io_error_system_failure_copy,
        globus_l_io_error_system_failure_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE   */
extern globus_object_t *
globus_io_error_construct_system_failure (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int save_errno)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE);

  error = globus_io_error_initialize_system_failure (
    newerror,
    source,
    cause,
    handle,
    save_errno);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE   */
extern globus_object_t *
globus_io_error_initialize_system_failure (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle,
    int save_errno)
{
  globus_io_error_system_failure_set_save_errno (error, save_errno);

  return globus_io_error_initialize_io_failed (
    error,
    source,
    cause,
    handle);
}

/* return the save_errno instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE   */
extern int
globus_io_error_system_failure_get_save_errno (globus_object_t * error)
{
  globus_io_error_system_failure_instance_t * instance_data;
  instance_data
   = globus_l_io_error_system_failure_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->save_errno);
  }
  else return -1;
}

/* set the save_errno instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE   */
extern void
globus_io_error_system_failure_set_save_errno (
    globus_object_t * error,
    int value)
{
  globus_io_error_system_failure_instance_t * instance_data;
  instance_data
   = globus_l_io_error_system_failure_instance_data (error);
  if (instance_data != NULL) {
    instance_data->save_errno = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_EOF_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_IO_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_EOF   */
extern globus_object_t *
globus_io_error_construct_eof (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_EOF);

  error = globus_io_error_initialize_eof (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_EOF   */
extern globus_object_t *
globus_io_error_initialize_eof (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_io_failed (
    error,
    source,
    cause,
    handle);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_IO_CANCELLED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_IO_FAILED_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_IO_CANCELLED   */
extern globus_object_t *
globus_io_error_construct_io_cancelled (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_IO_CANCELLED);

  error = globus_io_error_initialize_io_cancelled (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_IO_CANCELLED   */
extern globus_object_t *
globus_io_error_initialize_io_cancelled (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_io_failed (
    error,
    source,
    cause,
    handle);
}


typedef struct globus_io_error_bad_parameter_instance_s {
  char *   name;
  int   position;
  char *   function;
} globus_io_error_bad_parameter_instance_t;

static globus_io_error_bad_parameter_instance_t *
globus_l_io_error_bad_parameter_instance_data (globus_object_t *error)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_bad_parameter_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_bad_parameter_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->name = NULL;
    instance_data->position = -1;
    instance_data->function = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_bad_parameter_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_bad_parameter_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_bad_parameter_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_bad_parameter_instance_t));
  dst = ((globus_io_error_bad_parameter_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->name = src->name;
  dst->position = src->position;
  dst->function = src->function;
}

static void globus_l_io_error_bad_parameter_destroy (void *datavp)
{
  globus_io_error_bad_parameter_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_bad_parameter_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BASE_DEFINITION),
        globus_l_io_error_bad_parameter_copy,
        globus_l_io_error_bad_parameter_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern globus_object_t *
globus_io_error_construct_bad_parameter (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER);

  error = globus_io_error_initialize_bad_parameter (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern globus_object_t *
globus_io_error_initialize_bad_parameter (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_io_error_bad_parameter_set_name (error, name);
  globus_io_error_bad_parameter_set_position (error, position);
  globus_io_error_bad_parameter_set_function (error, function);

  return globus_io_error_initialize_base (
    error,
    source,
    cause);
}

/* return the name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern char *
globus_io_error_bad_parameter_get_name (globus_object_t * error)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->name);
  }
  else return NULL;
}

/* set the name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern void
globus_io_error_bad_parameter_set_name (
    globus_object_t * error,
    char * value)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    instance_data->name = value;
  }
}

/* return the position instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern int
globus_io_error_bad_parameter_get_position (globus_object_t * error)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->position);
  }
  else return -1;
}

/* set the position instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern void
globus_io_error_bad_parameter_set_position (
    globus_object_t * error,
    int value)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    instance_data->position = value;
  }
}

/* return the function instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern char *
globus_io_error_bad_parameter_get_function (globus_object_t * error)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->function);
  }
  else return NULL;
}

/* set the function instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER   */
extern void
globus_io_error_bad_parameter_set_function (
    globus_object_t * error,
    char * value)
{
  globus_io_error_bad_parameter_instance_t * instance_data;
  instance_data
   = globus_l_io_error_bad_parameter_instance_data (error);
  if (instance_data != NULL) {
    instance_data->function = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_BAD_POINTER_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_POINTER   */
extern globus_object_t *
globus_io_error_construct_bad_pointer (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_BAD_POINTER);

  error = globus_io_error_initialize_bad_pointer (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_BAD_POINTER   */
extern globus_object_t *
globus_io_error_initialize_bad_pointer (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_POINTER_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER   */
extern globus_object_t *
globus_io_error_construct_null_parameter (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER);

  error = globus_io_error_initialize_null_parameter (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER   */
extern globus_object_t *
globus_io_error_initialize_null_parameter (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_bad_pointer (
    error,
    source,
    cause,
    name,
    position,
    function);
}


typedef struct globus_io_error_invalid_type_instance_s {
  char *   required_type_string;
} globus_io_error_invalid_type_instance_t;

static globus_io_error_invalid_type_instance_t *
globus_l_io_error_invalid_type_instance_data (globus_object_t *error)
{
  globus_io_error_invalid_type_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_INVALID_TYPE);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_invalid_type_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_invalid_type_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->required_type_string = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_invalid_type_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_invalid_type_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_invalid_type_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_invalid_type_instance_t));
  dst = ((globus_io_error_invalid_type_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->required_type_string = src->required_type_string;
}

static void globus_l_io_error_invalid_type_destroy (void *datavp)
{
  globus_io_error_invalid_type_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_invalid_type_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_INVALID_TYPE_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        globus_l_io_error_invalid_type_copy,
        globus_l_io_error_invalid_type_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_TYPE   */
extern globus_object_t *
globus_io_error_construct_invalid_type (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * required_type_string)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_INVALID_TYPE);

  error = globus_io_error_initialize_invalid_type (
    newerror,
    source,
    cause,
    name,
    position,
    function,
    required_type_string);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_TYPE   */
extern globus_object_t *
globus_io_error_initialize_invalid_type (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * required_type_string)
{
  globus_io_error_invalid_type_set_required_type_string (error, required_type_string);

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}

/* return the required_type_string instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INVALID_TYPE   */
extern char *
globus_io_error_invalid_type_get_required_type_string (globus_object_t * error)
{
  globus_io_error_invalid_type_instance_t * instance_data;
  instance_data
   = globus_l_io_error_invalid_type_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->required_type_string);
  }
  else return NULL;
}

/* set the required_type_string instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INVALID_TYPE   */
extern void
globus_io_error_invalid_type_set_required_type_string (
    globus_object_t * error,
    char * value)
{
  globus_io_error_invalid_type_instance_t * instance_data;
  instance_data
   = globus_l_io_error_invalid_type_instance_data (error);
  if (instance_data != NULL) {
    instance_data->required_type_string = value;
  }
}


typedef struct globus_io_error_immutable_attribute_instance_s {
  char *   attribute_name;
} globus_io_error_immutable_attribute_instance_t;

static globus_io_error_immutable_attribute_instance_t *
globus_l_io_error_immutable_attribute_instance_data (globus_object_t *error)
{
  globus_io_error_immutable_attribute_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_immutable_attribute_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_immutable_attribute_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->attribute_name = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_immutable_attribute_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_immutable_attribute_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_immutable_attribute_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_immutable_attribute_instance_t));
  dst = ((globus_io_error_immutable_attribute_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->attribute_name = src->attribute_name;
}

static void globus_l_io_error_immutable_attribute_destroy (void *datavp)
{
  globus_io_error_immutable_attribute_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_immutable_attribute_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        globus_l_io_error_immutable_attribute_copy,
        globus_l_io_error_immutable_attribute_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE   */
extern globus_object_t *
globus_io_error_construct_immutable_attribute (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * attribute_name)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE);

  error = globus_io_error_initialize_immutable_attribute (
    newerror,
    source,
    cause,
    name,
    position,
    function,
    attribute_name);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE   */
extern globus_object_t *
globus_io_error_initialize_immutable_attribute (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * attribute_name)
{
  globus_io_error_immutable_attribute_set_attribute_name (error, attribute_name);

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}

/* return the attribute_name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE   */
extern char *
globus_io_error_immutable_attribute_get_attribute_name (globus_object_t * error)
{
  globus_io_error_immutable_attribute_instance_t * instance_data;
  instance_data
   = globus_l_io_error_immutable_attribute_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->attribute_name);
  }
  else return NULL;
}

/* set the attribute_name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE   */
extern void
globus_io_error_immutable_attribute_set_attribute_name (
    globus_object_t * error,
    char * value)
{
  globus_io_error_immutable_attribute_instance_t * instance_data;
  instance_data
   = globus_l_io_error_immutable_attribute_instance_data (error);
  if (instance_data != NULL) {
    instance_data->attribute_name = value;
  }
}


typedef struct globus_io_error_attribute_mismatch_instance_s {
  char *   attr1;
  char *   attr2;
} globus_io_error_attribute_mismatch_instance_t;

static globus_io_error_attribute_mismatch_instance_t *
globus_l_io_error_attribute_mismatch_instance_data (globus_object_t *error)
{
  globus_io_error_attribute_mismatch_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_attribute_mismatch_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_attribute_mismatch_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->attr1 = NULL;
    instance_data->attr2 = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_attribute_mismatch_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_attribute_mismatch_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_attribute_mismatch_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_attribute_mismatch_instance_t));
  dst = ((globus_io_error_attribute_mismatch_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->attr1 = src->attr1;
  dst->attr2 = src->attr2;
}

static void globus_l_io_error_attribute_mismatch_destroy (void *datavp)
{
  globus_io_error_attribute_mismatch_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_attribute_mismatch_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        globus_l_io_error_attribute_mismatch_copy,
        globus_l_io_error_attribute_mismatch_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern globus_object_t *
globus_io_error_construct_attribute_mismatch (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * attr1,
    char * attr2)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH);

  error = globus_io_error_initialize_attribute_mismatch (
    newerror,
    source,
    cause,
    name,
    position,
    function,
    attr1,
    attr2);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern globus_object_t *
globus_io_error_initialize_attribute_mismatch (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * attr1,
    char * attr2)
{
  globus_io_error_attribute_mismatch_set_attr1 (error, attr1);
  globus_io_error_attribute_mismatch_set_attr2 (error, attr2);

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}

/* return the attr1 instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern char *
globus_io_error_attribute_mismatch_get_attr1 (globus_object_t * error)
{
  globus_io_error_attribute_mismatch_instance_t * instance_data;
  instance_data
   = globus_l_io_error_attribute_mismatch_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->attr1);
  }
  else return NULL;
}

/* set the attr1 instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern void
globus_io_error_attribute_mismatch_set_attr1 (
    globus_object_t * error,
    char * value)
{
  globus_io_error_attribute_mismatch_instance_t * instance_data;
  instance_data
   = globus_l_io_error_attribute_mismatch_instance_data (error);
  if (instance_data != NULL) {
    instance_data->attr1 = value;
  }
}

/* return the attr2 instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern char *
globus_io_error_attribute_mismatch_get_attr2 (globus_object_t * error)
{
  globus_io_error_attribute_mismatch_instance_t * instance_data;
  instance_data
   = globus_l_io_error_attribute_mismatch_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->attr2);
  }
  else return NULL;
}

/* set the attr2 instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH   */
extern void
globus_io_error_attribute_mismatch_set_attr2 (
    globus_object_t * error,
    char * value)
{
  globus_io_error_attribute_mismatch_instance_t * instance_data;
  instance_data
   = globus_l_io_error_attribute_mismatch_instance_data (error);
  if (instance_data != NULL) {
    instance_data->attr2 = value;
  }
}


typedef struct globus_io_error_invalid_name_instance_s {
  char *   unresolvable_name;
} globus_io_error_invalid_name_instance_t;

static globus_io_error_invalid_name_instance_t *
globus_l_io_error_invalid_name_instance_data (globus_object_t *error)
{
  globus_io_error_invalid_name_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_INVALID_NAME);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_invalid_name_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_invalid_name_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->unresolvable_name = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_invalid_name_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_invalid_name_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_invalid_name_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_invalid_name_instance_t));
  dst = ((globus_io_error_invalid_name_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->unresolvable_name = src->unresolvable_name;
}

static void globus_l_io_error_invalid_name_destroy (void *datavp)
{
  globus_io_error_invalid_name_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_invalid_name_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_INVALID_NAME_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        globus_l_io_error_invalid_name_copy,
        globus_l_io_error_invalid_name_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_NAME   */
extern globus_object_t *
globus_io_error_construct_invalid_name (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * unresolvable_name)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_INVALID_NAME);

  error = globus_io_error_initialize_invalid_name (
    newerror,
    source,
    cause,
    name,
    position,
    function,
    unresolvable_name);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_NAME   */
extern globus_object_t *
globus_io_error_initialize_invalid_name (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * unresolvable_name)
{
  globus_io_error_invalid_name_set_unresolvable_name (error, unresolvable_name);

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}

/* return the unresolvable_name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INVALID_NAME   */
extern char *
globus_io_error_invalid_name_get_unresolvable_name (globus_object_t * error)
{
  globus_io_error_invalid_name_instance_t * instance_data;
  instance_data
   = globus_l_io_error_invalid_name_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->unresolvable_name);
  }
  else return NULL;
}

/* set the unresolvable_name instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INVALID_NAME   */
extern void
globus_io_error_invalid_name_set_unresolvable_name (
    globus_object_t * error,
    char * value)
{
  globus_io_error_invalid_name_instance_t * instance_data;
  instance_data
   = globus_l_io_error_invalid_name_instance_data (error);
  if (instance_data != NULL) {
    instance_data->unresolvable_name = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_INVALID_NAME_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND   */
extern globus_object_t *
globus_io_error_construct_host_not_found (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * unresolvable_name)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND);

  error = globus_io_error_initialize_host_not_found (
    newerror,
    source,
    cause,
    name,
    position,
    function,
    unresolvable_name);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND   */
extern globus_object_t *
globus_io_error_initialize_host_not_found (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function,
    char * unresolvable_name)
{

  return globus_io_error_initialize_invalid_name (
    error,
    source,
    cause,
    name,
    position,
    function,
    unresolvable_name);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_INVALID_PORT_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_PORT   */
extern globus_object_t *
globus_io_error_construct_invalid_port (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_INVALID_PORT);

  error = globus_io_error_initialize_invalid_port (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_INVALID_PORT   */
extern globus_object_t *
globus_io_error_initialize_invalid_port (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_INVALID_PORT_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT   */
extern globus_object_t *
globus_io_error_construct_restricted_port (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT);

  error = globus_io_error_initialize_restricted_port (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT   */
extern globus_object_t *
globus_io_error_initialize_restricted_port (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_invalid_port (
    error,
    source,
    cause,
    name,
    position,
    function);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_PORT_IN_USE_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_INVALID_PORT_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_PORT_IN_USE   */
extern globus_object_t *
globus_io_error_construct_port_in_use (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_PORT_IN_USE);

  error = globus_io_error_initialize_port_in_use (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_PORT_IN_USE   */
extern globus_object_t *
globus_io_error_initialize_port_in_use (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_invalid_port (
    error,
    source,
    cause,
    name,
    position,
    function);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED   */
extern globus_object_t *
globus_io_error_construct_not_initialized (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED);

  error = globus_io_error_initialize_not_initialized (
    newerror,
    source,
    cause,
    name,
    position,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED   */
extern globus_object_t *
globus_io_error_initialize_not_initialized (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * name,
    int position,
    char * function)
{

  return globus_io_error_initialize_bad_parameter (
    error,
    source,
    cause,
    name,
    position,
    function);
}


typedef struct globus_io_error_registration_error_instance_s {
  globus_io_handle_t *   handle;
} globus_io_error_registration_error_instance_t;

static globus_io_error_registration_error_instance_t *
globus_l_io_error_registration_error_instance_data (globus_object_t *error)
{
  globus_io_error_registration_error_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_registration_error_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_registration_error_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->handle = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_registration_error_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_registration_error_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_registration_error_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_registration_error_instance_t));
  dst = ((globus_io_error_registration_error_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->handle = src->handle;
}

static void globus_l_io_error_registration_error_destroy (void *datavp)
{
  globus_io_error_registration_error_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_registration_error_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BASE_DEFINITION),
        globus_l_io_error_registration_error_copy,
        globus_l_io_error_registration_error_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR   */
extern globus_object_t *
globus_io_error_construct_registration_error (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR);

  error = globus_io_error_initialize_registration_error (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR   */
extern globus_object_t *
globus_io_error_initialize_registration_error (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_io_error_registration_error_set_handle (error, handle);

  return globus_io_error_initialize_base (
    error,
    source,
    cause);
}

/* return the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR   */
extern globus_io_handle_t *
globus_io_error_registration_error_get_handle (globus_object_t * error)
{
  globus_io_error_registration_error_instance_t * instance_data;
  instance_data
   = globus_l_io_error_registration_error_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->handle);
  }
  else return NULL;
}

/* set the handle instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR   */
extern void
globus_io_error_registration_error_set_handle (
    globus_object_t * error,
    globus_io_handle_t * value)
{
  globus_io_error_registration_error_instance_t * instance_data;
  instance_data
   = globus_l_io_error_registration_error_instance_data (error);
  if (instance_data != NULL) {
    instance_data->handle = value;
  }
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_construct_read_already_registered (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED);

  error = globus_io_error_initialize_read_already_registered (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_initialize_read_already_registered (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_registration_error (
    error,
    source,
    cause,
    handle);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_construct_write_already_registered (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED);

  error = globus_io_error_initialize_write_already_registered (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_initialize_write_already_registered (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_registration_error (
    error,
    source,
    cause,
    handle);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_construct_except_already_registered (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED);

  error = globus_io_error_initialize_except_already_registered (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_initialize_except_already_registered (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_registration_error (
    error,
    source,
    cause,
    handle);
}


const globus_object_type_t GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR_DEFINITION),
        NULL,
        NULL,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_construct_close_already_registered (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED);

  error = globus_io_error_initialize_close_already_registered (
    newerror,
    source,
    cause,
    handle);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED   */
extern globus_object_t *
globus_io_error_initialize_close_already_registered (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    globus_io_handle_t * handle)
{

  return globus_io_error_initialize_registration_error (
    error,
    source,
    cause,
    handle);
}


typedef struct globus_io_error_internal_error_instance_s {
  char *   function;
} globus_io_error_internal_error_instance_t;

static globus_io_error_internal_error_instance_t *
globus_l_io_error_internal_error_instance_data (globus_object_t *error)
{
  globus_io_error_internal_error_instance_t * instance_data;
  globus_object_t * local_object;

  local_object 
  = globus_object_upcast (error, GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR);

  if (local_object==NULL) return NULL;

  instance_data 
  = ((globus_io_error_internal_error_instance_t *)
     globus_object_get_local_instance_data (local_object));

  if (instance_data!=NULL) return instance_data;
  else {
    instance_data 
    = globus_malloc (sizeof(globus_io_error_internal_error_instance_t));
    globus_object_set_local_instance_data (local_object,
                                           instance_data);

    instance_data->function = NULL;
    return instance_data;
  }
}

static void globus_l_io_error_internal_error_copy (void *srcvp, void **dstvpp)
{
  globus_io_error_internal_error_instance_t *src, *dst;
  if (srcvp==NULL || dstvpp==NULL) return;
  src = ((globus_io_error_internal_error_instance_t *) srcvp);
  (*dstvpp) = globus_malloc (sizeof(globus_io_error_internal_error_instance_t));
  dst = ((globus_io_error_internal_error_instance_t *) (*dstvpp));
  if (dst==NULL) return;
  dst->function = src->function;
}

static void globus_l_io_error_internal_error_destroy (void *datavp)
{
  globus_io_error_internal_error_instance_t *data;
  if (datavp==NULL) return;
  data = ((globus_io_error_internal_error_instance_t *) datavp);
  globus_free (data);
}

const globus_object_type_t GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR_DEFINITION
= globus_error_type_static_initializer (
        (&GLOBUS_IO_ERROR_TYPE_BASE_DEFINITION),
        globus_l_io_error_internal_error_copy,
        globus_l_io_error_internal_error_destroy,
        (globus_i_io_error_string_func));

/* allocate and initialize an error of type
 * GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR   */
extern globus_object_t *
globus_io_error_construct_internal_error (
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * function)
{
  globus_object_t * newerror, * error;
  newerror = globus_object_construct (GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR);

  error = globus_io_error_initialize_internal_error (
    newerror,
    source,
    cause,
    function);

  if (error==NULL) globus_object_free (newerror);

  return error;
}

/* initialize and return an error of type
 * GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR   */
extern globus_object_t *
globus_io_error_initialize_internal_error (
    globus_object_t * error,
    globus_module_descriptor_t * source,
    globus_object_t * cause,
    char * function)
{
  globus_io_error_internal_error_set_function (error, function);

  return globus_io_error_initialize_base (
    error,
    source,
    cause);
}

/* return the function instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR   */
extern char *
globus_io_error_internal_error_get_function (globus_object_t * error)
{
  globus_io_error_internal_error_instance_t * instance_data;
  instance_data
   = globus_l_io_error_internal_error_instance_data (error);
  if (instance_data != NULL) {
    return (instance_data->function);
  }
  else return NULL;
}

/* set the function instance data of an error
 * derived from GLOBUS_IO_ERROR_TYPE_INTERNAL_ERROR   */
extern void
globus_io_error_internal_error_set_function (
    globus_object_t * error,
    char * value)
{
  globus_io_error_internal_error_instance_t * instance_data;
  instance_data
   = globus_l_io_error_internal_error_instance_data (error);
  if (instance_data != NULL) {
    instance_data->function = value;
  }
}


