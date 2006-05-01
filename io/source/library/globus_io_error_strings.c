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
#include <string.h>

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
	    string = "an internal error_occurred in %s";
	    tmp = globus_malloc(strlen(string) + strlen(function)+1);

	    sprintf(tmp, string, function);

	    return tmp;
	}
	string = "an internal error_occurred in globus_io";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED))
    {
	globus_io_handle_t * handle;

	handle = globus_io_error_registration_error_get_handle(error);
	
	if(handle)
	{
	    string = "the handle %p was already registered for reading";
	    tmp = globus_malloc(strlen(string) + 64 + 1);
	    sprintf(tmp, string, handle);

	    return tmp;
	}
	string = "the handle was already registered for reading";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED))
    {
	globus_io_handle_t * handle;

	handle = globus_io_error_registration_error_get_handle(error);
	
	if(handle)
	{
	    string = "the handle %p was already registered for writing";
	    tmp = globus_malloc(strlen(string) + 64 + 1);
	    sprintf(tmp, string, handle);

	    return tmp;
	}
        string = "the handle was already registered for writing";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_EXCEPT_ALREADY_REGISTERED))
    {
	globus_io_handle_t * handle;

	handle = globus_io_error_registration_error_get_handle(error);
	
	if(handle)
	{
	    string = "the handle %p was already registered for exception events";
	    tmp = globus_malloc(strlen(string) + 64 + 1);
	    sprintf(tmp, string, handle);

	    return tmp;
	}
        string = "the handle was already registered for exception events";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED))
    {
	globus_io_handle_t * handle;

	handle = globus_io_error_registration_error_get_handle(error);
	
	if(handle)
	{
	    string = "the handle %p was already registered for closing";
	    tmp = globus_malloc(strlen(string) + 64 + 1);
	    sprintf(tmp, string, handle);

	    return tmp;
	}
        string = "the handle was already registered for closing";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_REGISTRATION_ERROR))
    {
	globus_io_handle_t * handle;

	handle = globus_io_error_registration_error_get_handle(error);
	
	if(handle)
	{
	    string = "a registration operation failed for handle %p";
	    tmp = globus_malloc(strlen(string) + 64 + 1);
	    sprintf(tmp, string, handle);

	    return tmp;
	}
        string = "a registration operation failed";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER))
    {
	int position;
	char * func;

	position = globus_io_error_bad_parameter_get_position(error);
	func = globus_io_error_bad_parameter_get_function(error);
	
	if(func)
	{
	    string = "a NULL parameter was passed as argument %d to %s";
	    tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
	    sprintf(tmp, string, position, func);

	    return tmp;
	}
	string = "a NULL parameter";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_BAD_POINTER))
    {
	int position;
	char * func;

	position = globus_io_error_bad_parameter_get_position(error);
	func = globus_io_error_bad_parameter_get_function(error);
	
	if(func)
	{
	    string = "a bad pointer was passed as argument %d to %s";
	    tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
	    sprintf(tmp, string, position, func);

	    return tmp;
	}
	string = "a bad pointer";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE))
    {
	char * attribute;

	attribute = globus_io_error_immutable_attribute_get_attribute_name(error);
	if(attribute)
	{
	    string = "an attempt to change the immutable attribute %s";
	    
	    tmp = globus_malloc(strlen(string) + strlen(attribute) + 1);

	    sprintf(tmp, string, attribute);

	    return tmp;
	}
	string = "an attempt to change an immutable attribute";
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
	    string = "argument %d to %s should be of type %s\n";
	    
	    tmp = globus_malloc(strlen(string) + strlen(func) + strlen(type_name)+ 1);

	    sprintf(tmp, string, position, func, type_name);

	    return tmp;
	}
	string = "an argument of incorrect type for an operation\n";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_ATTRIBUTE_MISMATCH))
    {
	char * attr1;
	char * attr2;

	attr1 = globus_io_error_attribute_mismatch_get_attr1(error);
	attr2 = globus_io_error_attribute_mismatch_get_attr2(error);

	if(attr1 && attr2)
	{
	    string = "attribute %s is incompatible with %s";

	    tmp = globus_malloc(strlen(string) + strlen(attr1) + strlen(attr2) + 1);
	    sprintf(tmp, string, attr1, attr2);

	    return tmp;
	}
	
	string = "an attempt to apply incompatible attributes";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND))
    {
	char *name;

	name = globus_io_error_invalid_name_get_unresolvable_name(error);

	if(name)
	{
	    string = "the name %s could not be resolved";

	    tmp = globus_malloc(strlen(string) + strlen(name) + 1);

	    sprintf(tmp, string, name);

	    return tmp;
	}
	string = "a host name could not be resolved";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_NAME))
    {
	char *name;

	name = globus_io_error_invalid_name_get_unresolvable_name(error);

	if(name)
	{
	    string = "the name %s could not be used";

	    tmp = globus_malloc(strlen(string) + strlen(name) + 1);

	    sprintf(tmp, string, name);
	}

	string = "a name could not be used";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_RESTRICTED_PORT))
    {
	string = "the process has insufficient permissions to use the desired port";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_PORT_IN_USE))
    {
	string = "the requested port was already in use";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_INVALID_PORT))
    {
	string = "the requested port could not be used";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED))
    {
	int position;
	char * func;

	position = globus_io_error_bad_parameter_get_position(error);
	func = globus_io_error_bad_parameter_get_function(error);
	
	if(func)
	{
	    string = "an uninitialied data structure was passed as argument %d to %s";
	    tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
	    sprintf(tmp, string, position, func);

	    return tmp;
	}
	string = "an uninitialized data structure";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER))
    {
	int position;
	char * func;

	position = globus_io_error_bad_parameter_get_position(error);
	func = globus_io_error_bad_parameter_get_function(error);
	
	if(func)
	{
	    string = "a bad parameter was passed as argument %d to %s";
	    tmp = globus_malloc(strlen(string) + strlen(func) + 64 + 1);
	    sprintf(tmp, string, position, func);

	    return tmp;
	}
	string = "a bad parameter was passed to this function";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE))
    {
	int save_errno;

	save_errno = 
	    globus_io_error_system_failure_get_save_errno(error);

	if(save_errno)
	{
	    string = "a system call failed (%s)";

	    tmp = globus_malloc(
		strlen(string) 
		+ strlen(globus_libc_system_error_string(save_errno))
		+ 1);
	    sprintf(tmp, string, globus_libc_system_error_string(save_errno));
	    
	    return tmp;
	}
	string = "a system call failed";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_EOF))
    {
	string = "an end-of-file was reached";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IO_CANCELLED))
    {
	string = "an I/O operation was cancelled";
    }
    else if(globus_object_type_match(type, GLOBUS_IO_ERROR_TYPE_IO_FAILED))
    {
	string = "an I/O operation failed";
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
						  "authentication failed:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "an authentication operation failed";
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
						  "unauthorized identity:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}

	else
	{
	    string = "an unauthorized identity";
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
						  "authorization failed:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "an authorization operation failed";
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
						  "protection failed:",
						  maj_stat,
						  min_stat,
							   0);
	    return string;
	}
	else
	{
	    string = "a protection operation failed";
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
						  "no security context:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "no security context";
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
						  "security context expired:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "a security context expired";
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
						  "credential expired:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "a security credential expired";
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
						  "no credentials:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "no credentials";
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
						  "invalid credentials:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "invalid credentials";
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
						  "security failure:",
						  maj_stat,
						  min_stat,
						  0);
	    return string;
	}
	else
	{
	    string = "a security operation failed";
	}
    }
    else
    {
	string = "an unknown error occurred";
    }

    return globus_libc_strdup(string);
}

