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

/**********************************************************************

gsigss_glue.c

Description:
	All the GSSAPI functions for a DLL with C calling conventions.
	Designed to work with SecureCRT 2.4 where we told them the wrong
	calling conventions. 

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/
#include <stdio.h>
#include <windows.h>

/* 
 * override the calling conventions, so we can use the C convention
 * as we told the SecureCRT people
 */

#define GSS_CALLCONV  
#define GSS_CALLCONV_C

#include "gssapi.h"

#define COM_CODE(name) static OM_uint32 (__stdcall *function)() = NULL; \
	if (!function) function_init(name, &function);
	

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

static void
function_init(char * name, OM_uint32 (__stdcall **pfunction)());

static OM_uint32 __stdcall
function_error();



/**********************************************************************
                       Define module specific variables
**********************************************************************/
/* we define the oid values here which are required */

static gss_OID_desc  GSS_C_NT_USER_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"};
gss_OID GSS_C_NT_USER_NAME = &GSS_C_NT_USER_NAME_desc;

static gss_OID_desc   GSS_C_NT_MACHINE_UID_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"};
gss_OID GSS_C_NT_MACHINE_UID_NAME = &GSS_C_NT_MACHINE_UID_NAME_desc;

static gss_OID_desc  GSS_C_NT_STRING_UID_NAME_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"};
gss_OID GSS_C_NT_STRING_UID_NAME = &GSS_C_NT_STRING_UID_NAME_desc;

static gss_OID_desc  GSS_C_NT_HOSTBASED_SERVICE_X_desc = 
		{6, (void *)"\x2b\x06\x01\x05\x06\x02"};
gss_OID GSS_C_NT_HOSTBASED_SERVICE_X = &GSS_C_NT_HOSTBASED_SERVICE_X_desc;

static gss_OID_desc  GSS_C_NT_HOSTBASED_SERVICE_desc = 
		{10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"};
gss_OID GSS_C_NT_HOSTBASED_SERVICE = &GSS_C_NT_HOSTBASED_SERVICE_desc;

static gss_OID_desc  GSS_C_NT_ANONYMOUS_desc = 
		{6, (void *)"\x2b\x06\01\x05\x06\x03"};
gss_OID GSS_C_NT_ANONYMOUS = &GSS_C_NT_ANONYMOUS_desc;

static gss_OID_desc  GSS_C_NT_EXPORT_NAME_desc = 
		{6, (void *)"\x2b\x06\x01\x05\x06\x04"};
gss_OID GSS_C_NT_EXPORT_NAME = &GSS_C_NT_EXPORT_NAME_desc;

/*
 * for backwards compatability, also define the V1 constant OID
 * pointing the V2 OIDs. This is done mostly for DLL compatability
 */

gss_OID gss_nt_user_name =        &GSS_C_NT_USER_NAME_desc;
gss_OID gss_nt_machine_uid_name = &GSS_C_NT_MACHINE_UID_NAME_desc;
gss_OID gss_nt_string_uid_name =  &GSS_C_NT_STRING_UID_NAME_desc;
gss_OID gss_nt_service_name = 	  &GSS_C_NT_HOSTBASED_SERVICE_desc;


/* handle of the real gssapi32.dll */
HMODULE gssapi_handle = NULL;

/**************************************************************************************
**************************************************************************************/
static OM_uint32 __stdcall
function_error()
{
    MessageBox(0,"Entry not in the gssapi","GSIGSS32.DLL",IDOK);
    return GSS_S_FAILURE;

}
/**************************************************************************************
**************************************************************************************/static void 
function_init(char * name, OM_uint32 (__stdcall **pfunction)())
{
	long err;
	char buf[256];

	if (!gssapi_handle)
	{
			gssapi_handle = LoadLibrary("gssapi32.dll");
	}
	if (gssapi_handle) 
	{
#ifdef DEBUG
		sprintf(buf,"First call to %s",name);
		MessageBox(0,buf,"GSIGSS32.DLL",IDOK);
#endif
		*pfunction = GetProcAddress(gssapi_handle, name);
	} 
	else
	{
		MessageBox(0,"Could not load gssapi32.dll","GSIGSS32.DLL",IDOK);
	}
	if (!*pfunction)
	{	
		err= GetLastError();
		sprintf(buf, "Error trying to resolve %s rc=%ld", name, err);
		MessageBox(0,buf,"GSIGSS32.DLL",IDOK);
		*pfunction = function_error;
	}
}

/**************************************************************************************
**************************************************************************************/

OM_uint32 GSS_CALLCONV gss_acquire_cred
(OM_uint32 *              minor_status ,
 const gss_name_t         desired_name ,
 OM_uint32                time_req ,
 const gss_OID_set        desired_mechs ,
 gss_cred_usage_t         cred_usage ,
 gss_cred_id_t *          output_cred_handle ,
 gss_OID_set *            actual_mechs ,
 OM_uint32 *              time_rec 
 ) 
{
    COM_CODE("gss_acquire_cred")

    return ( (*function)(minor_status,
				 desired_name,
				 time_req,
				 desired_mechs,
				 cred_usage,
				 output_cred_handle,
				 actual_mechs,
				 time_rec));
}


OM_uint32 GSS_CALLCONV gss_release_cred
(OM_uint32 *              minor_status ,
 gss_cred_id_t *          cred_handle 
) 
{ 
    COM_CODE("gss_release_cred")

    return ( (*function)(minor_status,
				 cred_handle));
}

OM_uint32 GSS_CALLCONV gss_init_sec_context
(OM_uint32 *             minor_status ,
 const gss_cred_id_t     initiator_cred_handle ,
 gss_ctx_id_t *          context_handle ,
 const gss_name_t        target_name ,
 const gss_OID           mech_type ,
 OM_uint32               req_flags ,
 OM_uint32               time_req ,
 const gss_channel_bindings_t  input_chan_bindings ,
 const gss_buffer_t      input_token ,
 gss_OID *               actual_mech_type ,
 gss_buffer_t            output_token ,
 OM_uint32 *             ret_flags ,
 OM_uint32 *             time_rec 
) 
{
    COM_CODE("gss_init_sec_context")

    return ( (*function)(minor_status,
				 initiator_cred_handle,
				 context_handle ,
				 target_name ,
				 mech_type,
				 req_flags,
				 time_req,
				 input_chan_bindings,
				 input_token,
				 actual_mech_type,
				 output_token,
				 ret_flags,
				 time_rec));
}


OM_uint32 GSS_CALLCONV gss_accept_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 const gss_cred_id_t      acceptor_cred_handle ,
 const gss_buffer_t       input_token_buffer ,
 const gss_channel_bindings_t  input_chan_bindings ,
 gss_name_t *             src_name ,
 gss_OID *                mech_type ,
 gss_buffer_t             output_token ,
 OM_uint32 *              ret_flags ,
 OM_uint32 *              time_rec ,
 gss_cred_id_t *          delegated_cred_handle 
) 
{ 
    COM_CODE("gss_accept_sec_context")

    return ( (*function)(minor_status,
				 context_handle,
				 acceptor_cred_handle,
				 input_token_buffer,
				 input_chan_bindings,
				 src_name,
				 mech_type,
				 output_token,
				 ret_flags,
				 time_rec,
				 delegated_cred_handle));
 }


OM_uint32 GSS_CALLCONV gss_process_context_token
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t       token_buffer 
)
{ 
    COM_CODE("gss_process_context_token")

    return ( (*function)(minor_status,
				 context_handle,
				 token_buffer));
}


OM_uint32 GSS_CALLCONV gss_delete_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 gss_buffer_t             output_token 
)
{
    COM_CODE("gss_delete_sec_context")
	
    return ( (*function)(minor_status,
				 context_handle,
				 output_token));
}


OM_uint32 GSS_CALLCONV gss_context_time
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 OM_uint32 *               time_rec 
)
{ 
    COM_CODE("gss_context_time")
    return ( (*function)(minor_status,
				 context_handle,
				 time_rec));
}


OM_uint32 GSS_CALLCONV gss_get_mic
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 gss_qop_t                qop_req ,
 const gss_buffer_t       message_buffer ,
 gss_buffer_t              message_token 
)
{
    COM_CODE("gss_get_mic")

    return ( (*function)(minor_status,
				 context_handle,
				 qop_req,
				 message_buffer,
				 message_token));
}



OM_uint32 GSS_CALLCONV gss_verify_mic
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t       message_buffer ,
 const gss_buffer_t       token_buffer ,
 gss_qop_t *               qop_state 
)
{ 
    
    COM_CODE("gss_verify_mic")

    return ( (*function)(minor_status,
				 context_handle,
				 message_buffer,
				 token_buffer,
				 qop_state));
}



OM_uint32 GSS_CALLCONV gss_wrap
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 int                      conf_req_flag ,
 gss_qop_t                qop_req ,
 const gss_buffer_t       input_message_buffer ,
 int *                    conf_state ,
 gss_buffer_t              output_message_buffer 
) 
{
    COM_CODE("gss_wrap")

    return ( (*function)(minor_status,
				 context_handle,
				 conf_req_flag,
				 qop_req,
				 input_message_buffer,
				 conf_state,
				 output_message_buffer));
}



OM_uint32 GSS_CALLCONV gss_unwrap
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t       input_message_buffer ,
 gss_buffer_t             output_message_buffer ,
 int *                    conf_state ,
 gss_qop_t *               qop_state 
)
{ 
    COM_CODE("gss_unwrap")

    return ( (*function)(minor_status,
				 context_handle,
				 input_message_buffer,
				 output_message_buffer,
				 conf_state,
				 qop_state));
}



OM_uint32 GSS_CALLCONV gss_display_status
(OM_uint32 *              minor_status ,
 OM_uint32                status_value ,
 int                      status_type ,
 const gss_OID            mech_type ,
 OM_uint32 *              message_context ,
 gss_buffer_t              status_string 
) 
{
    COM_CODE("gss_display_status")

    return ( (*function)(minor_status,
				 status_value,
				 status_type,
				 mech_type,
				 message_context,
				 status_string));
}


OM_uint32 GSS_CALLCONV gss_indicate_mechs
(OM_uint32 *              minor_status ,
 gss_OID_set *             mech_set 
)
{ 
    COM_CODE("gss_indicate_mechs")

    return ( (*function)(minor_status,
				 mech_set));
}


OM_uint32 GSS_CALLCONV gss_compare_name
(OM_uint32 *              minor_status ,
 const gss_name_t         name1 ,
 const gss_name_t         name2 ,
 int *                     name_equal 
) 
{ 
    COM_CODE("gss_compare_name")

    return ( (*function)(minor_status,
				 name1,
				 name2,
				 name_equal));
}

 
OM_uint32 GSS_CALLCONV gss_display_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 gss_buffer_t             output_name_buffer ,
 gss_OID *                 output_name_type 
)
{
    COM_CODE("gss_display_name")

    return ( (*function)(minor_status,
				 input_name,
				 output_name_buffer,
				 output_name_type));
}


OM_uint32 GSS_CALLCONV gss_import_name
(OM_uint32 *              minor_status ,
 const gss_buffer_t       input_name_buffer ,
 const gss_OID            input_name_type ,
 gss_name_t *              output_name 
)
{
    COM_CODE("gss_import_name")
    return ( (*function)(minor_status,
				 input_name_buffer,
				 input_name_type,
				 output_name));
}

OM_uint32 GSS_CALLCONV gss_export_name
(OM_uint32  *             minor_status ,
 const gss_name_t         input_name ,
 gss_buffer_t              exported_name 
)
{
    COM_CODE("gss_export_name")

    return ( (*function)(minor_status,
				 input_name,
				 exported_name));
}


OM_uint32 GSS_CALLCONV gss_release_name
(OM_uint32 *              minor_status ,
 gss_name_t *              input_name 
)
{
    COM_CODE("gss_release_name")

    return ( (*function)(minor_status,
				 input_name));
}


OM_uint32 GSS_CALLCONV gss_release_buffer
(OM_uint32 *              minor_status ,
 gss_buffer_t              buffer 
)
{
    COM_CODE("gss_release_buffer")

    return ( (*function)(minor_status,
				 buffer));
}


OM_uint32 GSS_CALLCONV gss_release_oid_set
(OM_uint32 *              minor_status ,
 gss_OID_set *             set 
)
{
    COM_CODE("gss_release_oid_set")

    return ( (*function)(minor_status,
				 set));
}


OM_uint32 GSS_CALLCONV gss_inquire_cred
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      cred_handle ,
 gss_name_t *             name ,
 OM_uint32 *              lifetime ,
 gss_cred_usage_t *       cred_usage ,
 gss_OID_set *             mechanisms 
)
{
    COM_CODE("gss_inquire_cred")
	
    return ( (*function)(minor_status,
				 cred_handle,
				 name,
				 lifetime,
				 cred_usage,
				 mechanisms));
}


OM_uint32 GSS_CALLCONV gss_inquire_context 
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 gss_name_t *             src_name ,
 gss_name_t *             targ_name ,
 OM_uint32 *              lifetime_rec ,
 gss_OID *                mech_type ,
 OM_uint32 *              ctx_flags ,
 int *                    locally_initiated ,
 int *                     open 
)
{
    COM_CODE("gss_inquire_context")
	
    return ( (*function)(minor_status,
				 context_handle,
				 src_name,
				 targ_name,
				 lifetime_rec,
				 mech_type,
				 ctx_flags,
				 locally_initiated,
				 open));
}

 
OM_uint32 GSS_CALLCONV gss_wrap_size_limit 
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 int                      conf_req_flag ,
 gss_qop_t                qop_req ,
 OM_uint32                req_output_size ,
 OM_uint32 *               max_input_size 
)
{
    COM_CODE("gss_wrap_size_limit")

    return ( (*function)(minor_status,
				 context_handle,
				 conf_req_flag,
				 qop_req,
				 req_output_size,
				 max_input_size));
}



OM_uint32 GSS_CALLCONV gss_add_cred 
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      input_cred_handle ,
 const gss_name_t         desired_name ,
 const gss_OID            desired_mech ,
 gss_cred_usage_t         cred_usage ,
 OM_uint32                initiator_time_req ,
 OM_uint32                acceptor_time_req ,
 gss_cred_id_t *          output_cred_handle ,
 gss_OID_set *            actual_mechs ,
 OM_uint32 *              initiator_time_rec ,
 OM_uint32 *               acceptor_time_rec 
)
{
    COM_CODE("gss_add_cred")

    return ( (*function)(minor_status,
				 input_cred_handle,
				 desired_name,
				 desired_mech,
				 cred_usage,
				 initiator_time_req,
				 acceptor_time_req,
				 output_cred_handle,
				 actual_mechs,
				 initiator_time_rec,
				 acceptor_time_req));
}

OM_uint32 GSS_CALLCONV gss_inquire_cred_by_mech 
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      cred_handle ,
 const gss_OID            mech_type ,
 gss_name_t *             name ,
 OM_uint32 *              initiator_lifetime ,
 OM_uint32 *              acceptor_lifetime ,
 gss_cred_usage_t *        cred_usage 
)
{
    COM_CODE("gss_inquire_cred_by_mech")

    return ( (*function)(minor_status,
				 cred_handle,
				 mech_type,
				 name,
				 initiator_lifetime,
				 acceptor_lifetime,
				 cred_usage));
}


OM_uint32 GSS_CALLCONV gss_export_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 gss_buffer_t              interprocess_token 
)
{
    COM_CODE("gss_export_sec_context")

    return ( (*function)(minor_status,
				 context_handle,
				 interprocess_token));
}



OM_uint32 GSS_CALLCONV gss_import_sec_context 
(OM_uint32 *              minor_status ,
 const gss_buffer_t       interprocess_token ,
 gss_ctx_id_t *            context_handle 
)
{
    COM_CODE("gss_import_sec_context")

    return ( (*function)(minor_status,
				 interprocess_token,
				 context_handle));
}


OM_uint32 GSS_CALLCONV gss_create_empty_oid_set
(OM_uint32 *              minor_status ,
 gss_OID_set *             oid_set 
)
{
    COM_CODE("gss_create_empty_oid_set")

    return ( (*function)(minor_status,
				 oid_set));
}

OM_uint32 GSS_CALLCONV gss_add_oid_set_member
(OM_uint32 *              minor_status ,
 const gss_OID            member_oid ,
 gss_OID_set *             oid_set 
)
{
    COM_CODE("gss_add_oid_set_number")

    return ( (*function)(minor_status,
				 member_oid,
				 oid_set));
}

OM_uint32 GSS_CALLCONV gss_test_oid_set_member
(OM_uint32 *              minor_status ,
 const gss_OID            member ,
 const gss_OID_set        set ,
 int *                    present 
)
{
    COM_CODE("gss_test_oid_set_member")

    return ( (*function)(minor_status,
				 member,
				 set,
				 present));
}

OM_uint32 GSS_CALLCONV gss_inquire_names_for_mech
(OM_uint32 *              minor_status ,
 const gss_OID            mechanism ,
 gss_OID_set *            name_types 
)
{
    COM_CODE("gss_inquire_names_for_mech")

    return ( (*function)(minor_status,
				 mechanism,
				 name_types));
}

OM_uint32 GSS_CALLCONV gss_inquire_mechs_for_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 gss_OID_set *            mech_types 
)
{
    COM_CODE("gss_inquire_mechs_for_name")

    return ( (*function)(minor_status,
				 input_name,
				 mech_types));
}

OM_uint32 GSS_CALLCONV gss_canonicalize_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 const gss_OID            mech_type ,
 gss_name_t *             output_name 
)
{
    COM_CODE("gss_canonicalize_name")

    return ( (*function)(minor_status,
				 input_name,
				 mech_type,
				 output_name));
}

OM_uint32 GSS_CALLCONV gss_duplicate_name
(OM_uint32 *              minor_status ,
 const gss_name_t         src_name ,
 gss_name_t *             dest_name 
)
{
    COM_CODE("gss_duplicate_name")

    return ( (*function)(minor_status,
				 src_name,
				 dest_name));
}

OM_uint32 GSS_CALLCONV gss_sign
(OM_uint32 *         minor_status,
 gss_ctx_id_t        context_handle,
 int                 qop_req,
 gss_buffer_t        message_buffer,
 gss_buffer_t        message_token
)
{
    COM_CODE("gss_sign")

    return ( (*function)(minor_status,
				 context_handle,
				 qop_req,
				 message_buffer,
				 message_token));
}

OM_uint32 GSS_CALLCONV gss_verify
(OM_uint32 *        minor_status,
 gss_ctx_id_t       context_handle,
 gss_buffer_t       message_buffer,
 gss_buffer_t       token_buffer,
 int *              qop_state
)
{
    COM_CODE("gss_verify")

    return ( (*function)(minor_status,
				 context_handle,
				 message_buffer,
				 token_buffer,
				 qop_state));
}

OM_uint32 GSS_CALLCONV gss_seal
(OM_uint32 *        minor_status,
 gss_ctx_id_t       context_handle,
 int                conf_req_flag,
 int                qop_req,
 gss_buffer_t       input_message_buffer,
 int *              conf_state,
 gss_buffer_t       output_message_buffer
)
{
    COM_CODE("gss_seal")

    return ( (*function)(minor_status,
				 context_handle,
				 conf_req_flag,
				 qop_req,
				 input_message_buffer,
				 conf_state,
				 output_message_buffer));
}

OM_uint32 GSS_CALLCONV gss_unseal
(OM_uint32 *        minor_status,
 gss_ctx_id_t       context_handle,
 gss_buffer_t       input_message_buffer,
 gss_buffer_t       output_message_buffer,
 int *              conf_state,
 int *              qop_state
)
{
    COM_CODE("gss_unseal")

    return ( (*function)(minor_status,
				 context_handle,
				 input_message_buffer,
				 output_message_buffer,
				 conf_state,
				 qop_state));
}

