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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_io_attr.c Globus I/O toolset (attribute definitions)
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

/**
 * RCS Identification of this source file
 */

static char *rcsid = "$Header$";

#endif

/*
 * Include header files
 */
#include "globus_l_io.h"
#include "globus_error_string.h"

/*
 * Module Specific Prototypes
 */
static
void
globus_l_io_socketattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data);

static
void
globus_l_io_socketattr_destroy(
    void *				instance_data);

static
void
globus_l_io_securesocketattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data);

static
void
globus_l_io_securesocketattr_destroy(
    void *				instance_data);

static
void
globus_l_io_tcpattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data);

static
void
globus_l_io_tcpattr_destroy(
    void *				instance_data);

static
void
globus_l_io_udpattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data);

static
void
globus_l_io_udpattr_destroy(
    void *				instance_data);

static
void
globus_l_io_fileattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data);

static
void
globus_l_io_fileattr_destroy(
    void *				instance_data);

/*
 * Global Constants
 */
const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_BASE_ATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_OBJECT_TYPE_BASE /* parent */,
	    GLOBUS_NULL /* data copy function */,
	    GLOBUS_NULL /* data destroy function */,
	    GLOBUS_NULL /* class data */);

const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_SOCKETATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_IO_OBJECT_TYPE_BASE_ATTR /* parent */,
	    globus_l_io_socketattr_copy /* data copy function */,
	    globus_l_io_socketattr_destroy /* data destroy function */,
	    GLOBUS_NULL /* class data */);

const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_IO_OBJECT_TYPE_SOCKETATTR /* parent */,
	    globus_l_io_securesocketattr_copy /* data copy function */,
	    globus_l_io_securesocketattr_destroy /* data destroy function */,
	    GLOBUS_NULL /* class data */);

const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_TCPATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR /* parent */,
	    globus_l_io_tcpattr_copy /* data copy function */,
	    globus_l_io_tcpattr_destroy /* data destroy function */,
	    GLOBUS_NULL /* class data */);

const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_UDPATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR /* parent */,
	    globus_l_io_udpattr_copy /* data copy function */,
	    globus_l_io_udpattr_destroy /* data destroy function */,
	    GLOBUS_NULL /* class data */);

const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_FILEATTR_DEFINITION =
	globus_object_type_static_initializer(
	    GLOBUS_IO_OBJECT_TYPE_BASE_ATTR /* parent */,
	    globus_l_io_fileattr_copy /* data copy function */,
	    globus_l_io_fileattr_destroy /* data destroy function */,
	    GLOBUS_NULL /* class data */);
/*
 * Module Specific Variables
 */
static globus_i_io_socketattr_instance_t globus_l_io_socketattr_default;
static globus_i_io_securesocketattr_instance_t
		globus_l_io_securesocketattr_default;
static globus_i_io_tcpattr_instance_t globus_l_io_tcpattr_default;
static globus_i_io_udpattr_instance_t globus_l_io_udpattr_default;
static globus_i_io_fileattr_instance_t globus_l_io_fileattr_default;

void
globus_i_io_attr_activate(void)
{
    /* socket level options */
    globus_l_io_socketattr_default.reuseaddr = GLOBUS_FALSE;
    globus_l_io_socketattr_default.keepalive = GLOBUS_FALSE;
    globus_l_io_socketattr_default.linger = GLOBUS_FALSE;
    globus_l_io_socketattr_default.linger_time = 0;
    globus_l_io_socketattr_default.oobinline = GLOBUS_FALSE;
    globus_l_io_socketattr_default.sndbuf = 0;
    globus_l_io_socketattr_default.rcvbuf = 0;
    
    globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE);
    globus_l_io_socketattr_default.space = GLOBUS_CALLBACK_GLOBAL_SPACE;

    /* secure socket layer options */
    globus_l_io_securesocketattr_default.authentication_mode =
	GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE;
    globus_l_io_securesocketattr_default.authorization_mode =
	GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE;
    globus_l_io_securesocketattr_default.channel_mode =
	GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR;
    globus_l_io_securesocketattr_default.protection_mode =
	GLOBUS_IO_SECURE_PROTECTION_MODE_NONE;
    globus_l_io_securesocketattr_default.delegation_mode =
	GLOBUS_IO_SECURE_DELEGATION_MODE_NONE;
    globus_l_io_securesocketattr_default.proxy_mode =
        GLOBUS_IO_SECURE_PROXY_MODE_NONE;
    globus_l_io_securesocketattr_default.credential =
	GSS_C_NO_CREDENTIAL;
    globus_l_io_securesocketattr_default.authorized_identity =
	GLOBUS_NULL;
    globus_l_io_securesocketattr_default.auth_callback =
	GLOBUS_NULL;
    globus_l_io_securesocketattr_default.auth_callback_arg =
	GLOBUS_NULL;
    globus_l_io_securesocketattr_default.extension_oids =
	GSS_C_NO_OID_SET;    

    /* tcp options */
    globus_l_io_tcpattr_default.nodelay = GLOBUS_FALSE;
    globus_l_io_tcpattr_default.restrict_port = GLOBUS_TRUE;
    memcpy(globus_l_io_tcpattr_default.interface_addr, "000.000.000.000", 16);
    
    /* udp options */ 
    globus_l_io_udpattr_default.connected = GLOBUS_FALSE;
    globus_l_io_udpattr_default.reuse = GLOBUS_FALSE;
    globus_l_io_udpattr_default.mc_loop = GLOBUS_FALSE;
    globus_l_io_udpattr_default.mc_ttl = 1;
    globus_l_io_udpattr_default.mc_enabled = GLOBUS_FALSE;
    globus_l_io_udpattr_default.address = GLOBUS_NULL;
    globus_l_io_udpattr_default.interface_addr = INADDR_ANY;
    globus_l_io_udpattr_default.restrict_port = GLOBUS_TRUE;

    /* file options */
    globus_l_io_fileattr_default.file_type = GLOBUS_IO_FILE_TYPE_BINARY;
}

/**
 * @name Callback Spaces
 * */
/* @{ */
/**
 * globus_io_attr_set_callback_space
 * @anchor globus_io_attr_set_callback_space_anchor
 * @ingroup attr
 *
 * Use this to associate a callback space with a globus_io_handle_t.  When
 * a space is associated with a globus io handle, all callbacks that are 
 * delivered on that handle are only delivered to the supplied callback space.
 * This function takes a refernce to the passed space.  In order for that space
 * to ever be freed, this attr must be destroyed when its use is complete.
 *
 * The default is for callbacks to go to the 'global' space, 
 * GLOBUS_CALLBACK_GLOBAL_SPACE.
 *
 * This attr only applies to socket attrs,  file attrs are ignored.
 *
 * @param attr
 *        attr to associate space with
 *
 * @param space
 *        a callback space handle, previously initialized with
 *        globus_callback_space_init
 *
 * @return
 *        - Error on invalid space or null attr
 *        - GLOBUS_SUCCESS
 *
 * @see 
 * @htmlonly
 * <a class="el" href="../../globus_common/html/group__globus__callback__spaces.html">
 *    Globus Callback Spaces
 * </a>
 * @endhtmlonly
 */

globus_result_t 
globus_io_attr_set_callback_space( 
    globus_io_attr_t *                  attr, 
    globus_callback_space_t             space)
{
    globus_object_t *                   socketattr;
    globus_i_io_socketattr_instance_t * instance;
    globus_result_t                     result;
    static char *                       myname =
        "globus_io_attr_set_callback_space";
        
    if(attr == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_not_initialized(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
 
    socketattr = globus_object_upcast(
        attr->attr, GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
        
    if(socketattr == GLOBUS_NULL)
    {
        /* ignore for other attrs */
        return GLOBUS_SUCCESS;
    }

    instance = (globus_i_io_socketattr_instance_t *)
        globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_bad_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
    
    result = globus_callback_space_reference(space);
    
    if(result == GLOBUS_SUCCESS)
    {
        /* destroy reference to previous space */
        globus_callback_space_destroy(instance->space);
    
        instance->space = space;
    }
    
    return result;
}

/**
 * globus_io_attr_get_callback_space
 * @ingroup attr
 *
 * Use this to get the callback space associated with a globus_io_attr_t. 
 * Note: you are NOT given a reference to the space passed back.
 * should you need one, call globus_callback_space_reference()
 *
 * @param attr
 *        attr to associate space with
 *
 * @param space
 *        storage for a callback space handle, result will be stored here
 *
 * @return
 *        - Error on null attrs
 *        - GLOBUS_SUCCESS
 *
 * @see 
 * @htmlonly
 * <a class="el" href="../../globus_common/html/group__globus__callback__spaces.html">
 *    Globus Callback Spaces
 * </a>
 * @endhtmlonly
 */

globus_result_t 
globus_io_attr_get_callback_space( 
    globus_io_attr_t *                  attr, 
    globus_callback_space_t *           space)
{
    globus_object_t *                   socketattr;
    globus_i_io_socketattr_instance_t * instance;
    static char *                       myname =
        "globus_io_attr_get_callback_space";
    
    if(attr == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
    if(space == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "space",
                2,
                myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_not_initialized(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
    
    socketattr = globus_object_upcast(
        attr->attr, GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
        
    if(socketattr == GLOBUS_NULL)
    {
        /* ignore for other attr types */
        *space = GLOBUS_CALLBACK_GLOBAL_SPACE;
        return GLOBUS_SUCCESS;
    }

    instance = (globus_i_io_socketattr_instance_t *)
        globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_bad_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }
    
    *space = instance->space;
    return GLOBUS_SUCCESS;
}
/* @} */


void
globus_i_io_set_callback_space(
    globus_io_handle_t *		handle,
    globus_callback_space_t             space)
{
    handle->socket_attr.space = space;
}

void
globus_i_io_get_callback_space(
    globus_io_handle_t *		handle,
    globus_callback_space_t *           space)
{
    *space = handle->socket_attr.space;
}

/****************************************************************
 *                      NETLOGGER
 *                      ---------
 ***************************************************************/

/*
 *  Associate NetLogger handle with globus_io_attr
 */
globus_result_t
globus_io_attr_netlogger_set_handle(
    globus_io_attr_t *                       attr,
    globus_netlogger_handle_t *              nl_handle)
{
    static char *                            myname=
                             "globus_io_attr_set_netlogger_handle";

    if(nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    }
    if(attr == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                myname));
    }

    /*
     *  make sure netlogger is active
     */
    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    attr->nl_handle = nl_handle;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_write(
    globus_netlogger_handle_t *              nl_handle,
    const char *                             event,
    const char *                             id,
    const char *                             level,
    const char *                             tag)
{
    struct globus_netlogger_handle_s *       s_nl_handle;
    static char *                            myname=
        "globus_netlogger_write";

    if(nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    }

    if(event == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "event",
                2,
                myname));
    }

    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    s_nl_handle = *nl_handle;
    if(s_nl_handle == GLOBUS_NULL ||
       s_nl_handle->nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] This netlogger handle has not been activated.",
                       GLOBUS_IO_MODULE->module_name));
    }

    /*
     *  may want to add a netlogger vprintf type thing
     *  to netlogger api to make this more efficient/user friendly
     */
#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        outstr_len = strlen(s_nl_handle->main_str) + 1;
        if(level != GLOBUS_NULL)
        { 
            outstr_len += strlen(" LVL=") + strlen(level) + 1;
        }
        if(tag != GLOBUS_NULL)
        {
            outstr_len += strlen(tag);
        }
        if(id != GLOBUS_NULL)
        {
            outstr_len += strlen(" ID=") + strlen(id);
        }
        if(s_nl_handle->desc != GLOBUS_NULL)
        {
            outstr_len += strlen(" SOCK_DESC=") + strlen(s_nl_handle->desc);
        }
        outstr = (char *)globus_malloc(outstr_len);
        /*
         * apparently strcpy is much faster than sprintf
         */
        strcpy(outstr, s_nl_handle->main_str);
        if(level != GLOBUS_NULL)
        { 
            strcat(outstr, " LVL=");
            strcat(outstr, level);
        }
        if(id != GLOBUS_NULL)
        {
            strcat(outstr, " ID=");
            strcat(outstr, id);
        }
        if(s_nl_handle->desc != GLOBUS_NULL)
        {
            strcat(outstr, " SOCK_DESC=");
            strcat(outstr, s_nl_handle->desc);
        }
        if(tag != GLOBUS_NULL)
        {
            strcat(outstr, " ");
            strcat(outstr, tag);
        }

        rc = NetLoggerWrite(
                 s_nl_handle->nl_handle,
                 (char *)event,
                 (char *)outstr,
                 "");
        if(rc != 1)
        {
            return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLoggerWrite failed.",
                       GLOBUS_IO_MODULE->module_name));
        }
    }
#   endif

    return GLOBUS_SUCCESS;
}

/*
 *  netlogger handle init
 */
globus_result_t
globus_netlogger_handle_init(
    globus_netlogger_handle_t *              gnl_handle,
    const char *                             hostname,
    const char *                             progname,
    const char *                             pid)
{
    struct globus_netlogger_handle_s *       s_gnl_handle;
    char *                                   main_str;
    int                                      ms_len = 0;
    static char *                            myname=
        "globus_netlogger_handle_init";

    if(gnl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nl_handle",
                1,
                myname));
    }

    if(hostname == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "hostname",
                3,
                myname));
    }

    if(progname == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "progname",
                4,
                myname));
    }

    /*
     *  make sure netlogger is active
     */
    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    s_gnl_handle = globus_malloc(sizeof(struct globus_netlogger_handle_s));
    *gnl_handle = s_gnl_handle;

    s_gnl_handle->nl_handle = GLOBUS_NULL;
#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        s_gnl_handle->nl_handle = NetLoggerOpen((char *)progname, NULL, NL_ENV);
        if(s_gnl_handle->nl_handle == GLOBUS_NULL)
        {
            return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger failed to open handle.",
                       GLOBUS_IO_MODULE->module_name));
        }
    }
#   else
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not built in.",
                       GLOBUS_IO_MODULE->module_name));
    }
#   endif

    ms_len = 1;
    if(pid != GLOBUS_NULL)
    {
        ms_len += strlen("PID=") + strlen(pid) + 1;
        s_gnl_handle->pid = globus_libc_strdup(pid);
    }
    main_str = (char *)globus_malloc(ms_len);
    main_str[0] = '\0';
    if(pid != GLOBUS_NULL)
    {
        strcat(main_str, " PID=");
        strcat(main_str, pid);
    }
    s_gnl_handle->hostname = globus_libc_strdup(hostname);
    s_gnl_handle->progname = globus_libc_strdup(progname);
    s_gnl_handle->main_str = main_str;
    s_gnl_handle->desc = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

/*
 *  netlogger handle destroy
 */

globus_result_t
globus_netlogger_handle_destroy(
    globus_netlogger_handle_t *              gnl_handle)
{
    struct globus_netlogger_handle_s *       s_gnl_handle;
    static char *                            myname=
        "globus_netlogger_handle_destroy";

    if(gnl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "gnl_handle",
                1,
                myname));
    }

    /*
     *  make sure netlogger is active
     */

    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    s_gnl_handle = *gnl_handle;

    if(s_gnl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger handle has not been initialized.",
                       GLOBUS_IO_MODULE->module_name));
    }
#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        NetLoggerClose(s_gnl_handle->nl_handle);
    }
#   endif
    if(s_gnl_handle->hostname != NULL)
    {
        free(s_gnl_handle->hostname);
    }
    if(s_gnl_handle->progname != NULL)
    {
        free(s_gnl_handle->progname);
    }
    if(s_gnl_handle->pid != NULL)
    {
        free(s_gnl_handle->pid);
    }
    if(s_gnl_handle->main_str != NULL)
    {
        free(s_gnl_handle->main_str);
    }
    if(s_gnl_handle->desc != NULL)
    {
        free(s_gnl_handle->desc);
    }

    globus_free(s_gnl_handle);
    *gnl_handle = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

/*
 *  copy a handle
 */
globus_result_t
globus_io_attr_netlogger_copy_handle(
    globus_netlogger_handle_t *              src,
    globus_netlogger_handle_t *              dst)
{
    struct globus_netlogger_handle_s *       s_gnl_handle;
    struct globus_netlogger_handle_s *       d_gnl_handle;

    static char *                            myname=
        "globus_io_attr_netlogger_copy_handle";

    if(src == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "src",
                1,
                myname));
    }

    if(dst == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "dst",
                2,
                myname));
    }

    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    s_gnl_handle = *src;

    d_gnl_handle = globus_malloc(sizeof(struct globus_netlogger_handle_s));
    *dst = d_gnl_handle;

    d_gnl_handle->nl_handle = s_gnl_handle->nl_handle;
    if(s_gnl_handle->hostname != GLOBUS_NULL)
    {
        d_gnl_handle->hostname = globus_libc_strdup(s_gnl_handle->hostname);
    }
    if(s_gnl_handle->progname != GLOBUS_NULL)
    {
        d_gnl_handle->progname = globus_libc_strdup(s_gnl_handle->progname);
    }
    if(s_gnl_handle->main_str != GLOBUS_NULL)
    {
        d_gnl_handle->main_str = globus_libc_strdup(s_gnl_handle->main_str);
    }
    if(s_gnl_handle->pid != GLOBUS_NULL)
    {
        d_gnl_handle->pid = globus_libc_strdup(s_gnl_handle->pid);
    }
    if(s_gnl_handle->desc != GLOBUS_NULL)
    {
        d_gnl_handle->desc = globus_libc_strdup(s_gnl_handle->desc);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_set_desc(
    globus_netlogger_handle_t *              nl_handle,
    char *                                   desc)
{
    struct globus_netlogger_handle_s *       s_nl_handle;
    static char *                            myname=
                                        "globus_netlogger_set_desc";

    if(nl_handle == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nl_handle",
                1,
                myname));
    }
    if(desc == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "desc",
                2,
                myname));
    }

    /*
     *  make sure netlogger is active
     */
    if(!g_globus_i_io_use_netlogger)
    {
        return globus_error_put(
                   globus_error_construct_string(
                       GLOBUS_IO_MODULE,
                       GLOBUS_NULL,
                       "[%s] NetLogger is not enabled.",
                       GLOBUS_IO_MODULE->module_name));
    }

    s_nl_handle = *nl_handle;
    if(s_nl_handle->desc != GLOBUS_NULL)
    {
        free(s_nl_handle->desc);
    }
    s_nl_handle->desc = globus_libc_strdup(desc);

    return GLOBUS_SUCCESS;
}

/* end NETLOGGER code */


/*
 * Function:	globus_i_io_fileattr_construct()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_FILEATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_object_t *
globus_i_io_fileattr_construct(void)
{
    globus_object_t *			obj;
    globus_result_t			result;
    
    obj = globus_object_construct(GLOBUS_IO_OBJECT_TYPE_FILEATTR);
    if(obj == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    
    result = globus_i_io_fileattr_initialize(obj);
    if(result != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    return obj;
    
  error_exit:
    globus_object_free(obj);
    return GLOBUS_NULL;    
}
/* globus_i_io_fileattr_construct() */

/*
 * Function:	globus_i_io_fileattr_initialize()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_FILEATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_fileattr_initialize(
    globus_object_t *			obj)
{
    globus_i_io_fileattr_instance_t *	instance;

    globus_assert(
	globus_object_get_type(obj) == GLOBUS_IO_OBJECT_TYPE_FILEATTR);
    
    globus_l_io_fileattr_copy(&globus_l_io_fileattr_default,
			      (void **) &instance);
    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
                 globus_io_error_construct_system_failure(
		         GLOBUS_IO_MODULE,
                         GLOBUS_NULL,
	                 GLOBUS_NULL,
		         EAGAIN));

    }

    globus_object_set_local_instance_data(
	obj,
	(void *) instance);

    return globus_i_io_attr_initialize(
	globus_object_upcast(obj,
			     GLOBUS_IO_OBJECT_TYPE_BASE_ATTR));    
}
/* globus_i_io_fileattr_initialize() */

/*
 * Function:	globus_i_io_tcpattr_construct()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_TCPATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_object_t *
globus_i_io_tcpattr_construct(void)
{
    globus_object_t *			obj;
    globus_result_t			result;
    
    obj = globus_object_construct(GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(obj == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    
    result = globus_i_io_tcpattr_initialize(obj);
    if(result != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    return obj;
    
  error_exit:
    globus_object_free(obj);
    return GLOBUS_NULL;    
}
/* globus_i_io_tcpattr_construct() */

/*
 * Function:	globus_i_io_tcpattr_initialize()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_TCPATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_tcpattr_initialize(
    globus_object_t *			obj)
{
    globus_i_io_tcpattr_instance_t *	instance;

    globus_assert(
	globus_object_get_type(obj) == GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    
    globus_l_io_tcpattr_copy(&globus_l_io_tcpattr_default,
			     (void **) &instance);
    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
                 globus_io_error_construct_system_failure(
		         GLOBUS_IO_MODULE,
                         GLOBUS_NULL,
	                 GLOBUS_NULL,
		         EAGAIN));
    }

    globus_object_set_local_instance_data(
	obj,
	(void *) instance);

    return globus_i_io_securesocketattr_initialize(
	globus_object_upcast(obj,
			     GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR));
    
}
/* globus_i_io_tcpattr_initialize() */

/*
 * Function:	globus_i_io_udpattr_construct()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_UDPATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_object_t *
globus_i_io_udpattr_construct(void)
{
    globus_object_t *			obj;
    globus_result_t			result;
    
    obj = globus_object_construct(GLOBUS_IO_OBJECT_TYPE_UDPATTR);
    if(obj == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    
    result = globus_i_io_udpattr_initialize(obj);
    if(result != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    return obj;
    
  error_exit:
    globus_object_free(obj);
    return GLOBUS_NULL;    
}

/*
 * Function:	globus_i_io_udpattr_initialize()
 *
 * Description:	
 *		Construct an object of type GLOBUS_IO_OBJECT_TYPE_UDPATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_udpattr_initialize(
    globus_object_t *			obj)
{
    globus_i_io_udpattr_instance_t *	instance;

    globus_assert(
	globus_object_get_type(obj) == GLOBUS_IO_OBJECT_TYPE_UDPATTR);
    
    globus_l_io_udpattr_copy(&globus_l_io_udpattr_default,
			     (void **) &instance);
    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
                 globus_io_error_construct_system_failure(
		         GLOBUS_IO_MODULE,
                         GLOBUS_NULL,
	                 GLOBUS_NULL,
		         EAGAIN));
    }

    globus_object_set_local_instance_data(
	obj,
	(void *) instance);

    instance->connected = GLOBUS_FALSE;
    instance->reuse = GLOBUS_FALSE;
    instance->mc_loop = GLOBUS_TRUE;
    instance->restrict_port = GLOBUS_TRUE;
    instance->mc_ttl = 1;
    instance->mc_enabled = GLOBUS_FALSE;
    instance->address = GLOBUS_NULL;
    instance->interface_addr = INADDR_ANY;

    return globus_i_io_securesocketattr_initialize(
	globus_object_upcast(obj,
			     GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR));
} 

/*
 * Function:	globus_i_io_socketattr_initialize()
 *
 * Description:	
 *		Construct an object of type
 *			GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_securesocketattr_initialize(
    globus_object_t *			obj)
{
    globus_i_io_securesocketattr_instance_t *
					instance;

    globus_assert(
	globus_object_get_type(obj) == GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    globus_l_io_securesocketattr_copy(&globus_l_io_securesocketattr_default,
				      (void **) &instance);
    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
                 globus_io_error_construct_system_failure(
		         GLOBUS_IO_MODULE,
                         GLOBUS_NULL,
	                 GLOBUS_NULL,
		         EAGAIN));
    }
    globus_object_set_local_instance_data(
	obj,
	(void *) instance);

    return globus_i_io_socketattr_initialize(
	globus_object_upcast(obj,
			     GLOBUS_IO_OBJECT_TYPE_SOCKETATTR));    
}
/* globus_i_io_securesocketattr_initialize() */

/*
 * Function:	globus_i_io_socketattr_intialize()
 *
 * Description:	
 *		Construct an object of type
 *			GLOBUS_IO_OBJECT_TYPE_SOCKETATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_socketattr_initialize(
    globus_object_t *			obj)
{
    globus_i_io_socketattr_instance_t *	instance;

    globus_assert(
	globus_object_get_type(obj) == GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);

    globus_l_io_socketattr_copy(&globus_l_io_socketattr_default,
				(void **) &instance);
    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
                 globus_io_error_construct_system_failure(
		         GLOBUS_IO_MODULE,
                         GLOBUS_NULL,
	                 GLOBUS_NULL,
		         EAGAIN));
    }
    
    globus_object_set_local_instance_data(
	obj,
	(void *) instance);

    return globus_i_io_attr_initialize(
	globus_object_upcast(obj,
			     GLOBUS_IO_OBJECT_TYPE_BASE_ATTR));
}
/* globus_i_io_socketattr_initialize() */

/*
 * Function:	globus_i_io_attr_initialize()
 *
 * Description:	
 *		Construct an object of type
 *			GLOBUS_IO_OBJECT_TYPE_ATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
globus_result_t
globus_i_io_attr_initialize(
    globus_object_t *			obj)
{
    return GLOBUS_SUCCESS;
}
/* globus_i_io_attr_initialize() */

/*
 * globus_l_io_fileattr_copy()
 *
 * Copy the instance data of a fileattr object
 *
 * Parameters:
 *
 *     src_instance_data - pointer to the instance data to be copied
 *
 *     dst_instance_data - pointer to the location to store the address of the
 *     freshly copied instance data
 *
 * Returns:
 *
 *     none
 */
static
void
globus_l_io_fileattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data)
{
    globus_assert(dst_instance_data != GLOBUS_NULL);
    
    *dst_instance_data =
	globus_malloc(sizeof(globus_i_io_fileattr_instance_t));

    if(*dst_instance_data != GLOBUS_NULL)
    {
	memcpy(*dst_instance_data,
	       src_instance_data,
	       sizeof(globus_i_io_fileattr_instance_t));
    }
}
/* globus_l_io_fileattr_copy() */


/*
 * globus_l_io_fileattr_destroy()
 *
 * Destroy any instance data associated with a fileattr object
 *
 * Parameters:
 *
 *     instance_data - pointer to the instance data which needs to be freed
 *
 * Returns:
 *
 *     none
 */
static
void
globus_l_io_fileattr_destroy(
    void *				instance_data)
{
    if(instance_data)
    {
	globus_free(instance_data);
    }
}
/* globus_l_io_fileattr_destroy() */


/*
 * Function:	globus_l_io_tcpattr_copy()
 *
 * Description:	
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_tcpattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data)
{
    globus_assert(dst_instance_data != GLOBUS_NULL);
    
    *dst_instance_data =
	globus_malloc(sizeof(globus_i_io_tcpattr_instance_t));

    if(*dst_instance_data)
    {
	memcpy(*dst_instance_data,
	       src_instance_data,
	       sizeof(globus_i_io_tcpattr_instance_t));
    }
}
/* globus_l_io_tcpattr_copy() */

/*
 * Function:	globus_i_io_tcpattr_destroy()
 *
 * Description:	
 *		Construct an object of type
 *			GLOBUS_IO_OBJECT_TYPE_ATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_tcpattr_destroy(
    void *				instance_data)
{
    if(instance_data != GLOBUS_NULL)
    {
	globus_free(instance_data);
    }
}
/* globus_l_io_tcpattr_destroy() */

/*
 * Function:	globus_l_io_udpattr_copy()
 *
 * Description:	
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_udpattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data)
{
    globus_assert(dst_instance_data != GLOBUS_NULL);
    
    *dst_instance_data =
	globus_malloc(sizeof(globus_i_io_udpattr_instance_t));

    if(*dst_instance_data)
    {
	memcpy(*dst_instance_data,
	       src_instance_data,
	       sizeof(globus_i_io_udpattr_instance_t));
    }
}
/* globus_l_io_udpattr_copy() */

/*
 * Function:	globus_i_io_udpattr_destroy()
 *
 * Description:	
 *		Construct an object of type
 *			GLOBUS_IO_OBJECT_TYPE_ATTR
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_udpattr_destroy(
    void *				instance_data)
{
    if(instance_data != GLOBUS_NULL)
    {
	globus_free(instance_data);
    }
}
/* globus_l_io_udpattr_destroy() */

/*
 * Function:	globus_l_io_securesocketattr_copy()
 *
 * Description:	
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_securesocketattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data)
{
    globus_assert(dst_instance_data != GLOBUS_NULL);
    
    *dst_instance_data =
	globus_malloc(sizeof(globus_i_io_securesocketattr_instance_t));

    if(*dst_instance_data)
    {
	globus_i_io_securesocketattr_instance_t *
					src_inst;
	globus_i_io_securesocketattr_instance_t *
					dest_inst;

	memcpy(*dst_instance_data,
	       src_instance_data,
	       sizeof(globus_i_io_securesocketattr_instance_t));
	src_inst = (globus_i_io_securesocketattr_instance_t *)
	    src_instance_data;
	dest_inst = (globus_i_io_securesocketattr_instance_t *)
	    dst_instance_data;
	
	if(src_inst->authorized_identity != GLOBUS_NULL)
	{
	    dest_inst->authorized_identity =
		globus_libc_strdup(src_inst->authorized_identity);
	}	
    }
}
/* globus_l_io_securesocketattr_copy */

/*
 * Function:	globus_l_io_securesocketattr_destroy()
 *
 * Description:	
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_securesocketattr_destroy(
    void *				instance_data)
{
    globus_i_io_securesocketattr_instance_t *
					attr;

    attr = (globus_i_io_securesocketattr_instance_t *) instance_data;
    
    if(instance_data)
    {
	if(attr->authorized_identity)
	{
	    globus_free(attr->authorized_identity);
	}
	globus_free(instance_data);
    }
}
/* globus_l_io_securesocketattr_destroy() */

/*
 * Function:	globus_l_io_socketattr_copy()
 *
 * Description:	 
 *		Copy the instance data of a socketattr
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_socketattr_copy(
    void *				src_instance_data,
    void **				dst_instance_data)
{
    globus_i_io_socketattr_instance_t *	instance;
    
    globus_assert(dst_instance_data != GLOBUS_NULL);
    
    *dst_instance_data =
	globus_malloc(sizeof(globus_i_io_socketattr_instance_t));

    if(*dst_instance_data)
    {
	memcpy(*dst_instance_data,
	       src_instance_data,
	       sizeof(globus_i_io_socketattr_instance_t));
	
	instance = (globus_i_io_socketattr_instance_t *) *dst_instance_data;
	globus_callback_space_reference(instance->space);
    }
}
/* globus_l_io_socketattr_copy() */

/*
 * Function:	globus_l_io_socketattr_destroy()
 *
 * Description:	
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_io_socketattr_destroy(
    void *				instance_data)
{
    globus_i_io_socketattr_instance_t *	instance;
    
    if(instance_data)
    {
        instance = (globus_i_io_socketattr_instance_t *) instance_data;
        
        globus_callback_space_destroy(instance->space);
        
	globus_free(instance_data);
    }
}
/* globus_l_io_socketattr_destroy() */

/**
 * @name File Type
 * */
/* @{ */
/**
 * Set/Query the file-type attribute in the specified attribute set.
 * @ingroup attr
 *
 * Set the file type attribute in the specified attribute set. This
 * attribute is used to choose whether the file is opened in text or
 * binary mode on systems where those are different. This attribute
 * may not be applied to an existing file handle.
 *
 * @param attr
 *        The attributes to query or modify.
 * @param file_type
 *        The new value of the file type.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O file attribute structure.
 *
 * @see globus_io_fileattr_init()
 */
globus_result_t
globus_io_attr_set_file_type(
    globus_io_attr_t *			attr,
    globus_io_file_type_t		file_type)
{
    globus_object_t *			fileattr;
    globus_i_io_fileattr_instance_t *	instance;
    static char *			myname=
	"globus_io_attr_set_file_type";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    fileattr = globus_object_upcast(attr->attr,
				    GLOBUS_IO_OBJECT_TYPE_FILEATTR);
    if(fileattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_FILEATTR"));
    }

    instance = (globus_i_io_fileattr_instance_t *)
	globus_object_get_local_instance_data(fileattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->file_type = file_type;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_file_type() */

globus_result_t
globus_io_attr_get_file_type(
    globus_io_attr_t *			attr,
    globus_io_file_type_t *		file_type)
{
    globus_object_t *			fileattr;
    globus_i_io_fileattr_instance_t *	instance;
    static char *			myname=
	"globus_io_attr_get_file_type";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if(file_type == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"file_type",
		2,
		myname));
    }

    fileattr = globus_object_upcast(attr->attr,
				    GLOBUS_IO_OBJECT_TYPE_FILEATTR);
    if(fileattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_FILEATTR"));
    }

    instance = (globus_i_io_fileattr_instance_t *)
	globus_object_get_local_instance_data(fileattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *file_type = instance->file_type;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_file_type() */
/* @} */

/**
 * @name TCP Port Restriction
 */
/* @{ */
/**
 * Set/Query the restrict-port attribute in the specified TCP attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to use the 
 * GLOBUS_TCP_PORT_RANGE environment variable to choose an anonymous
 * port for a TCP listener handle. This attribute may not be applied to
 * an existing TCP handle.
 *
 * @param attr
 *        The attribute to query or modify. The @a attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param restrict_port
 *        The new value of the restrict_port attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init()
 */
globus_result_t
globus_io_attr_set_tcp_restrict_port(
    globus_io_attr_t *			attr,
    globus_bool_t			restrict_port)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_tcp_restrict_port";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    tcpattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->restrict_port = restrict_port;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_tcp_restrict_port() */

globus_result_t
globus_io_attr_get_tcp_restrict_port(
    globus_io_attr_t *			attr,
    globus_bool_t *			restrict_port)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_tcp_restrict_port";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(restrict_port == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"restrict_port",
		2,
		myname));
    }
    
    tcpattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *restrict_port = instance->restrict_port;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_tcp_restrict_port() */
/* @} */

/**
 * @name Reuse address
 */
/* @{ */
/**
 * Set/Query the reuse-addr attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to allow reuse
 * of addresses when binding a socket to a port number.
 *
 * @param attr
 *        The attribute to query. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param reuseaddr
 *        The value of the reuse-addr attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP
 *         attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_socket_reuseaddr(
    globus_io_attr_t *			attr,
    globus_bool_t			reuseaddr)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname="globus_io_attr_set_socket_reuseaddr";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
#   if defined(TARGET_ARCH_CYGWIN)
    {
	/*
	 * Under SunOS4.1, NeXTStep and Cygnus Win32, there apparently is a bug
	 * in this.  With this option set, a bind() will succeed on a port even
	 * if that port is still in active use by another process.
	 */
	if(reuseaddr)
	{
	    return globus_error_put(
		globus_io_error_construct_immutable_attribute(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "reuseaddr"));
	}
    }
#   endif
    instance->reuseaddr = reuseaddr;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_socket_reuseaddr() */

globus_result_t
globus_io_attr_get_socket_reuseaddr(
    globus_io_attr_t *			attr,
    globus_bool_t *			reuseaddr)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_socket_reuseaddr";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(reuseaddr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"reuseaddr",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *reuseaddr = instance->reuseaddr;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_reuseaddr() */
/* @} */

/**
 * @name Socket Keepalive
 */
/* @{ */
/**
 * Set/Query the keepalive attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to periodically
 * send "keepalive" messages on a connected socket handle. This may
 * enable earlier detection of broken connections.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param keepalive
 *        The value of the keepalive attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP attribute
 *         structure.
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init() 
 */
globus_result_t
globus_io_attr_set_socket_keepalive(
    globus_io_attr_t *			attr,
    globus_bool_t			keepalive)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_socket_keepalive";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    instance->keepalive = keepalive;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_socket_keepalive() */

globus_result_t
globus_io_attr_get_socket_keepalive(
    globus_io_attr_t *			attr,
    globus_bool_t *			keepalive)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname="globus_io_attr_get_socket_keepalive";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(keepalive == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"keepalive",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *keepalive = instance->keepalive;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_keepalive() */
/* @} */

/**
 * @name Socket Linger
 */
/* @{ */
/**
 * Set/Query the linger attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine what to do when data is in 
 * the socket's buffer when the socket is closed. If linger is
 * set to true, then the close operation will block until the socket
 * buffers are empty, or the linger_time has expired.
 *
 * @param attr
 *        The attribute to query. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param linger
 *        The value of the linger attribute.
 * @param linger_time
 *        The time (in seconds) to block at close time
 *        if linger is true and data is queued in the socket buffer.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_socket_linger(
    globus_io_attr_t *			attr,
    globus_bool_t			linger,
    int					linger_time)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_socket_linger";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    instance->linger = linger;
    instance->linger_time = linger_time;

    return GLOBUS_SUCCESS;    
}
/* globus_io_attr_set_socket_linger() */

globus_result_t
globus_io_attr_get_socket_linger(
    globus_io_attr_t *			attr,
    globus_bool_t *			linger,
    int *				linger_time)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_socket_linger";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(linger == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"linger",
		2,
		myname));
    }
    if(linger_time == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"linger_time",
		3,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *linger = instance->linger;
    *linger_time = instance->linger_time;

    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_linger() */
/* @} */

/**
 * @name Out of Band Data Handling
 */
/* @{ */
/**
 * Set/Query the oobinline attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to choose whether out-of-band data is
 * received in the normal data queue, or must be received specially
 * by calling globus_io_recv() or globus_io_register_recv() with the
 * MSG_OOB flag set to true.
 *
 * @param attr
 *        The attribute to query. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param oobline
 *        The value of the oobinline attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP attribute
 *         structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_socket_oobinline(
    globus_io_attr_t *			attr,
    globus_bool_t			oobinline)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_socket_oobinline";
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
 
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->oobinline = oobinline;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_socket_oobinline() */

globus_result_t
globus_io_attr_get_socket_oobinline(
    globus_io_attr_t *			attr,
    globus_bool_t *			oobinline)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname="globus_io_attr_get_socket_oobinline";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(oobinline == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"oobinline",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *oobinline = instance->oobinline;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_oobinline() */
/* @} */

/**
 * @name Socket Send Buffer
 */
/* @{ */
/**
 * Set/Query the sndbuf attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to choose the size of the send buffer
 * for the socket handle this attribute is applied to. The send buffer
 * is often used by the operating system to choose the appropriate
 * TCP window size.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param sndbuf
 *        The value of the send buffer in bytes.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP attribute
 *         structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_socket_sndbuf(
    globus_io_attr_t *			attr,
    int                                 sndbuf)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_socket_sndbuf";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->sndbuf = sndbuf;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_socket_sndbuf() */

globus_result_t
globus_io_attr_get_socket_sndbuf(
    globus_io_attr_t *			attr,
    int *                               sndbuf)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_socket_sndbuf";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(sndbuf == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"sndbuf",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *sndbuf = instance->sndbuf;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_sndbuf() */
/* @} */

/**
 * @name Socket Receive Buffer
 */
/* @{ */
/**
 * Set/Query the rcvbuf attribute in the specified attribute set.
 * @ingroup attr
 *
 * This attribute is used to choose the size of the receive buffer for
 * the socket handle this attribute is applied to. The receive buffer
 * is often used by the operating system to choose the appropriate TCP
 * window size.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init() or globus_io_udpattr_init().
 * @param rcvbf
 *        The value of the receive buffer in bytes.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP or UDP
 *         attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_socket_rcvbuf(
    globus_io_attr_t *			attr,
    int                                 rcvbuf)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_socket_rcvbuf";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->rcvbuf = rcvbuf;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_socket_rcvbuf() */

globus_result_t
globus_io_attr_get_socket_rcvbuf(
    globus_io_attr_t *			attr,
    int *                               rcvbuf)
{
    globus_object_t *			socketattr;
    globus_i_io_socketattr_instance_t *	instance;
    static char *			myname="globus_io_attr_get_socket_rcvbuf";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(rcvbuf== GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"rcvbuf",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    socketattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
    if(socketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
    }

    instance = (globus_i_io_socketattr_instance_t *)
	globus_object_get_local_instance_data(socketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *rcvbuf = instance->rcvbuf;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_socket_rcvbuf() */
/* @} */

/**
 * @name TCP No delay
 */
/* @{ */
/**
 * Set/Query the nodelay attribute in the specified TCP attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to disable
 * Nagle's algorithm. If set to GLOBUS_TRUE, the socket will send
 * packets as soon as possible with no unnecessary delays introduced.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param nodelay
 *        The new value of the nodelay attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init()
 */
globus_result_t
globus_io_attr_set_tcp_nodelay(
    globus_io_attr_t *			attr,
    globus_bool_t			nodelay)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_set_tcp_nodelay";
    
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    tcpattr = globus_object_upcast(attr->attr,
				   GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    instance->nodelay = nodelay;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_tcp_nodelay() */

globus_result_t
globus_io_attr_get_tcp_nodelay(
    globus_io_attr_t *			attr,
    globus_bool_t *			nodelay)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_tcp_nodelay";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(nodelay == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"nodelay",
		2,
		myname));
    }
    
    tcpattr = globus_object_upcast(attr->attr,
				   GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *nodelay = instance->nodelay;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_tcp_nodelay() */
/* @} */

/**
 * @name TCP Interface
 */
/* @{ */
/**
 * Set/Query the tcp interface attribute in the specified TCP attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether to bind TCP sockets to a
 * particular interface. This attribute must be set before calling
 * globus_io_tcp_create_listener() or globus_io_tcp_connect().
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param interface_addr
 *        The value of the interface attribute. The interface string must
 *        be in dotted-ip format (ie "127.0.0.1").
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init()
 */
globus_result_t
globus_io_attr_set_tcp_interface(
    globus_io_attr_t * attr,
    const char * interface_addr)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    unsigned int			address[4];
    static char *			myname=
	                                "globus_io_attr_set_tcp_interface";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    tcpattr = globus_object_upcast(attr->attr,
				   GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(sscanf(interface_addr, "%u.%u.%u.%u",
              &address[0], &address[1], &address[2], &address[3]) != 4)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"interface_addr",
		2,
		myname));
    }

    sprintf((char *)instance->interface_addr, "%u.%u.%u.%u",
            address[0], address[1], address[2], address[3]);

    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_tcp_interface() */

globus_result_t
globus_io_attr_get_tcp_interface(
    globus_io_attr_t * attr,
    char ** interface_addr)
{
    globus_object_t *			tcpattr;
    globus_i_io_tcpattr_instance_t *	instance;
    static char *			myname=
	                                "globus_io_attr_get_tcp_interface";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(interface_addr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"interface_addr",
		2,
		myname));
    }

    *interface_addr = GLOBUS_NULL;
    tcpattr = globus_object_upcast(attr->attr,
				   GLOBUS_IO_OBJECT_TYPE_TCPATTR);
    if(tcpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(tcpattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(instance->interface_addr[0] != 0)
    {
        *interface_addr = globus_libc_malloc(16);
        memcpy(*interface_addr, &instance->interface_addr[0], 16);
    }
    else
    {
        *interface_addr = GLOBUS_NULL;
    }
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_tcp_interface() */
/* @} */

/**
 * @name Authentication Mode
 */
/* @{ */
/**
 * Set/Query the authentication mode attribute in the specified socket
 * attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to call the
 * GSSAPI security context establishment functions once a socket
 * connection is established.
 *
 * If the authentication_mode value is
 * GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE, then the channel mode,
 * delegation mode, protection mode, and authorization mode will all be reset
 * to disable all security on the socket attribute set.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The value of the authentication-mode attribute. The 
 *        values for mode are described in the documentation for the
 *        #globus_io_secure_authentication_mode_t type.
 * @param credential
 *        A GSSAPI credential to be used when
 *        authenticating. If the credential is equal to GSS_C_NO_CREDENTIAL,
 *        then Globus I/O will use the process's default credentials.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_authorization_mode_t
 */
globus_result_t
globus_io_attr_set_secure_authentication_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authentication_mode_t
					mode,
    gss_cred_id_t			credential)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_set_secure_authentication_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
	instance->channel_mode = GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR;
	instance->delegation_mode = GLOBUS_IO_SECURE_DELEGATION_MODE_NONE;
        instance->proxy_mode = GLOBUS_IO_SECURE_PROXY_MODE_NONE;
	instance->protection_mode = GLOBUS_IO_SECURE_PROTECTION_MODE_NONE;
	instance->authorization_mode = GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE;
	instance->authentication_mode = mode;
	instance->credential = GSS_C_NO_CREDENTIAL;
    }
    else
    {
	instance->authentication_mode = mode;
	instance->credential = credential;	
	if(credential == GSS_C_NO_CREDENTIAL)
	{
	    instance->internal_credential = GLOBUS_TRUE;
	}
	else
	{
	    instance->internal_credential = GLOBUS_FALSE;
	}
        
        if(mode == GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS)
        {
            instance->authorization_mode =
                GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY;
            instance->authorized_identity =
                globus_libc_strdup("<anonymous>");
        }
    }
    
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_authentication_mode() */

globus_result_t
globus_io_attr_get_secure_authentication_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authentication_mode_t *
					mode,
    gss_cred_id_t *			credential)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_authentication_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    if(credential == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"credential",
		3,
		myname));
    }
    
    securesocketattr =
	globus_object_upcast(
	    attr->attr,
	    GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);

    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    *mode = instance->authentication_mode;
    *credential = instance->credential;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_authentication_mode() */
/* @} */

/**
 * @name Authorization Mode
 */
/* @{ */
/**
 * Set/Query the authorization-mode attribute in the specified socket
 * attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine what security identities to
 * authorize as the peer to the security handshake done when making
 * an authenticated connection.
 *
 * @param attr
 *        The attribute to modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The new value of the authorization-mode attribute. The 
 *        values for mode are described in the documentation for the
 *        globus_io_secure_authorization_mode_t type.
 * @param data
 *        A globus_io_secure_authorization_data_t structure
 *        containing any additional information necessary to perform the
 *        specified type of authorization.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_authorization_mode_t
 */
globus_result_t
globus_io_attr_set_secure_authorization_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authorization_mode_t
					mode,
    globus_io_secure_authorization_data_t *
					data)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    char *				old_identity = GLOBUS_NULL;
    static char *			myname=
	                                "globus_io_attr_set_secure_authorizationn_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if((instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE) ||
       (instance->authentication_mode ==
        GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS &&
        mode == GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF))
    {
	    return globus_error_put(
		globus_io_error_construct_attribute_mismatch(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "authentication_mode",
		    "authorization_mode"));
    }
    if(instance->authorization_mode ==
       GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY)
    {
	old_identity = instance->authorized_identity;
    }
    switch(mode)
    {
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
	instance->authorization_mode = mode;
	instance->authorized_identity = GLOBUS_NULL;
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
	if(data->identity == GLOBUS_NULL)
	{
	    return globus_error_put(
		globus_io_error_construct_not_initialized(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "data",
		    3,
		    myname));
	}
	else
	{
	    instance->authorization_mode = mode;
	    instance->authorized_identity = globus_libc_strdup(data->identity);
	}
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
	if(data->callback == GLOBUS_NULL)
	{
	    return globus_error_put(
		globus_io_error_construct_not_initialized(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "data",
		    3,
		    myname));
	}
	else
	{
	    instance->authorization_mode = mode;
	    instance->auth_callback = data->callback;
	    
	    instance->auth_callback_arg = data->callback_arg;
	    instance->authorized_identity = GLOBUS_NULL;
	}
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
      default:
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"authentication_mode",
		"authorization_mode"));
    }
    
    if(old_identity != GLOBUS_NULL)
    {
	globus_free(old_identity);
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_authorization_mode() */

globus_result_t
globus_io_attr_get_secure_authorization_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authorization_mode_t *
					mode,
    globus_io_secure_authorization_data_t *
					data)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_authorization_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		3,
		myname));
    }

    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    *mode = instance->authorization_mode;
    
    switch(instance->authorization_mode)
    {
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
	data->identity = globus_libc_strdup(instance->authorized_identity);
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
	data->callback = instance->auth_callback;
	data->callback_arg = instance->auth_callback_arg;
	break;
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_authorization_mode() */
/* @} */

/**
 * @name Authorization Data
 */
/* @{ */
/** 
 * Initialize a data structure to hold authorization-mode specific
 * data. This function must be called before any of the data accessors 
 * for this structure can be used.
 *
 * @param data The data structure to initialize.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data parameter was GLOBUS_NULL.
 *
 * @see globus_io_secure_authorization_data_destroy()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_get_identity()
 * @see globus_io_secure_authorization_data_set_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_initialize(
    globus_io_secure_authorization_data_t *
					data)
{
    static char *			myname =
	"globus_io_secure_authorization_data_initialize";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    
    data->identity = GLOBUS_NULL;
    data->callback = GLOBUS_NULL;
    data->callback_arg = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_io_secure_authorization_data_initialize() */

/** 
 * Free a data structure used previously to hold authorization-mode specific
 * data. This function must be after the data structure is no longer
 * being used to free memory allocated by setting it's member data.
 *
 * @param data The data structure to free. Once this function returns, 
 * the data structure must not be used until another call to
 * globus_io_secure_authorization_data_initialize() is made with this
 * structure.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data parameter was GLOBUS_NULL.
 *
 * @see globus_io_secure_authorization_data_initialize()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_get_identity()
 * @see globus_io_secure_authorization_data_set_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_destroy(
    globus_io_secure_authorization_data_t *
					data)
{
    static char *			myname="globus_io_secure_authorization_data_destroy";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    
    if(data->identity)
    {
	globus_free(data->identity);
    }
    
    data->identity = GLOBUS_NULL;
    data->callback = GLOBUS_NULL;
    data->callback_arg = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_io_secure_authorization_data_destroy() */

/** 
 * Set the "identity" member of the authorization-mode specific data
 * structure. This member should be set to a string containing the
 * security distinguished name of the peer which you will authorize
 * for this connection. The identity is only when the
 * authorization-mode attribute is set to
 * GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY.
 *
 * @param data The data structure previously initialized by a call to
 * globus_io_secure_authorization_data_initialize().
 * @param identity The string naming the security identity to authorize.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data or identity parameter was GLOBUS_NULL.
 *
 * @see globus_io_secure_authorization_data_initialize()
 * @see globus_io_secure_authorization_data_destroy()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_get_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_set_identity(
    globus_io_secure_authorization_data_t *
					data,
    char *				identity)
{
    static char *			myname="globus_io_secure_authorization_data_set_identity";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    if(identity == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"identity",
		2,
		myname));
    }
    if(data->identity != GLOBUS_NULL)
    {
	globus_free(data->identity);
    }
    
    data->identity = globus_libc_strdup(identity);

    return GLOBUS_SUCCESS;
}


/** 
 * Query the "identity" member of the authorization-mode specific data
 * structure. This member is set by a call to
 * globus_io_secure_authorization_mode_set_identity.
 *
 * @param data The data structure previously initialized by a call to
 * globus_io_secure_authorization_data_initialize().
 * @param identity A pointer to hold a copy of the identity string
 * set in the data structure.
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data or identity parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The identity member of the data structure was not initialized by a
 * call to globus_io_secure_authorization_mode_set_identity.
 *
 * @see globus_io_secure_authorization_data_initialize()
 * @see globus_io_secure_authorization_data_destroy()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_set_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_get_identity(
    globus_io_secure_authorization_data_t *
					data,
    char **				identity)
{
    static char *			myname="globus_io_secure_authorization_data_get_identity";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    if(identity == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"identity",
		2,
		myname));
    }
    if(data->identity == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }

    *identity = globus_libc_strdup(data->identity);

    return GLOBUS_SUCCESS;    
}
/* globus_io_secure_authorization_data_get_identity() */

/** 
 * Set the callback and callback-arg members of the authorization-mode
 * specific data structure. This member is used when setting the 
 * authorization-mode attribute of a TCP attribute set to
 * GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK in a call to 
 * globus_io_attr_set_secure_authorization_mode().
 *
 * @param data The data structure previously initialized by a call to
 * globus_io_secure_authorization_data_initialize().
 * @param callback The new value of the callback member.
 * @param callback_arg The new value of the callback-arg member.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data or identity parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The callback member of the data structure was not initialized by a
 * call to globus_io_secure_authorization_mode_set_identity.
 *
 * @see globus_io_secure_authorization_data_initialize()
 * @see globus_io_secure_authorization_data_destroy()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_secure_authorization_data_get_identity()
 * @see globus_io_secure_authorization_data_set_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_set_callback(
    globus_io_secure_authorization_data_t *
					data,
    globus_io_secure_authorization_callback_t
					callback,
    void *				callback_arg)
{
    static char *			myname="globus_io_secure_authorization_data_set_callback";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    if(callback == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"callback",
		2,
		myname));
    }
   
    data->callback = callback;
    data->callback_arg = callback_arg;

    return GLOBUS_SUCCESS;    
}
/* globus_io_secure_authorization_data_set_callback() */

/** 
 * Query the callback and callback-arg members of the authorization-mode
 * specific data structure. This member is set by a call to the
 * function globus_io_secure_authorization_data_set_callback().
 *
 * @param data The data structure previously initialized by a call to
 * globus_io_secure_authorization_data_initialize().
 * @param callback A pointer to the hold the current value of the
 * callback in the data structure.
 * @param callback_arg A pointer to the hold the current value of the
 * callback-arg in the data structure.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The data or identity parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The callback member of the data structure was not initialized by a
 * call to globus_io_secure_authorization_mode_set_identity.
 *
 * @see globus_io_secure_authorization_data_initialize()
 * @see globus_io_secure_authorization_data_destroy()
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_get_identity()
 * @see globus_io_secure_authorization_data_set_identity()
 * @ingroup attr
 */
globus_result_t
globus_io_secure_authorization_data_get_callback(
    globus_io_secure_authorization_data_t *
					data,
    globus_io_secure_authorization_callback_t *
					callback,
    void **				callback_arg)
{
    static char *			myname="globus_io_secure_authorization_data_get_callback";

    if(data == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    if(callback == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"callback",
		2,
		myname));
    }
    if(callback_arg == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"callback_arg",
		3,
		myname));
    }
    if(data->callback == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"data",
		1,
		myname));
    }
    
    *callback = data->callback;
    *callback_arg = data->callback_arg;

    return GLOBUS_SUCCESS;    
}
/* globus_io_secure_authorization_data_get_callback() */
/* @} */


/**
 * @name Channel Mode
 */
/* @{ */
/**
 * Set/get the channel-mode attribute in the specified socket
 * attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine if any data wrapping should
 * be done on the socket connection. This is required to use the
 * data protection attribute.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The new value of the channel-mode attribute. The 
 *        values for mode are described in the documentation for the
 *        #globus_io_secure_channel_mode_t type.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 *
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_channel_mode_t
 */
globus_result_t
globus_io_attr_set_secure_channel_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_channel_mode_t	mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_set_secure_channel_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"authentication_mode",
		"channel_mode"));
    }

    if(instance->channel_mode == GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR &&
       mode != instance->channel_mode &&
       instance->protection_mode == GLOBUS_IO_SECURE_PROTECTION_MODE_NONE)
    {
        instance->protection_mode = GLOBUS_IO_SECURE_PROTECTION_MODE_SAFE;
    }
    else if(mode == GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR &&
            instance->channel_mode != mode &&
            instance->protection_mode != GLOBUS_IO_SECURE_PROTECTION_MODE_NONE)
    {
        instance->protection_mode = GLOBUS_IO_SECURE_PROTECTION_MODE_NONE;
    }
 

    instance->channel_mode = mode;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_channel_mode() */

globus_result_t
globus_io_attr_get_secure_channel_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_channel_mode_t *	mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_channel_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *mode = GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR;
    }
    else
    {
	*mode = instance->channel_mode;
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_channel_mode() */
/* @} */

/**
 * @name Data Protection
 */
/* @{ */
/**
 * Set/Query the protection-mode attribute in the specified socket
 * attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine if any data protection should
 * be done on the socket connection.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The new value of the protection mode attribute. The 
 *        values for mode are described in the documentation for the
 *        globus_io_secure_protection_mode_t type.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 *
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_protection_mode_t
 */
globus_result_t
globus_io_attr_set_secure_protection_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_protection_mode_t	mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_set_secure_protection_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->channel_mode == GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR &&
       mode != GLOBUS_IO_SECURE_PROTECTION_MODE_NONE)
    {
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"channel_mode",
		"protection_mode"));
    }

    instance->protection_mode = mode;
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_protection_mode() */

globus_result_t
globus_io_attr_get_secure_protection_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_protection_mode_t *mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_protection_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *mode = GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR;
    }
    else
    {
	*mode = instance->protection_mode;
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_protection_mode() */
/* @} */


/**
 * @name Delegation
 */
/* @{ */
/** 
 * Set/Query the of the delegation-mode attribute in the specified
 * socket attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether the process's
 * credentials should be delegated to the other side of the connection.
 *
 * @param attr
 *        The attribute to modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The new value of the delegation-mode attribute. The
 *        values for mode are described in the documentation for the
 *        globus_io_secure_delegation_mode_t type.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr or mode parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_delegation_mode_t 
 */
globus_result_t
globus_io_attr_set_secure_delegation_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_delegation_mode_t	mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_set_secure_delegation_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if((instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE) ||
        (instance->authentication_mode ==
            GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS &&
         mode != GLOBUS_IO_SECURE_DELEGATION_MODE_NONE))
    {
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"authentication_mode",
		"delegation_mode"));
    }
    
    instance->delegation_mode = mode;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_delegation_mode() */

globus_result_t
globus_io_attr_get_secure_delegation_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_delegation_mode_t *
					mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_delegation_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *mode = GLOBUS_IO_SECURE_DELEGATION_MODE_NONE;
    }
    else
    {
        *mode = instance->delegation_mode;
    }
    
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_security_delegation_mode() */
/* @} */


/**
 * @name Authentication using Proxy 
 */
/* @{ */
/** 
 * Set/Query the of the proxy-mode attribute in the specified
 * socket attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether the process should
 * accept limited proxy certificates for authentication.
 *
 * @param attr
 *        The attribute to modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param mode
 *        The new value of the proxy-mode attribute. The
 *        values for mode are described in the documentation for the
 *        globus_io_secure_proxy_mode_t type.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr or mode parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init(), globus_io_secure_proxy_mode_t 
 */
globus_result_t
globus_io_attr_set_secure_proxy_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_proxy_mode_t	mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_set_secure_proxy_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"authentication_mode",
		"proxy_mode"));
    }
    
    instance->proxy_mode = mode;
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_proxy_mode() */

globus_result_t
globus_io_attr_get_secure_proxy_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_proxy_mode_t *     mode)
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    static char *			myname=
	                                "globus_io_attr_get_secure_proxy_mode";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(mode == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"mode",
		2,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *mode = GLOBUS_IO_SECURE_PROXY_MODE_NONE;
    }
    else
    {
        *mode = instance->proxy_mode;
    }
    
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_proxy_mode() */
/* @} */

/**
 * @name X509 Extensions
 */
/* @{ */
/** 
 * Set/Query of the extension OIDs attribute in the specified
 * socket attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine which critical extensions the
 * application is willing to deal with.
 *
 * @param attr
 *        The attribute to modify. The attr parameter must be 
 *        initialized by globus_io_tcpattr_init().
 * @param extension_oids
 *        The new value of the extension OIDs attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The @a attr or mode parameter was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The @a attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The @a attr structure was not a Globus I/O TCP attribute structure.
 *
 * @see globus_io_tcpattr_init()
 */
globus_result_t
globus_io_attr_set_secure_extension_oids(
    globus_io_attr_t *			attr,
    gss_OID_set                         extension_oids) 
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    int                                 i;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    static char *			myname=
	                                "globus_io_attr_set_secure_extension_oids";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(extension_oids == GSS_C_NO_OID_SET)
    {
        return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    if(instance->authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
	return globus_error_put(
	    globus_io_error_construct_attribute_mismatch(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"authentication_mode",
		"extension OIDs"));
    }
    
    if(instance->extension_oids != GSS_C_NO_OID_SET)
    {
        globus_libc_free(instance->extension_oids->elements);
        instance->extension_oids->count = 0;
    }
    else
    {
        maj_stat = gss_create_empty_oid_set(
            &min_stat,
            &instance->extension_oids);

        if(maj_stat != GSS_S_COMPLETE)
        {
            return globus_error_put(
                globus_io_error_construct_security_failed(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    maj_stat,
                    min_stat,
                    0));
        }
    }

    for(i=0;i<extension_oids->count;i++)
    {
        maj_stat = gss_add_oid_set_member(
            &min_stat,
            (gss_OID) &extension_oids->elements[i],
            (gss_OID_set *) &instance->extension_oids);

        if(maj_stat != GSS_S_COMPLETE)
        {
            return globus_error_put(
                globus_io_error_construct_security_failed(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    maj_stat,
                    min_stat,
                    0));
        }
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_secure_extension_oids() */

globus_result_t
globus_io_attr_get_secure_extension_oids(
    globus_io_attr_t *			attr,
    gss_OID_set *                       extension_oids) 
{
    globus_object_t *			securesocketattr;
    globus_i_io_securesocketattr_instance_t *
					instance;
    int                                 i;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;

    static char *			myname=
	                                "globus_io_attr_get_secure_extension_oids";
    
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(extension_oids == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"extension_oids",
		2,
		myname));
    }
    
    securesocketattr = globus_object_upcast(
	attr->attr,
	GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    if(securesocketattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
    }

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(securesocketattr);

    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    if(instance->extension_oids == GSS_C_NO_OID_SET)
    {
        *extension_oids = GSS_C_NO_OID_SET;
    }
    else
    {
        maj_stat = gss_create_empty_oid_set(
            &min_stat,
            extension_oids);

        if(maj_stat != GSS_S_COMPLETE)
        {
            return globus_error_put(
                globus_io_error_construct_security_failed(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    maj_stat,
                    min_stat,
                    0));
        }
    }

    for(i=0;i<instance->extension_oids->count;i++)
    {
        maj_stat = gss_add_oid_set_member(
            &min_stat,
            (gss_OID) &instance->extension_oids->elements[i],
            (gss_OID_set *) extension_oids);

        if(maj_stat != GSS_S_COMPLETE)
        {
            return globus_error_put(
                globus_io_error_construct_security_failed(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    maj_stat,
                    min_stat,
                    0));
        }
    }
    
    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_secure_extension_oids() */
/* @} */


/*
 * Function:	globus_i_io_socket_copy_attr()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
void
globus_i_io_socket_copy_attr(
    globus_i_io_socketattr_instance_t *	dst,
    globus_i_io_socketattr_instance_t *	src)
{
    globus_callback_space_destroy(dst->space);
    
    memcpy(dst,
	   src,
	   sizeof(globus_i_io_socketattr_instance_t));
    
    globus_callback_space_reference(dst->space);
}
/* globus_i_io_socket_copy_attr() */

/*
 * Function:	globus_i_io_securesocket_copy_attr()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
void
globus_i_io_securesocket_copy_attr(
    globus_i_io_securesocketattr_instance_t *
					dst,
    globus_i_io_securesocketattr_instance_t *
					src)
{
    memcpy(dst,
	   src,
	   sizeof(globus_i_io_securesocketattr_instance_t));

    if(src->authorized_identity != GLOBUS_NULL)
    {
	dst->authorized_identity =
	    globus_libc_strdup(src->authorized_identity);	
    }

    if(src->extension_oids != GSS_C_NO_OID_SET)
    {
        OM_uint32                       maj_stat;
        OM_uint32                       min_stat;
        int                             i;
        
        maj_stat = gss_create_empty_oid_set(
            &min_stat,
            &dst->extension_oids);

        for(i=0;i<src->extension_oids->count;i++)
        {
            maj_stat = gss_add_oid_set_member(
                &min_stat,
                (gss_OID) &src->extension_oids->elements[i],
                (gss_OID_set *) &dst->extension_oids);
        }
    }
}
/* globus_i_io_securesocket_copy_attr() */

/*
 * Function:	globus_i_io_tcp_copy_attr()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
void
globus_i_io_tcp_copy_attr(
    globus_i_io_tcpattr_instance_t *	dst,
    globus_i_io_tcpattr_instance_t *	src)
{
    memcpy(dst,
	   src,
	   sizeof(globus_i_io_tcpattr_instance_t));
    
}

/*
 * Function:	globus_i_io_udp_copy_attr()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
void
globus_i_io_udp_copy_attr(
    globus_i_io_udpattr_instance_t *	dst,
    globus_i_io_udpattr_instance_t *	src)
{
    memcpy(dst,
	   src,
	   sizeof(globus_i_io_udpattr_instance_t));
    
}

/* globus_i_io_tcp_copy_attr() */
/*
 * Function:    globus_i_io_copy_socketattr_to_handle()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_copy_socketattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_i_io_socketattr_instance_t *	instance;
    globus_object_t *			socketattr;
    static char *			myname="globus_i_io_copy_socketattr_to_handle";

    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));

	}
	socketattr =
	    globus_object_upcast(attr->attr,
			     GLOBUS_IO_OBJECT_TYPE_SOCKETATTR);
	if(socketattr == GLOBUS_NULL)
	{
	    return globus_error_put(
		globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
	}
	
	instance = (globus_i_io_socketattr_instance_t *)
	    globus_object_get_local_instance_data(socketattr);
	
	globus_i_io_socket_copy_attr(
	       &handle->socket_attr,
	       instance);
	
	return GLOBUS_SUCCESS;
    }
    else
    {
	globus_i_io_socket_copy_attr(
	       &handle->socket_attr,
	       &globus_l_io_socketattr_default);
	return GLOBUS_SUCCESS;
    }    
}
/* globus_i_io_copy_socketattr_to_handle() */

/*
 * Function:    globus_i_io_copy_securesocketattr_to_handle()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_copy_securesocketattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_i_io_securesocketattr_instance_t *
					instance;
    globus_object_t *			securesocketattr;
    globus_result_t			result;
    static char *			myname="globus_i_io_copy_securesocketattr_to_handle";

    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
	}
	securesocketattr =
	    globus_object_upcast(attr->attr,
				 GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
	if(securesocketattr == GLOBUS_NULL)
	{
	    return globus_error_put(
		globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR"));
	}
	result = globus_i_io_copy_socketattr_to_handle(attr,
						       handle);
	if(result != GLOBUS_SUCCESS)
	{
	    return result;
	}
	else
	{
	    instance = (globus_i_io_securesocketattr_instance_t *)
		globus_object_get_local_instance_data(securesocketattr);

	    globus_i_io_securesocket_copy_attr(
		&handle->securesocket_attr,
		instance);
            
	    return GLOBUS_SUCCESS;
	}
    }
    else
    {
	result = globus_i_io_copy_socketattr_to_handle(attr,
						       handle);
	if(result != GLOBUS_SUCCESS)
	{
	    return result;
	}
	else
	{
	    globus_i_io_securesocket_copy_attr(
		&handle->securesocket_attr,
		&globus_l_io_securesocketattr_default);

	    return GLOBUS_SUCCESS;
	}
    }
}
/* globus_i_io_copy_securesocketattr_to_handle() */

/*
 * Function:	globus_i_io_copy_tcpattr_to_handle()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_copy_tcpattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_result_t			rc;
    static char *			myname="globus_i_io_copy_tcpattr_to_handle";

    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
	}
	if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_TCPATTR)
	{
	    return globus_error_put(
		globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
	}
	
	rc = globus_i_io_copy_securesocketattr_to_handle(attr,
							 handle);
	
	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
	else
	{
	    globus_i_io_tcpattr_instance_t *
					instance;
	    instance = (globus_i_io_tcpattr_instance_t *)
		globus_object_get_local_instance_data(attr->attr);

	    handle->tcp_attr.nodelay = instance->nodelay;
	    handle->tcp_attr.restrict_port = instance->restrict_port;
            memcpy(&handle->tcp_attr.interface_addr[0],
                   &instance->interface_addr[0],
                   16);
	    
	    return GLOBUS_SUCCESS;
	}
    }
    else
    {
	rc = globus_i_io_copy_securesocketattr_to_handle(attr,
							 handle);
	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
	else
	{
	    globus_i_io_tcp_copy_attr(
		&handle->tcp_attr,
		&globus_l_io_tcpattr_default);
	}
    }

    return GLOBUS_SUCCESS;
}
/* globus_i_io_copy_tcpattr_to_handle() */


/*
 * Function:	globus_i_io_copy_udpattr_to_handle()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_copy_udpattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_result_t			rc;
    static char *			myname="globus_i_io_copy_udpattr_to_handle";

    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
	}
	if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_UDPATTR)
	{
	    return globus_error_put(
		globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_SOCKETATTR"));
	}
	
	rc = globus_i_io_copy_securesocketattr_to_handle(attr,
							 handle);
	
	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
	else
	{
	    globus_i_io_udpattr_instance_t *
					instance;
	    instance = (globus_i_io_udpattr_instance_t *)
		globus_object_get_local_instance_data(attr->attr);

	    handle->udp_attr.connected = instance->connected;
	    handle->udp_attr.reuse = instance->reuse;
	    handle->udp_attr.mc_loop = instance->mc_loop;
	    handle->udp_attr.mc_ttl = instance->mc_ttl;
	    handle->udp_attr.address = instance->address;
	    handle->udp_attr.interface_addr = instance->interface_addr;
	    handle->udp_attr.restrict_port = instance->restrict_port;
            
	    return GLOBUS_SUCCESS;
	}
    }
    else
    {
	rc = globus_i_io_copy_securesocketattr_to_handle(attr,
							 handle);
	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
	else
	{
	    globus_i_io_udp_copy_attr(
		&handle->udp_attr,
		&globus_l_io_udpattr_default);
	}
    }

    return GLOBUS_SUCCESS;
}
/* globus_i_io_copy_udpattr_to_handle() */

/*
 * Function:	globus_i_io_copy_fileattr_to_handle()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_copy_fileattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    static char *			myname="globus_i_io_copy_fileattr_to_handle";
    globus_i_io_fileattr_instance_t *	instance;

    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
	}
	if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_FILEATTR)
	{
	    return globus_error_put(
		globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    1,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_FILEATTR"));
	}
	else
	{
	    instance = (globus_i_io_fileattr_instance_t *)
		globus_object_get_local_instance_data(attr->attr);

	    handle->file_attr.file_type = instance->file_type;
	    
	    return GLOBUS_SUCCESS;
	}
    }
    else
    {
	    handle->file_attr.file_type = GLOBUS_IO_FILE_TYPE_BINARY;
	    return GLOBUS_SUCCESS;
    }
}
/* globus_i_io_copy_fileattr_to_handle() */

/*
 * Function:	globus_i_io_securesocket_get_attr()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_securesocket_get_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr)
{
    globus_i_io_securesocketattr_instance_t *
					instance;
    
    globus_i_io_socket_get_attr(handle,
				attr);

    instance = (globus_i_io_securesocketattr_instance_t *)
	globus_object_get_local_instance_data(
	    globus_object_upcast(attr->attr,
				 GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR));
    
    globus_i_io_securesocket_copy_attr(
	instance,
	&handle->securesocket_attr);
    
    return GLOBUS_SUCCESS;
}
/* globus_i_io_securesocket_get_attr() */

/*
 * Function:	globus_l_io_udpattr_upcast()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_l_io_udpattr_upcast(
    globus_io_attr_t *                       attr,
    char *                                   myname,
    globus_i_io_udpattr_instance_t **        inst)
{
    globus_object_t *			udpattr;
    globus_i_io_udpattr_instance_t *	instance;

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    udpattr = globus_object_upcast(attr->attr,
				      GLOBUS_IO_OBJECT_TYPE_UDPATTR);
    if(udpattr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_UDPATTR"));
    }


    instance = (globus_i_io_udpattr_instance_t *)
	globus_object_get_local_instance_data(udpattr);


    if(instance == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
              	    1,
		    myname));
    }

    *inst = instance;

    return GLOBUS_SUCCESS;
}


/**
 * @name UDP Port Restriction
 */
/* @{ */
/**
 * Set/Query the restrict-port attribute in the specified UDP attribute set.
 * @ingroup attr
 *
 * This attribute is used to determine whether or not to use the 
 * GLOBUS_UDP_PORT_RANGE environment variable to choose an anonymous
 * port for a UDP handle. This attribute may not be re-applied to
 * an existing UDP handle.
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_udpattr_init().
 * @param restrict_port
 *        The new value of the restrict_port attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O UDP attribute structure.
 *
 * @see globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_udp_restrict_port(
    globus_io_attr_t *                       attr,
    globus_bool_t                            restrict_port)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_set_udp_multicast_loop";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */

    instance->restrict_port = restrict_port;

    return GLOBUS_SUCCESS;
}
/* globus_io_attr_set_udp_restrict_port() */

globus_result_t
globus_io_attr_get_udp_restrict_port(
    globus_io_attr_t *                       attr,
    globus_bool_t *                          restrict_port)
{    
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_get_udp_multicast_loop";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);

    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */
    *restrict_port = instance->restrict_port;

    return GLOBUS_SUCCESS;
}
/* globus_io_attr_get_udp_restrict_port() */
/* @} */

/**
 * @name Multicast Loopback
 */
/* @{ */
/**
 * Set/Query the multicast-loop attribute in the specified UDP attribute
 * set.
 * @ingroup attr
 *
 * This attribute determines whether multicast packets are sent
 * to multicast group members on the local machine. Multicasting is
 * only done if the 
 *
 * @param attr
 *        The attribute to query or modify. The attr parameter must be 
 *        initialized by globus_io_udpattr_init().
 * @param enable_loopback
 *        The new value of the multicast_loop attribute.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 *         The attr was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 *         The attr structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 *         The attr structure was not a Globus I/O UDP attribute structure.
 *
 * @see globus_io_udpattr_init()
 */
globus_result_t
globus_io_attr_set_udp_multicast_loop(
    globus_io_attr_t *                       attr,
    globus_bool_t                            enable_loopback)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_set_udp_multicast_loop";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */

    if(instance->mc_enabled)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    instance->mc_loop = enable_loopback;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_get_udp_multicast_loop(
    globus_io_attr_t *                       attr,
    globus_bool_t *                          enable_loopback)
{    
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_get_udp_multicast_loop";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);

    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */
    *enable_loopback = instance->mc_loop;

    return GLOBUS_SUCCESS;
}
/* @} */

globus_result_t
globus_io_attr_set_udp_multicast_membership(
    globus_io_attr_t *                        attr,
    char *                                    address,
    char *                                    interface_addr)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    unsigned int                         ip_daddr;
    unsigned int                         tmp_u;
    static char *                        myname = "globus_io_attr_set_udp_multicast_membership";
    int x;

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */
    x = sscanf(address, "%u.%*u.%*u.%u", &ip_daddr, &tmp_u);
    if((x == 2)
       && (ip_daddr >= 224U && ip_daddr <= 239U))
    {
	/* TODO: test interface information */
        instance->address = address;
        instance->interface_addr = interface_addr;
        instance->mc_enabled = GLOBUS_TRUE;
        instance->reuse = GLOBUS_TRUE;
    }
    else
    {
	return globus_error_put(
	    globus_io_error_construct_bad_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_get_udp_multicast_membership(
    globus_io_attr_t *                        attr,
    char **                                   address,
    char **                                   interface_addr)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_get_udp_multicast_membership";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    *address = instance->address;
    *interface_addr = instance->interface_addr;

    return GLOBUS_SUCCESS;
    /* set specifcattribute */
}

/*
 * Function:	globus_io_attr_set_udp_multicast_ttl()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_io_attr_set_udp_multicast_ttl(
    globus_io_attr_t *                        attr,
    globus_byte_t                             ttl)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_set_udp_multicast_ttl";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    /* TODO: check ttl for valid value */

    if(!instance->mc_enabled)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }

    instance->mc_ttl = ttl;

    return GLOBUS_SUCCESS;
}
/*
 * Function:	globus_io_attr_get_udp_multicast_ttl()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_io_attr_get_udp_multicast_ttl(
    globus_io_attr_t *                        attr,
    globus_byte_t *                           ttl)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_get_udp_multicast_ttl";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */

    *ttl = instance->mc_ttl;

    return GLOBUS_SUCCESS;
}

/*
 * Function:	globus_io_attr_set_udp_multicast_interface()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_io_attr_set_udp_multicast_interface(
    globus_io_attr_t *                       attr,
    char *                                   interface_addr)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_set_udp_multicast_interface";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */
    
    /* error check interface */
/*    if( bad interface ) */
    {

    }

    instance->interface_addr = interface_addr;

    return GLOBUS_SUCCESS;
}
/*
 * Function:	globus_io_attr_get_udp_multicast_interface()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_io_attr_get_udp_multicast_interface(
    globus_io_attr_t *                      attr,
    char **                                 interface_addr)
{
    globus_result_t                      result;
    globus_i_io_udpattr_instance_t *	 instance;
    static char *                        myname = "globus_io_attr_get_udp_multicast_interface";

    result = globus_l_io_udpattr_upcast(
	         attr,
                 myname,
                 &instance);
    
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    /* set specifcattribute */

    *interface_addr = instance->interface_addr;

    return GLOBUS_SUCCESS;
}

