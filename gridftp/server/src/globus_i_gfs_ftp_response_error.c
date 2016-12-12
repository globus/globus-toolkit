/*
 * Copyright 1999-2016 University of Chicago
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
 * @file globus_i_gfs_response_error.c FTP Response Error Type
 * @brief FTP Response Error Type Implementation
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "globus_i_gridftp_server_config.h"
#include "globus_gridftp_server.h"
#include "globus_object.h"
#include "globus_module.h"
#include "globus_error_generic.h"

#include <string.h>

typedef struct globus_l_gfs_ftp_response_error_s
{
    int                                 response_code;
    char *                              message;
}
globus_l_gfs_ftp_response_error_t;

/**
 * Allocate and initialize an error of type GLOBUS_ERROR_TYPE_FTP_RESPONSE
 * @ingroup globus_gridftp_server_error_response
 *
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error, this parameter may be NULL.
 * @param response_code
 *        The FTP response code.
 * @param fmt
 *        Response string format
 * @param ...
 *        Response string format arguments
 * @return
 *        The resulting error object. It is the user's responsibility
 *        to eventually free this object using globus_object_free(). A
 *        globus_result_t may be obtained by calling
 *        globus_error_put() on this object.        
 */
globus_object_t *
globus_gfs_ftp_response_error_construct(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    int                                 response_code,
    const char                         *fmt,
    ...)
{
    globus_object_t *                   error;
    globus_object_t *                   newerror;
    va_list                             ap;

    va_start(ap, fmt);

    newerror = globus_object_construct(
            GLOBUS_GFS_ERROR_FTP_RESPONSE_TYPE);
    error = globus_gfs_ftp_response_error_initialize(
        newerror,
        base_source,
        base_cause,
        response_code,
        fmt,
        ap);

    va_end(ap);

    if (error == NULL)
    {
        globus_object_free(newerror);
    }

    return error;
}
/* globus_gfs_ftp_response_error_construct() */

/**
 * Initialize a previously allocated error of type
 * GLOBUS_GRIDFTP_SERVER_ERROR_FTP_RESPONSE_TYPE
 * @ingroup globus_gridftp_server_error_response
 *
 * @param error
 *        The previously allocated error object.
 * @param base_source
 *        Pointer to the originating module.
 * @param base_cause
 *        The error object causing the error. If this is the original
 *        error this parameter may be NULL.
 * @param response_code
 *        The FTP response code.
 * @param fmt
 *        Response string format
 * @param ap
 *        Response string format arguments
 * @return
 *        The resulting error object. You may have to call
 *        globus_error_put() on this object before passing it on.
 */
globus_object_t *
globus_gfs_ftp_response_error_initialize(
    globus_object_t *                   error,
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    int                                 response_code,
    const char *                        fmt,
    va_list                             ap)
{
    globus_l_gfs_ftp_response_error_t * instance_data = NULL;

    instance_data = malloc(sizeof(globus_l_gfs_ftp_response_error_t));

    if (instance_data == NULL)
    {
        return NULL;
    }

    *instance_data = (globus_l_gfs_ftp_response_error_t)
    {
        .response_code = response_code,
        .message = globus_common_v_create_string(fmt, ap)
    };

    if (instance_data->message == NULL)
    {
        free(instance_data);
        return NULL;
    }

    globus_object_set_local_instance_data(error, instance_data);

    return globus_error_initialize_base(error,
                                        base_source,
                                        base_cause);
}
/* globus_ftp_response_error_initialize() */

/**
 * Retrieve the response code from a globus_ftp_response_error object
 * @ingroup globus_gridftp_server_error_response
 *
 * @param error
 *        The error from which to retrieve the response code
 * @return
 *        The response code stored in the object
 */
int
globus_gfs_error_get_ftp_response_code(
    globus_object_t *                   error)
{
    globus_object_t *                   ftp_response_error = NULL;
    globus_l_gfs_ftp_response_error_t * instance_data = NULL;

    ftp_response_error = globus_object_upcast(
            error,
            GLOBUS_GFS_ERROR_FTP_RESPONSE_TYPE);

    if (ftp_response_error != NULL)
    {
        instance_data = globus_object_get_local_instance_data(error);
        return instance_data->response_code;
    }
    else
    {
        return 0;
    }
}
/* globus_gfs_error_get_ftp_response_code() */

/**
 * Retrieve the message from a globus_ftp_response_error object
 * @ingroup globus_gridftp_server_error_response
 *
 * @param error
 *        The error from which to retrieve the response code
 * @return
 *        The response code stored in the object
 */
char *
globus_gfs_error_get_ftp_response_message(
    globus_object_t *                   error)
{
    globus_object_t *                   ftp_response_error = NULL;
    char *                              msg = NULL;
    globus_l_gfs_ftp_response_error_t * instance_data = NULL;

    ftp_response_error = globus_object_upcast(
            error,
            GLOBUS_GFS_ERROR_FTP_RESPONSE_TYPE);

    if (ftp_response_error != NULL)
    {
        instance_data = globus_object_get_local_instance_data(error);
        msg = strdup(instance_data->message);
        return msg;
    }
    else
    {
        return NULL;
    }
}
/* globus_gfs_error_get_ftp_response_message() */

/**
 * Copy the instance data of a Globus FTP Response error object.
 * @ingroup globus_gridftp_server_error_response
 * 
 * @param src
 *        The source instance data
 * @param dst
 *        The destination instance data
 * @return
 *        void
 */
static
void
globus_l_gridftp_server_error_copy(
    void *                              src,
    void **                             dst)
{
    globus_l_gfs_ftp_response_error_t * src_instance_data = NULL;
    globus_l_gfs_ftp_response_error_t * dst_instance_data = NULL;

    if(src == NULL || dst == NULL) return;
    src_instance_data = src;
    dst_instance_data = malloc(sizeof(globus_l_gfs_ftp_response_error_t));
    if (dst_instance_data == NULL)
    {
        goto done;
    }
    dst_instance_data->response_code = src_instance_data->response_code;
    dst_instance_data->message = strdup(src_instance_data->message);
    if (dst_instance_data->message == NULL)
    {
        free(dst_instance_data);
        dst_instance_data = NULL;
    }
done:
    *dst = dst_instance_data;
    return;
}
/* globus_l_gridftp_server_error_copy() */

/**
 * Free the instance data of a Globus Errno Error object.
 * @ingroup globus_gridftp_server_error_response
 * 
 * @param data
 *        The instance data
 * @return
 *        void
 */
static
void
globus_l_gridftp_server_error_free(
    void *                              data)
{
    globus_l_gfs_ftp_response_error_t * instance_data = data;

    if (instance_data != NULL)
    {
        free(instance_data->message);
        free(instance_data);
    }
}
/* globus_l_gridftp_server_error_free() */

/**
 * Return a copy of the short description from the instance data
 * @ingroup globus_gridftp_server_error_response
 * 
 * @param error
 *        The error object to retrieve the data from.
 * @return
 *        String containing the short description if it exists, NULL
 *        otherwise.
 */
static
char *
globus_l_gridftp_server_error_printable(
    globus_object_t *                   error)
{
    globus_object_t *                   ftp_response_error = NULL;
    char *                              msg = NULL;
    globus_l_gfs_ftp_response_error_t * instance_data = NULL;

    ftp_response_error = globus_object_upcast(
            error,
            GLOBUS_GFS_ERROR_FTP_RESPONSE_TYPE);

    assert (ftp_response_error != NULL);

    instance_data = globus_object_get_local_instance_data(error);
    msg = globus_common_create_string(
            "%s",
            instance_data->message);
    return msg;
}/* globus_l_error_errno_printable */

globus_object_t *
globus_i_gfs_error_system(
    int                                 code)
{
    char                                msg[256];
    char                               *m = msg;
    globus_object_t                    *err = NULL;

    msg[0] = '\0';
#ifdef _WIN32
    strerror_s(msg, sizeof(msg), errno);
#elif defined(HAVE_DECL_STRERROR_R)
#ifdef STRERROR_R_CHAR_P
    m = strerror_r(errno, msg, sizeof(msg));
#else
    strerror_r(errno, msg, sizeof(msg));
#endif
#else
    m = strerror(errno);
#endif

    if (code == 0)
    {
        switch (errno)
        {
#ifdef ETXTBSY
            case ETXTBSY: code = 450; break;
#endif
#ifdef ECONNREFUSED
            case ECONNREFUSED: code = 425; break;
#endif
#if defined(ECONNRESET)
            case ECONNRESET: code = 426; break;
#endif
#if defined(ECONNABORTED)
            case ECONNABORTED: code = 426; break;
#endif
            case ENOENT: code = 550; break;
            case EACCES: code = 550; break;
            case EPERM: code = 550; break;
            case ENOTDIR: code = 550; break;
            case EISDIR: code = 550; break;
            case EROFS: code = 550; break;
            case ESPIPE: code = 550; break;
            case EFBIG: code = 552; break;
            case ENOSPC: code = 552; break;
#if defined(EDQUOT)
            case EDQUOT: code = 552; break;
#endif
            case EEXIST: code = 553; break;
            default:
                code = 451;
        }
    }

    if (msg[0] != 0)
    {
        err = globus_gfs_ftp_response_error_construct(
            NULL,
            NULL,
            code,
            "%s",
            msg);
    }
    else
    {
        err = globus_gfs_ftp_response_error_construct(
            NULL,
            NULL,
            code,
            "Requested action aborted. Local error in processing.");
    }
    return err;
}

/**
 * Error type static initializer.
 */
const globus_object_type_t GLOBUS_GFS_ERROR_FTP_RESPONSE_TYPE_DEFINITION
= globus_error_type_static_initializer (
    GLOBUS_ERROR_TYPE_BASE,
    globus_l_gridftp_server_error_copy,
    globus_l_gridftp_server_error_free,
    globus_l_gridftp_server_error_printable);
