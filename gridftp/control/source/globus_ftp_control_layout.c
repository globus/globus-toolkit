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

/**
 * @file globus_ftp_control_layout.c
 *
 */

#include "globus_ftp_control.h"
#include <string.h>

/*
 *
 *  StripedLayout=Blocked;BlockSize=<size>;
 */
globus_result_t 
globus_ftp_control_layout_blocked_verify(
    char *                                     layout_str)
{
    char *                                     name;
    char *                                     tmp_ptr;
    char *                                     parm_name;
    int                                        block_size;
    globus_result_t                            res = GLOBUS_SUCCESS;

    if(layout_str == GLOBUS_NULL)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format.")));
        goto exit;
    }

    name = (char *)globus_malloc(strlen(layout_str));
    
    if(sscanf(layout_str, "StripedLayout=%s", name) < 1)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format.")));
        goto exit;
    }
    tmp_ptr = strchr(name, ';');
    if(tmp_ptr == GLOBUS_NULL)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format. must end with ';'")));
        goto exit;
    }
    *tmp_ptr = '\0';
    if(tmp_ptr == GLOBUS_NULL)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format. ';'")));
        goto exit;
    }

    parm_name = tmp_ptr + 1; 
    if(strcmp(name, "Blocked") != 0)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not named \"Blocked\".")));
        goto exit;
    }
    if(sscanf(parm_name, "BlockSize=%d;", &block_size) < 1)
    {
        res = globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("\"BlockSize\" argument not found.")));
        goto exit;
    }

  exit:

    globus_free(name);

    return res;
}

void *
globus_ftp_control_layout_blocked_user_arg_create()
{
    return GLOBUS_NULL;
}

void
globus_ftp_control_layout_blocked_user_arg_destroy(
    void *                                      user_arg)
{
    return;
}

globus_result_t
globus_ftp_control_layout_blocked(
    globus_ftp_control_handle_t *               handle,
    globus_ftp_control_data_write_info_t *      data_info,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                in_offset,
    globus_bool_t                               eof,
    int                                         stripe_count,
    char *                                      enqueue_str,
    void *                                      user_arg)
{
    int                                         chunk;
    int                                         stripe_ndx;
    globus_off_t                                offset;
    globus_size_t                               size;
    globus_result_t                             res;

    sscanf(enqueue_str, "StripedLayout=Blocked;BlockSize=%d;", &chunk);

    for(offset = in_offset;
        offset < in_offset + length;
        offset += size)
    {
        stripe_ndx = (offset / chunk) % stripe_count;

        size = chunk - (offset % chunk);
        if(size > length - (offset - in_offset))
        {
            size = length - (offset - in_offset);
        }

        res = globus_X_ftp_control_data_write_stripe(
                  handle,
                  &buffer[(globus_size_t)(offset-in_offset)],
                  size,
                  offset,
                  eof, 
                  stripe_ndx,
                  data_info);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
    }  

    return GLOBUS_SUCCESS;
}


/*
 *
 *  StripedLayout=Partitioned;
 */
globus_result_t 
globus_ftp_control_layout_partitioned_verify(
    char *                                     layout_str)
{
    if(layout_str == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format.")));
    }

    if(strcmp(layout_str, "StripedLayout=Partitioned;") != 0)
    {
        return globus_error_put(globus_error_construct_string(
                     GLOBUS_FTP_CONTROL_MODULE,
                     GLOBUS_NULL,
                     _FCSL("layout string not in proper format.")));
    }

    return GLOBUS_SUCCESS;
}

void *
globus_ftp_control_layout_partitioned_user_arg_create(
    globus_size_t                               file_size)
{
    globus_size_t *                             user_arg;

    user_arg = (globus_size_t *) globus_malloc(sizeof(file_size));

    *user_arg = file_size;

    return user_arg;
}

void
globus_ftp_control_layout_partitioned_user_arg_destroy(
    void *                                      user_arg)
{
    globus_free(user_arg);

    return;
}

globus_result_t
globus_ftp_control_layout_partitioned(
    globus_ftp_control_handle_t *               handle,
    globus_ftp_control_data_write_info_t *      data_info,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                in_offset,
    globus_bool_t                               eof,
    int                                         stripe_count,
    char *                                      enqueue_str,
    void *                                      user_arg)
{
    int                                         chunk;
    int                                         stripe_ndx;
    globus_off_t                                offset;
    globus_size_t                               size;
    globus_size_t                               filesize;
    globus_result_t                             res;

    filesize = *((globus_size_t *)user_arg);
    chunk = filesize / stripe_count;

    for(offset = in_offset;
        offset < in_offset + length;
        offset += size)
    {
        stripe_ndx = (offset / chunk) % stripe_count;

        size = chunk - (offset % chunk);
        if(size > length - (offset - in_offset))
        {
            size = length - (offset - in_offset);
        }

        res = globus_X_ftp_control_data_write_stripe(
                  handle,
                  &buffer[(globus_size_t)(offset-in_offset)],
                  size,
                  offset,
                  eof, 
                  stripe_ndx,
                  data_info);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
    }  

    return GLOBUS_SUCCESS;
}

