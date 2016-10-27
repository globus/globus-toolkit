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

/**
 * @file read_vhost_cred_dir.c Read all credentials in a directory
 */

#include "globus_gss_assist.h"
#include "globus_gsi_system_config.h"

static
OM_uint32
globus_l_gss_assist_read_file(
    OM_uint32                          *minor_status_out,
    const char                         *directory_path,
    const char                         *file_name,
    void                              **data_buffer_out,
    size_t                             *data_buffer_size_out);

/**
 * @brief Acquire all GSSAPI credentials in a directory
 * @ingroup globus_gss_assist_credential
 * @details
 *     This function loads all of the credentials available in the 
 *     vhost credential directory and returns them in its
 *     output parameters. The service credentials must be in a form understood
 *     by gss_import_cred().
 *
 *     The credentials are loaded from the path contained in the
 *     `X509_VHOST_CRED_DIR` environment variable, or the default
 *     `/etc/grid-security/vhosts/` if it is not set.
 *
 *     Within the designated directory, each `.p12` or `.pem` file is imported
 *     using gss_import_cred().
 */
OM_uint32
globus_gss_assist_read_vhost_cred_dir(
    /** [out] Mechanism-specific error code */
    OM_uint32                          *minor_status,
    /** [out] Pointer to a dynamic array allocated to hold credentials */
    gss_cred_id_t                     **output_credentials_array,
    /**
     * [out] Pointer to be set to the resulting size (in bytes) of the
     * output_credentials_array
     */
    size_t                             *output_credentials_array_size)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    void                               *credential_buffer = NULL;
    size_t                              credential_buffer_len = 0;
    gss_cred_id_t                      *credential_array = NULL;
    size_t                              credential_array_count = 0;
    size_t                              credential_array_size = 0;
    char                               *dirname = NULL;
    DIR                                *dir_handle = NULL;
    struct dirent                      *dir_entry = NULL;
    int                                 rc = 0;

    if (output_credentials_array == NULL ||
        output_credentials_array_size == NULL)
    {
        major_status = GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_WRITE;
        *minor_status = GLOBUS_FAILURE;

        goto invalid_parameter;
    }

    *minor_status = GLOBUS_GSI_SYSCONFIG_GET_VHOST_CRED_DIR(&dirname);
    if (*minor_status != GLOBUS_SUCCESS)
    {
        major_status = GSS_S_FAILURE;

        goto no_dir;
    }

    if (dirname == NULL)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = GLOBUS_FAILURE;

        goto no_dir;
    }

    dir_handle = opendir(dirname);
    if (dir_handle == NULL)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = GLOBUS_FAILURE;

        goto opendir_fail;
    }

    while ((rc = globus_libc_readdir_r(dir_handle, &dir_entry)) == 0
        && dir_entry != NULL)
    {
        const char                     *extension = NULL;;

        extension = strrchr(dir_entry->d_name, '.');

        if (extension == NULL
            || (strcmp(extension, ".pem") != 0
                && strcmp(extension, ".p12") != 0))
        {
            goto bad_extension;
        }
        major_status = globus_l_gss_assist_read_file(
                minor_status,
                dirname,
                dir_entry->d_name,
                &credential_buffer,
                &credential_buffer_len);
        if (major_status != GSS_S_COMPLETE)
        {
            *minor_status = GLOBUS_FAILURE;
            goto read_file_fail;
        }

        if (credential_buffer == NULL)
        {
            major_status = GSS_S_FAILURE;
            *minor_status = GLOBUS_FAILURE;
            goto no_data;
        }

        if (credential_array_count == credential_array_size)
        {
            gss_cred_id_t          *tmp = NULL;

            tmp = realloc(credential_array,
                2 
                * (credential_array_size ? credential_array_size : 1)
                * sizeof(gss_cred_id_t));
                
            if (tmp == NULL)
            {
                major_status = GSS_S_FAILURE;
                *minor_status = GLOBUS_FAILURE;

                goto realloc_credential_fail;
            }
            credential_array = tmp;
            credential_array_size = 2
                    * (credential_array_size ? credential_array_size : 1);
        }
        major_status = gss_import_cred(
                minor_status,
                &credential_array[credential_array_count],
                GSS_C_NO_OID,
                0,
                &(gss_buffer_desc)
                {
                    .value = credential_buffer,
                    .length = credential_buffer_len,
                },
                0,
                NULL);

        free(credential_buffer);
        credential_buffer = NULL;
        credential_buffer_len = 0;

        if (major_status != GSS_S_COMPLETE)
        {
            goto import_cred_fail;
        }
        credential_array_count++;
bad_extension:
        free(dir_entry);
        dir_entry = NULL;
    }
    if (major_status != GSS_S_COMPLETE)
    {
import_cred_fail:
realloc_credential_fail:
no_data:
read_file_fail:
        free(credential_buffer);
        credential_buffer = NULL;
        credential_buffer_len = 0;

        for (size_t i = 0; i < credential_array_count; i++)
        {
            gss_release_cred(
                    minor_status,
                    &credential_array[i]);
        }
        free(credential_array);

        credential_array_count = 0;
        credential_array_size = 0;
        credential_array = NULL;
    }
    if (dir_entry != NULL)
    {
        free(dir_entry);
        dir_entry = NULL;
    }
    closedir(dir_handle);
    dir_handle = NULL;

opendir_fail:
    free(dirname);
    dirname = NULL;
no_dir:
    *output_credentials_array = credential_array;
    *output_credentials_array_size =
            credential_array_count * sizeof(gss_cred_id_t);
invalid_parameter:
    return major_status;
}
/* globus_gss_assist_read_vhost_cred_dir() */

static
OM_uint32
globus_l_gss_assist_read_file(
    OM_uint32                          *minor_status_out,
    const char                         *directory_path,
    const char                         *file_name,
    void                              **data_buffer_out,
    size_t                             *data_buffer_size_out)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           minor_status = GLOBUS_SUCCESS;
    size_t                              amt_read = 0;
    char                               *fullpath = NULL;
    char                               *data_buffer = NULL;
    size_t                              data_buffer_size = 0;
    struct stat                         st = {0};
    FILE                               *fp = NULL;
    int                                 rc = 0;

    assert (minor_status_out != NULL);
    assert (directory_path != NULL);
    assert (file_name != NULL);
    assert (data_buffer_out != NULL);
    assert (data_buffer_size_out != NULL);

    fullpath = globus_common_create_string(
            "%s/%s",
            directory_path,
            file_name);

    if (fullpath == NULL)
    {
        major_status = GSS_S_FAILURE;
        minor_status = GLOBUS_FAILURE;

        goto fullpath_malloc_fail;
    }

    rc = stat(fullpath, &st);
    if (rc != 0)
    {
        major_status = GSS_S_FAILURE;
        minor_status = GLOBUS_FAILURE;

        goto stat_fail;
    }
    
    if ((st.st_mode & S_IFREG) == 0)
    {
        goto not_a_regular_file;
    }

    if (st.st_size > SIZE_MAX)
    {
        major_status = GSS_S_FAILURE;
        minor_status = GLOBUS_FAILURE;

        goto cred_too_big;
    }

    data_buffer_size = st.st_size;

    data_buffer = malloc(data_buffer_size);
    if (data_buffer == NULL)
    {
        major_status = GSS_S_FAILURE;
        minor_status = GLOBUS_FAILURE;

        goto malloc_data_buffer_fail;
    }
    fp = fopen(fullpath, "r");
    if (fp == NULL)
    {
        major_status = GSS_S_FAILURE;
        minor_status = GLOBUS_FAILURE;

        goto fopen_fail;
    }

    do
    {
        size_t                     read_result = 0;

        read_result = fread(
                data_buffer + amt_read,
                1,
                data_buffer_size - amt_read,
                fp);

        if (read_result > 0)
        {
            amt_read += read_result;
        }
        else if (ferror(fp))
        {
            major_status = GSS_S_FAILURE;
            minor_status = GLOBUS_FAILURE;

            goto fail_read;
        }
    }
    while (rc >= 0 && amt_read < data_buffer_size);
fail_read:
    fclose(fp);
    fp = NULL;

fopen_fail:
    if (major_status == GSS_S_FAILURE)
    {
        free(data_buffer);
        data_buffer = NULL;
    }
malloc_data_buffer_fail:
cred_too_big:
not_a_regular_file:
stat_fail:
fullpath_malloc_fail:
    free(fullpath);
    fullpath = NULL;

    *data_buffer_out = data_buffer;
    *data_buffer_size_out = data_buffer_size;
    *minor_status_out = minor_status;

    return major_status;
}
/* globus_l_gss_assist_read_file() */

