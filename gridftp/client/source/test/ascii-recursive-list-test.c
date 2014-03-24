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

/*
 * ascii MLSD test.
 *
 * makes sure that the ftp client and control libraries will process ascii.
 */
#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;
#define SIZE 15

static
void
done_cb(
    void *                  user_arg,
    globus_ftp_client_handle_t *        handle,
    globus_object_t *           err)
{
    char * tmpstr;

    if(err) tmpstr = " an";
    else    tmpstr = "out";

    if(err) { printf("done with%s error\n", tmpstr);
          error = GLOBUS_TRUE; }
    globus_mutex_lock(&lock);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&lock);
       
}

static
void
data_cb(
    void *                  user_arg,
    globus_ftp_client_handle_t *        handle,
    globus_object_t *               err,
    globus_byte_t *             buffer,
    globus_size_t               length,
    globus_off_t                offset,
    globus_bool_t               eof)
{
    fwrite(buffer, 1, length, stdout);
    if(!eof)
    {
    globus_ftp_client_register_read(handle,
                    buffer,
                    SIZE,
                    data_cb,
                    0);
    }
}

int main(int argc, char * argv[])
{
    globus_ftp_client_handle_t          handle;
    globus_ftp_client_operationattr_t       attr;
    globus_byte_t               buffer[SIZE];
    globus_size_t               buffer_length = SIZE;
    globus_result_t             result;
    globus_ftp_client_handleattr_t      handle_attr;
    char *                  src;
    char *                  dst;

    LTDL_SET_PRELOADED_SYMBOLS();
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_operationattr_init(&attr);
    globus_ftp_client_handleattr_init(&handle_attr);

    test_parse_args(argc, 
            argv,
            &handle_attr,
            &attr,
            &src,
            &dst);

    globus_ftp_client_handle_init(&handle,  &handle_attr);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_recursive_list(&handle,
                        src,
                        &attr,
                        done_cb,
                        0);
    if(result != GLOBUS_SUCCESS)
    {
    done = GLOBUS_TRUE;
    }
    else
    {
    globus_ftp_client_register_read(
        &handle,
        buffer,
        buffer_length,
        data_cb,
        0);
    }
    globus_mutex_lock(&lock);
    while(!done)
    {
    globus_cond_wait(&cond, &lock);
    }
    globus_mutex_unlock(&lock);

    globus_ftp_client_handle_destroy(&handle);
    globus_module_deactivate_all();

    if(test_abort_count && error)
    {
    return 0;
    }
    return error;
}
