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
 * utime test.
 *
 * makes sure that the ftp client and control libraries are able to
 * change file modification times
 */
#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;

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

int main(int argc, char * argv[])
{
    globus_ftp_client_handle_t          handle;
    globus_ftp_client_operationattr_t       attr;
    globus_result_t             result;
    globus_ftp_client_handleattr_t      handle_attr;
    char *                  src = NULL;
    char *                  dst = NULL;
    struct tm                                   modtime;
    extern char *                               optarg;
    extern int                                  optind;
    int                                         c;

    LTDL_SET_PRELOADED_SYMBOLS();
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    test_parse_args(argc, 
            argv,
                    &handle_attr,
                    &attr,
            &src,
            &dst);

    optind = 1;
    while((c = getopt(argc, argv, "T:")) != -1)
    {
    switch(c)
    {
      case 'T':
            memset(&modtime, 0, sizeof(modtime));
            if (sscanf(optarg, "%4d%2d%2d%2d%2d%2d", 
                        &modtime.tm_year, &modtime.tm_mon, &modtime.tm_mday,
                        &modtime.tm_hour, &modtime.tm_min, &modtime.tm_sec) != 6)
            {
                printf("Invalid time format\n");
                return GLOBUS_TRUE;
            }
            modtime.tm_year -= 1900;
            modtime.tm_mon  -= 1;
        break;
    }
    }   


    globus_ftp_client_operationattr_set_type(&attr,
                                         GLOBUS_FTP_CONTROL_TYPE_ASCII);

    globus_ftp_client_handleattr_set_cache_all(&handle_attr,
                                               GLOBUS_TRUE);
    
    globus_ftp_client_handle_init(&handle,  &handle_attr);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_utime(&handle,
                      src,
                      &modtime,
                      &attr,
                      done_cb,
                      0);
    if(result != GLOBUS_SUCCESS)
    {
    done = GLOBUS_TRUE;
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
































