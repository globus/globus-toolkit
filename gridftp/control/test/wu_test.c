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
 *  This program tests the globus_ftp_control_data library
 */
#include "globus_ftp_control.h"
#include "globus_common.h"
#include <string.h>
#include "test_common.h"

#define TEST_ITEREATION                         1
#define WRITE_CHUNK_COUNT                       32

#define PARTITIONED 1

/*
#define RETR_TEST                               1
*/

#define STOR_TEST                               1

/*
#define SEND_EOF                                1
*/

#if defined(SEND_EOF)
#define   WAIT_COUNT 3
#else
#define WAIT_COUNT 2
#endif

typedef void (*set_handle_mode_cb_t)(
    globus_ftp_control_handle_t *               handle);

globus_size_t                                   g_file_size;
typedef struct data_test_info_s
{
    char                                        fname[512];
    char                                        a[2024];
    FILE *                                      fin;
    char                                        c[2024];
    FILE *                                      fout;
    char                                        b[2024];
    ftp_test_monitor_t *                        monitor;
} data_test_info_t;

static float                                    g_total_throughput = 0.0;
static int                                      g_throughput_count = 0;

static int                                      g_test_count = 0;
static char *                                   g_server_file = "GlobusTestFile";
static char *                                   g_test_file = GLOBUS_NULL;
static char *                                   g_tmp_file = "/tmp/globus_ftp_control_data_test_tmp_file.tmp";

globus_bool_t
spas_to_host_port(
    char *                                      astr,
    globus_ftp_control_host_port_t *            addr,
    int *                   cnt);

void
test_result(
    globus_result_t                             result,
    char *                                      msg);

globus_result_t
transfer_test(
    set_handle_mode_cb_t                       mode_cb);

void
failure_end(
    char *                                      msg);

void
connect_read_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

void
connect_write_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

void
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof);

void
data_read_big_buffer_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               length_read,
    globus_off_t                                offset,
    globus_off_t                                file_offset,
    globus_bool_t                               eof);

void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof);

void
connect_write_big_buffer_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

void
connect_read_big_buffer_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

void 
eof_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error);

void 
binary_eb_mode(
    globus_ftp_control_handle_t *               handle);

void 
binary_stream_mode(
    globus_ftp_control_handle_t *               handle);

void
pasv_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;
    globus_ftp_control_host_port_t              addr;
    globus_ftp_control_host_port_t              spas_addr[ 16 ];
    globus_result_t                             res;

    monitor = (ftp_test_monitor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        if(ftp_response->code == 227)
        {
            pasv_to_host_port(ftp_response->response_buffer, &addr);
            res = globus_ftp_control_local_port(handle, &addr);
            monitor->result = res;
        }
        else if ( ftp_response->code == 229 )
        {
           int cnt;
           globus_ftp_control_layout_t    layout;

 fprintf(stderr,"got 229\n");

#if ROUND_ROBIN
           layout.mode = GLOBUS_FTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN; 
           layout.round_robin.block_size  = 65536;
           globus_ftp_control_local_layout( handle, &layout, g_file_size);
#elif PARTITIONED
           layout.mode = GLOBUS_FTP_CONTROL_STRIPING_PARTITIONED;
           layout.partitioned.size = g_file_size;
           globus_ftp_control_local_layout( handle, &layout, g_file_size);
#endif
           spas_to_host_port(ftp_response->response_buffer, spas_addr, &cnt);
           res = globus_ftp_control_local_spor(handle, spas_addr, cnt);
                        
           monitor->result = res;
        }
        else
        {
            monitor->result = globus_error_put(GLOBUS_ERROR_NO_INFO);
        }

        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

globus_result_t
send_pasv_cmd(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             res;
    ftp_test_monitor_t                          monitor;

    ftp_test_monitor_init(&monitor);
    res = globus_ftp_control_send_command(
               handle,
               "PASV\r\n",
                pasv_response_callback,
                (void*)&monitor);
    test_result(res, "send_command PASV");

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);
  
    test_result(monitor.result, "after PASV block");
     
    ftp_test_monitor_destroy(&monitor);

    return res;
}

void
port_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;

    monitor = (ftp_test_monitor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            verbose_printf(2, "port_response_callback(): error in callback\n");
            monitor->result = globus_error_put(error);
        }
        else if(ftp_response->code != 200)
        {
            verbose_printf(2, "port_response_callback(): != 227 %d\n",
                           ftp_response->code);
            monitor->result = globus_error_put(GLOBUS_ERROR_NO_INFO);
        }
        else
        {
            verbose_printf(2, "port_response_callback(): SUCCESS\n");
            monitor->result = GLOBUS_SUCCESS;
        }

        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

globus_result_t
send_port_cmd(
    globus_ftp_control_handle_t *               handle)
{
    int                                         hi;
    int                                         low;
    globus_ftp_control_host_port_t              addr;
    globus_result_t                             res;
    ftp_test_monitor_t                          monitor;

    ftp_test_monitor_init(&monitor);

    addr.port = 0;
    res = globus_ftp_control_local_pasv(
              handle,
              &addr);
    test_result(res, "local_pasv");

    hi = addr.port / 256;
    low = addr.port % 256;

    res = globus_ftp_control_send_command(
              handle, 
              "PORT %d,%d,%d,%d,%d,%d\r\n",
              port_response_callback,
              (void *)&monitor,
              addr.host[0],
              addr.host[1],
              addr.host[2],
              addr.host[3],
              hi,
              low);
    test_result(res, "send command port");

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    res = monitor.result;
     
    ftp_test_monitor_destroy(&monitor);

    return res;
}

static char *                             g_host;
static int                                g_port;
static int                                g_parallel;
static char *                             g_login;
static char *                             g_password;
static char *                             g_base_dir;

int 
main(
    int                                         argc,
    char *                                      argv[])
{ 
    globus_result_t                             res;
    int                                         ctr;

    g_parallel = 1;
    g_test_file = argv[0];
    for(ctr = 0; ctr < argc; ctr++)
    {
        if(strcmp(argv[ctr], "-verbose") == 0)
        {
            if(ctr + 1 >= argc)
            {
                verbose_print_level = 1;
            }
            else
            {
                verbose_print_level = atoi(argv[ctr+1]);
                ctr++;
            }
        }
        else if(strcmp(argv[ctr], "--file") == 0 && ctr + 1 <= argc)
        {
            g_test_file = argv[ctr + 1];
            ctr++;
        }
        else if(strcmp(argv[ctr], "--tmp_file") == 0 && ctr + 1 <= argc)
        {
            g_tmp_file = argv[ctr + 1];
            ctr++;
        }
        else if(strcmp(argv[ctr], "--host") == 0 && ctr + 2 <= argc)
        {
            ctr++;
            g_host = argv[ctr];
            ctr++;
            g_port = (unsigned short)atoi(argv[ctr]);
        }
        else if(strcmp(argv[ctr], "--login") == 0 && ctr + 3 <= argc)
        {
            ctr++;
            g_login = argv[ctr];
            ctr++;
            g_password = argv[ctr];
            ctr++;
            g_base_dir = argv[ctr];
        }
        else if(strcmp(argv[ctr], "--p") == 0 && ctr + 3 <= argc)
        {
            ctr++;
            g_parallel = atoi(argv[ctr]);
        }
    }

    {
       struct stat stat_s;
       stat(g_test_file, &stat_s);
       g_file_size = stat_s.st_size;
    }
    /*
     *  activate
     */
    res = (globus_result_t)globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    test_result(res, "globus_module_activate failed");

#if !defined(SEND_EOF)
#if 0
    g_test_count++;
    verbose_printf(1, "------------------------------------\n");
    verbose_printf(1, "running transfer test in stream mode\n");
    transfer_test(binary_stream_mode);
    verbose_printf(1, "transfer test in stream mode passed\n");
    verbose_printf(1, "------------------------------------\n");
#endif
#endif

    g_test_count++;
    verbose_printf(1, "------------------------------------\n");
    verbose_printf(1, "running transfer test in eb mode\n");
    transfer_test(binary_eb_mode);
    verbose_printf(1, "transfer test in eb mode passed\n");
    verbose_printf(1, "------------------------------------\n");

    printf("average throughput %f\n", (float)g_total_throughput/(float)g_throughput_count);
    res = (globus_result_t)globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);
    test_result(res, "deactivate");

    verbose_printf(1, "%d tests passed.\n", g_test_count);
    printf("Success.\n");
    return 0;
}

void
stor_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;

    monitor = (ftp_test_monitor_t *)            callback_arg;

    verbose_printf(2, "stor_callback() : start\n");
    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            verbose_printf(2, "stor_callback() : %s\n", 
                globus_object_printable_to_string(error));
                
            monitor->done = GLOBUS_TRUE;
            monitor->result = globus_error_put(error);
            monitor->count++;
        }
        else if(ftp_response->code == 226)
        {
            verbose_printf(2, "stor_callback() : %s\n", 
                ftp_response->response_buffer);
            monitor->count++;
        }
        else if(ftp_response->code == 112)
        {
            char *                  tmp_ptr;
            float                   tmp_f;

            verbose_printf(2, "performance stor_callback() : %s\n", 
                ftp_response->response_buffer);
  
            tmp_ptr = strstr(ftp_response->response_buffer, "AllThroughput:");
            tmp_ptr = strstr(tmp_ptr, ":");
            tmp_ptr++;
            sscanf(tmp_ptr, "%f", &tmp_f);

            g_total_throughput += tmp_f;
            g_throughput_count++;

            verbose_printf(2, "%f\n", tmp_f);
        }
        else
        {
            verbose_printf(2, "stor_callback() : %s\n", 
                ftp_response->response_buffer);
        }
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
retr_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;

    monitor = (ftp_test_monitor_t *)            callback_arg;

    verbose_printf(2, "retr_callback() : start\n");
    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            verbose_printf(2, "retr_callback() : %s\n", 
                globus_object_printable_to_string(error));
                
            monitor->done = GLOBUS_TRUE;
            monitor->result = globus_error_put(error);
            monitor->count++;
        }
        else if(ftp_response->code == 226)
        {
            verbose_printf(2, "retr_callback() : %s\n", 
                ftp_response->response_buffer);
            monitor->count++;
        }
        else if(ftp_response->code == 112)
        {
            verbose_printf(1, "performance retr_callback() : %s\n", 
                ftp_response->response_buffer);
        }
        else
        {
            verbose_printf(2, "retr_callback() : %s\n", 
                ftp_response->response_buffer);
        }
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
signal_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;

    monitor = (ftp_test_monitor_t *)            callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            test_result(globus_error_put(error), "signal callback");
        }
        else
        {
    verbose_printf(2, "signal_callback %s\n", ftp_response->response_buffer);
            monitor->done = GLOBUS_TRUE;
            globus_cond_signal(&monitor->cond);
        }
    }
    globus_mutex_unlock(&monitor->mutex);

}

void 
binary_eb_mode(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             res;
    globus_ftp_control_parallelism_t            parallelism;
    ftp_test_monitor_t                          monitor;

    ftp_test_monitor_init(&monitor);

    /*
     *  set binary transfer type
     */
    globus_ftp_control_send_command(
              handle, 
              "TYPE I\r\n",
              signal_callback,
              (void*)&monitor);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    res = globus_ftp_control_local_type(
              handle, 
              GLOBUS_FTP_CONTROL_TYPE_IMAGE, 
              0);
    test_result(res, "local_type");

    /*  
     *  set mode E
     */
    ftp_test_monitor_reset(&monitor);
    globus_ftp_control_send_command(
              handle, 
              "MODE E\r\n",
              signal_callback,
              (void*)&monitor);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    res = globus_ftp_control_local_mode(
              handle, 
              GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
    test_result(res, "local_mode");

    /*
     *  set parallel level
     */
    ftp_test_monitor_reset(&monitor);
    globus_ftp_control_send_command(
              handle, 
              "OPTS RETR Parallelism=%d,%d,%d;\r\n",
              signal_callback,
              (void*)&monitor,
              g_parallel,
              g_parallel,
              g_parallel);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
    parallelism.fixed.size = g_parallel;
    res = globus_ftp_control_local_parallelism(
              handle, 
              &parallelism);
    test_result(res, "local_parallel");
}

void 
binary_stream_mode(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             res;
    ftp_test_monitor_t                          monitor;

    ftp_test_monitor_init(&monitor);

    /*
     *  set binary transfer type
     */
    globus_ftp_control_send_command(
              handle, 
              "TYPE I\r\n",
              signal_callback,
              (void*)&monitor);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    res = globus_ftp_control_local_type(
              handle, 
              GLOBUS_FTP_CONTROL_TYPE_IMAGE, 
              0);
    test_result(res, "local_type");

    /*  
     *  set mode E
     */
    ftp_test_monitor_reset(&monitor);

    globus_ftp_control_send_command(
              handle, 
              "MODE S\r\n",
              signal_callback,
              (void*)&monitor);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    res = globus_ftp_control_local_mode(
              handle, 
              GLOBUS_FTP_CONTROL_MODE_STREAM);
    test_result(res, "local_mode");
}

/*
 *  transfer test
 *  -------------
 *  This test local creates several pasv and port handles and connects them.
 *  It then sends data to all of them and compares the data on both ends
 *  if the trasfers.  In order to ease the testing of some of the clean up
 *  this test does leak some memory.
 * 
 *  It tests the control library data code for:
 *  1) read and write functionality for data integrity
 *  2) functionality when multiple handles are simaltaneously being used.
 *  3) reads of sizes greater than and smaller than the size of the extended
 *     block.
 *  4) clean up.  At the end of half the transfers close() and destroy() 
 *     are called.  The other half leave the clean up up to deactivate.
 */
globus_result_t
transfer_test(
    set_handle_mode_cb_t                       mode_cb)
{
    int                                     ctr;
    globus_result_t                         res;
    globus_ftp_control_host_port_t          host_port;
    globus_ftp_control_handle_t             handle;
    data_test_info_t *                      test_info;
    data_test_info_t                        test_info_array[TEST_ITEREATION];
    ftp_test_monitor_t                      monitor; 
    globus_abstime_t                        start_time;
    globus_abstime_t                        end_time;
    globus_reltime_t                        diff_time;
    struct stat                             stat_info;
    globus_size_t                           filesize;
    globus_size_t                           tm;
    float                                   rate;
    float                                   secs;

    stat(g_server_file, &stat_info);
    filesize = stat_info.st_size;

    ftp_test_monitor_init(&monitor); 

    res = globus_ftp_control_handle_init(&handle);
    test_result(res, "port handle init");
    connect_control_handle(
            &handle,
            g_login,
            g_password,
            g_base_dir,
            g_host,
            g_port);

#if defined(SEND_EOF)
    globus_ftp_control_local_send_eof(&handle, GLOBUS_FALSE);
#endif
    for(ctr = 0; ctr < TEST_ITEREATION; ctr++)
    {
        ftp_test_monitor_reset(&monitor);

        /*
         *  initialize test info structure
         */
        test_info = &test_info_array[ctr];
        test_info->monitor = &monitor;
        strcpy(test_info->fname, g_tmp_file);
        strcat(test_info->fname, ".   ");
        sprintf(&test_info->fname[strlen(test_info->fname) - 3],
                "%d", ctr);

#ifdef STOR_TEST
        /*
         * local_port/pasv()
         */
        globus_ftp_control_host_port_init(&host_port, "localhost", 0);
        res = send_pasv_cmd(&handle);
        test_result(res, "send pasv");

        ftp_test_monitor_reset(&monitor);
        mode_cb(&handle);

        GlobusTimeAbstimeGetCurrent(start_time);
        res = globus_ftp_control_send_command(
                  &handle, 
                  "STOR %s\r\n",
                  stor_callback,
                  (void*)&monitor,
                  g_server_file);
        test_result(res, "send STOR command");

        res = globus_ftp_control_data_connect_write(
                  &handle,
                  connect_write_callback,
                  (void *)test_info);
        test_result(res, "connect_write");

        /*
         *  wait for end
         */
        verbose_printf(2, "waiting for end\n");
        globus_mutex_lock(&monitor.mutex);
        {
            while(monitor.count < WAIT_COUNT /* && !monitor.done */ )
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);

        GlobusTimeAbstimeGetCurrent(end_time);
        GlobusTimeAbstimeDiff(diff_time, end_time, start_time);

        tm = diff_time.tv_sec * 1000000;
        tm += diff_time.tv_usec;
        secs = (float)tm / 1000.0;
        rate = (float)g_file_size / secs;
        verbose_printf(1, "sent     %d bytes in %8.2f secs, at %8.2fKB/s\n",
                       g_file_size, secs,
                       rate);
#endif

#ifdef RETR_TEST
        ftp_test_monitor_reset(&monitor);

        res = send_port_cmd(&handle);
        test_result(res, "send_port failed");

        mode_cb(&handle);
        res = globus_ftp_control_send_command(
                  &handle, 
                  "RETR %s\r\n",
                  retr_callback,
                  (void*)&monitor,
                  g_server_file);
        test_result(res, "send RETR command");

        res = globus_ftp_control_data_connect_read(
                  &handle,
                  connect_read_callback,
                  (void *)test_info);
        test_result(res, "connect_read");

        /*
         *  wait for end
         */
        verbose_printf(2, "waiting for end\n");

        globus_mutex_lock(&monitor.mutex);
        {
            while(monitor.count < 2 /* && !monitor.done */ )
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);

#endif
    } /* for */

    disconnect_control_handle(&handle);
    res = globus_ftp_control_handle_destroy(&handle);
    test_result(res, "deactivate");

    verbose_printf(2, "ending\n");

    return GLOBUS_SUCCESS;
}

void
connect_read_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error)
{
    data_test_info_t *                         test_info;
    struct stat                                stat_info;
    int                                        write_blk_size;
    int                                        blk_size;
    globus_byte_t *                            buf;
    globus_result_t                            res;

    if ( stripe_ndx != 0 )
        return;
 
    test_info = (data_test_info_t *)callback_arg;
   
    verbose_printf(3, "connect_read_callback() : start\n"); 
    if(error != GLOBUS_NULL)
    {
        test_result(globus_error_put(error), "connect_read_callback error");
    }

    globus_mutex_lock(&test_info->monitor->mutex);
    {
        test_info->fout = fopen(test_info->fname, "w");
        if(test_info->fout == GLOBUS_NULL)
        {
            failure_end("fopen failed\n");
        }
        if(stat(g_test_file, &stat_info) < 0)
        {
            failure_end("stat failed\n");
        }
        write_blk_size = stat_info.st_size / WRITE_CHUNK_COUNT + 1; 
        blk_size = write_blk_size / 2 + 1;

        buf = (globus_byte_t *)malloc(blk_size);
        res = globus_ftp_control_data_read(
                  handle,
                  buf,
                  blk_size,
                  data_read_callback,
                  (void *)test_info);
        test_result(res, "data_read");
    }
    globus_mutex_unlock(&test_info->monitor->mutex);

}

void 
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    data_test_info_t *                          test_info; 
    globus_result_t                             res;
    int                                         blk_size;
    globus_byte_t *                             buf;

    verbose_printf(3, "data_read_callback() : start\n"); 
    if(error != GLOBUS_NULL)
    {
        test_result(globus_error_put(error), "data_read_callback error\n");
    }
    test_info = (data_test_info_t *)callback_arg;
    globus_mutex_lock(&test_info->monitor->mutex);
    {
        verbose_printf(3, "seeking to %ld\n", (long) offset);
        if(fseek(test_info->fout, offset, SEEK_SET) != 0)
        {
            verbose_printf(1, "errno %d %d %d\n", errno, EBADF, EINVAL);
            failure_end("seek failed\n");
        }
        if(fwrite(buffer, 1, length, test_info->fout) != length)
        {
            failure_end("fwrite failed\n");
        }

        if(eof)
        {
            verbose_printf(2, "EOF received\n");
            verbose_printf(2, "closing the out stream\n");
            fclose(test_info->fout);

            {
                verbose_printf(2, "files are the same\n");
                test_info->monitor->count++;
                globus_cond_signal(&test_info->monitor->cond);
            }
        }
        else
        {
            /* add some stuff to the length */
            blk_size = length + (rand() % length);
            buf = globus_malloc(blk_size);
            res = globus_ftp_control_data_read(
                      handle,
                      buf,
                      blk_size,
                      data_read_callback,
                      (void *)test_info);
            test_result(res, "data_read");
        }
    }
    globus_mutex_unlock(&test_info->monitor->mutex);

    globus_free(buffer);
}

void
connect_write_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error)
{
    data_test_info_t *                         test_info;
    struct stat                                stat_info;
    int                                        blk_size;
    globus_off_t                               offset = 0;
    int                                        nbyte;
    globus_byte_t *                            buf;
    globus_bool_t                              eof = GLOBUS_FALSE;
    globus_result_t                            res;
    int                                        ctr;
    globus_size_t                              connections;

    if ( stripe_ndx != 0 )
        return;

    test_info = (data_test_info_t *)callback_arg;

    verbose_printf(3, "connect_write_callback() : start stripe=%u\n",
                    stripe_ndx);
    if(error != GLOBUS_NULL)
    {
        verbose_printf(1, "error:%s\n",
            globus_object_printable_to_string(error));
        failure_end("connect_write_callback error\n");
    }

    globus_mutex_lock(&test_info->monitor->mutex);
    {
        test_info->fin = fopen(g_test_file, "r");
        if(test_info->fin == GLOBUS_NULL)
        {
            failure_end("fopen failed\n");
        }
        if(stat(g_test_file, &stat_info) < 0)
        {
            failure_end("stat failed\n");
        }
       
        blk_size = stat_info.st_size / WRITE_CHUNK_COUNT + 1; 
        eof = GLOBUS_FALSE;
        ctr = 0;
        while(!eof)
        {
            buf = globus_malloc(blk_size);
            assert(buf != GLOBUS_NULL);
            /*
             *  read a chunk
             */
            nbyte = fread(buf, 1, blk_size, test_info->fin); 
            if(nbyte != blk_size)
            {
                if(feof(test_info->fin))
                {
                    verbose_printf(2, "registering eof\n");
                    fclose(test_info->fin);
                    eof = GLOBUS_TRUE;

#if defined(SEND_EOF)
                    ia[0] = 0;
                   globus_ftp_control_data_send_eof(
                        handle,
                        ia,
                        1,
                        eof_callback,
                        callback_arg);
#endif
                }
                else
                {
                    failure_end("fread failed\n");
                }
            }
            /*
             *  write a chunk
             */
            verbose_printf(3, "registering a write 0x%x offset=%ld length=%d eof=%d callbacks registered=%d\n",
                          buf, (long int) offset, nbyte, eof, ctr);
            res = globus_ftp_control_data_write(
                      handle,
                      buf,
                      nbyte,
                      offset,
                      eof,
                      data_write_callback, 
                      (void *)test_info);
            test_result(res, "data_write");
            offset += nbyte;
            ctr++;

        res = globus_ftp_control_data_get_total_data_channels(
                    handle,
                    &connections,
                    0);
            if(ctr % connections == 0)
            {
                globus_poll();
            }
        }
    }
    globus_mutex_unlock(&test_info->monitor->mutex);
}

void 
eof_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error)
{
    data_test_info_t *                         test_info;

    test_info = (data_test_info_t *)callback_arg;

    verbose_printf(2, "eof_callback() : start\n");
        globus_mutex_lock(&test_info->monitor->mutex);
        {
            test_info->monitor->count++;
            globus_cond_signal(&test_info->monitor->cond);
        }
        globus_mutex_unlock(&test_info->monitor->mutex);
}


void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset2,
    globus_bool_t                               eof)
{
    data_test_info_t *                         test_info;

    test_info = (data_test_info_t *)callback_arg;

    verbose_printf(3, "data_write_callback() : start\n");
    if(error != GLOBUS_NULL)
    {
        verbose_printf(1, "write callback error:%s\n",
            globus_object_printable_to_string(error));
        failure_end("data_write_callback error\n");
    }

    if(eof)
    {
        verbose_printf(2, "data_write_callback() : eof has been reached\n");

        globus_mutex_lock(&test_info->monitor->mutex);
        {
            test_info->monitor->count++;
            globus_cond_signal(&test_info->monitor->cond);
        }
        globus_mutex_unlock(&test_info->monitor->mutex);
    }
    globus_free(buffer);
}

void
failure_end(
    char *                                      msg)
{
    verbose_printf(1, "%s\n", msg);
    verbose_printf(1, "test #%d failed\n", g_test_count);
    assert(GLOBUS_FALSE);
}

void
test_result(
    globus_result_t                             res,
    char *                                      msg)
{
    if(res != GLOBUS_SUCCESS)
    {
        verbose_printf(1, "error:%s\n",
            globus_object_printable_to_string(globus_error_get(res)));
        failure_end(msg);
    }
}

globus_bool_t
spas_to_host_port(
    char *                                      astr,
    globus_ftp_control_host_port_t *            addr,
    int *                   cnt)
{   
    char *                                      hostname;
    char *                                      port_str;
    char *                                      tmp_ptr;
    unsigned short                              port;
    int                                         hi;
    int                                         low;
    int                                         ctr;
    int                                         i=0;
    
    
    hostname = strchr(astr, '(');
    
    while ((hostname != NULL))
    {
    hostname++;
    
        tmp_ptr = strchr(hostname, ',');
        for(ctr = 0; ctr < 3; ctr++)
        {
            if(tmp_ptr == GLOBUS_NULL)
            {
                return GLOBUS_FALSE;
            }   
            tmp_ptr[0] = '.';
            tmp_ptr++; 
            tmp_ptr = strchr(tmp_ptr, ',');
        }   
        
        tmp_ptr[0] = '\0';
        port_str = tmp_ptr + 1;
        
        sscanf(port_str, "%d,%d", &hi, &low);
        port = hi * 256; 
        port = port | low;
        
        
        fprintf(stderr,"initing %s, %d\n", hostname, port);
        
        globus_ftp_control_host_port_init(
            &addr[i],
            hostname,
            port);
            
        hostname=++tmp_ptr;
        hostname = strchr(hostname, '(');
    i++;
   }
    
    *cnt=i;
    return GLOBUS_TRUE;
}   


