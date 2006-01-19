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

#define STOR_TEST                               1
#define WAIT_COUNT 2

typedef void (*set_handle_mode_cb_t)(
    globus_ftp_control_handle_t *               handle);

globus_size_t                                   g_file_size;
typedef struct data_test_info_s
{
    char                                        a[2024];
    FILE *                                      fin;
    char                                        c[2024];
    FILE *                                      fout;
    char                                        b[2024];
    ftp_test_monitor_t *                        monitor;
    int count;
} data_test_info_t;

static float                                    g_total_throughput = 0.0;
static int                                      g_throughput_count = 0;

static int                                      g_test_count = 0;
static char *                                   g_remote_file = GLOBUS_NULL;
static char *                                   g_local_file = GLOBUS_NULL;

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
put_test(
    set_handle_mode_cb_t                       mode_cb);

void
failure_end(
    char *                                      msg);

void
connect_write_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

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
binary_eb_mode(
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

int 
main(
    int                                         argc,
    char *                                      argv[])
{ 
    globus_result_t                             res;
    int                                         ctr;

    g_parallel = 1;
    g_local_file = argv[0];
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
        else if(strcmp(argv[ctr], "--local-file") == 0 && ctr + 1 <= argc)
        {
            g_local_file = argv[ctr + 1];
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
            g_remote_file = argv[ctr];
        }
        else if(strcmp(argv[ctr], "--p") == 0 && ctr + 3 <= argc)
        {
            ctr++;
            g_parallel = atoi(argv[ctr]);
        }
    }

    {
       struct stat stat_s;
       stat(g_local_file, &stat_s);
       g_file_size = stat_s.st_size;
    }
    /*
     *  activate
     */
    res = (globus_result_t)globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    test_result(res, "globus_module_activate failed");

    put_test(binary_eb_mode);

    res = (globus_result_t)globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);

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

globus_result_t
put_test(
    set_handle_mode_cb_t                       mode_cb)
{
    int                                     ctr;
    globus_result_t                         res;
    globus_ftp_control_host_port_t          host_port;
    globus_ftp_control_handle_t             handle;
    data_test_info_t *                      test_info;
    data_test_info_t                        test_info_array[TEST_ITEREATION];
    ftp_test_monitor_t                      monitor; 
    struct stat                             stat_info;
    globus_size_t                           filesize;

    stat(g_local_file, &stat_info);
    filesize = stat_info.st_size;

    ftp_test_monitor_init(&monitor); 

    res = globus_ftp_control_handle_init(&handle);
    test_result(res, "port handle init");
    connect_control_handle(
            &handle,
            g_login,
            g_password,
            "./",
            g_host,
            g_port);

    for(ctr = 0; ctr < TEST_ITEREATION; ctr++)
    {
        ftp_test_monitor_reset(&monitor);

        /*
         *  initialize test info structure
         */
        test_info = &test_info_array[ctr];
        test_info->monitor = &monitor;
        test_info->count = 0;

        /*
         * local_port/pasv()
         */
        globus_ftp_control_host_port_init(&host_port, "localhost", 0);
        res = send_pasv_cmd(&handle);
        test_result(res, "send pasv");

        ftp_test_monitor_reset(&monitor);
        mode_cb(&handle);

        res = globus_ftp_control_send_command(
                  &handle, 
                  "STOR %s\r\n",
                  stor_callback,
                  (void*)&monitor,
                  g_remote_file);
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

    } /* for */

    disconnect_control_handle(&handle);
    res = globus_ftp_control_handle_destroy(&handle);
    test_result(res, "deactivate");

    verbose_printf(2, "ending\n");

    return GLOBUS_SUCCESS;
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
    int                                        offset = 0;
    int                                        nbyte;
    globus_byte_t *                            buf;
    globus_bool_t                              eof = GLOBUS_FALSE;
    globus_result_t                            res;
    int                                        ctr;

    if ( stripe_ndx != 0 )
        return;

    test_info = (data_test_info_t *)callback_arg;

    verbose_printf(2, "connect_write_callback() : start stripe=%u\n",
                    stripe_ndx);
    if(error != GLOBUS_NULL)
    {
        verbose_printf(1, "error:%s\n",
            globus_object_printable_to_string(error));
        failure_end("connect_write_callback error\n");
    }

    globus_mutex_lock(&test_info->monitor->mutex);
    {
        test_info->count = 0;
        test_info->fin = fopen(g_local_file, "r");
        if(test_info->fin == GLOBUS_NULL)
        {
            failure_end("fopen failed\n");
        }
        if(stat(g_local_file, &stat_info) < 0)
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
            globus_poll();
            if(nbyte != blk_size)
            {
                if(feof(test_info->fin))
                {
                    verbose_printf(2, "registering eof\n");
                    fclose(test_info->fin);
                    eof = GLOBUS_TRUE;
                }
                else
                {
                    failure_end("fread failed\n");
                }
            }
            /*
             *  write a chunk
             */
            verbose_printf(3, "registering a write 0x%x offset=%d length=%d eof=%d callbacks registered=%d\n",
                          buf, offset, nbyte, eof, ctr);
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

            if(ctr == 4)
            {
                globus_mutex_lock(&test_info->monitor->mutex);
                while(test_info->count != ctr)
                {
                    globus_cond_wait(&test_info->monitor->cond,
                                     &test_info->monitor->mutex);
                }
                globus_mutex_unlock(&test_info->monitor->mutex);
                ctr  = 0;
                test_info->count = 0;
            }
            globus_poll();
        }
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
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    data_test_info_t *                         test_info;

    test_info = (data_test_info_t *)callback_arg;

    verbose_printf(3, "data_write_callback() : start %d\n", test_info->count);
    if(error != GLOBUS_NULL)
    {
        verbose_printf(1, "write callback error:%s\n",
            globus_object_printable_to_string(error));
        failure_end("data_write_callback error\n");
    }

            test_info->count++;
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


