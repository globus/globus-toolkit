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
#include <ctype.h>
#include "test_common.h"

#define TEST_ITEREATION                         1
#define WRITE_CHUNK_COUNT                       32

typedef void (*set_handle_mode_cb_t)(
    globus_ftp_control_handle_t *               handle);

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
binary_eb_mode(
    globus_ftp_control_handle_t *               handle);

void 
binary_stream_mode(
    globus_ftp_control_handle_t *               handle);

static int                                g_parallel;
static char *                             g_host_r;
static int                                g_port_r;
static char *                             g_login_r;
static char *                             g_password_r;
static char *                             g_file_r;

static char *                             g_host_s;
static int                                g_port_s;
static char *                             g_login_s;
static char *                             g_password_s;
static char *                             g_file_s;

static int                                g_file_size;
static int                                g_test_count = 0;

    globus_ftp_control_host_port_t              g_addr;

void
port_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    ftp_test_monitor_t *                        monitor;

    monitor = (ftp_test_monitor_t *)callback_arg;

verbose_printf(2, "port_response_callback() : start %s\n", ftp_response->response_buffer);
    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            verbose_printf(2, "port_response_callback(): error in callback\n");
            monitor->result = globus_error_put(error);
        }
        else if(ftp_response->code != 200)
        {
            verbose_printf(2, "port_response_callback(): %d != 200\n",
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
    globus_ftp_control_handle_t *               port_handle;
    int                                         hi;
    int                                         low;
    int                                         ctr;

    monitor = (ftp_test_monitor_t *)callback_arg;

verbose_printf(2, "pasv_response_callback() : start %s\n", ftp_response->response_buffer);
    globus_mutex_lock(&monitor->mutex);
    {
        if(ftp_response->code == 227)
        {
            port_handle = (globus_ftp_control_handle_t *)monitor->user_arg;

            pasv_to_host_port(ftp_response->response_buffer, &addr);

            hi = addr.port / 256;
            low = addr.port % 256;
            res = globus_ftp_control_send_command(
                      port_handle,
                      "PORT %d,%d,%d,%d,%d,%d\r\n",
                      port_response_callback,
                      (void*)monitor,
                      addr.host[0],
                      addr.host[1],
                      addr.host[2],
                      addr.host[3],
                      hi,
                      low);

            verbose_printf(2, "sending PORT %d,%d,%d,%d,%d,%d %d\n",
                      addr.host[0],
                      addr.host[1],
                      addr.host[2],
                      addr.host[3],
                      hi,
                      low, addr.port);
            test_result(res, "send port command");
        }
        else if(ftp_response->code == 229)
        {
            int                               server_count = 16;
            int                               server_ndx = 0;
            char                              server_buf[2024];

            port_handle = (globus_ftp_control_handle_t *)monitor->user_arg;

            spas_to_host_port(
                ftp_response->response_buffer, spas_addr, &server_count);

            sprintf(&server_buf[server_ndx], "SPOR");
                server_ndx = strlen(server_buf);
            for(ctr = 0; ctr < server_count; ctr++)
            {
                hi = spas_addr[ctr].port / 256;
                low = spas_addr[ctr].port % 256;

                sprintf(&server_buf[server_ndx],
                          " %d,%d,%d,%d,%d,%d",
                          spas_addr[ctr].host[0],
                          spas_addr[ctr].host[1],
                          spas_addr[ctr].host[2],
                          spas_addr[ctr].host[3],
                          hi,
                          low);
                server_ndx = strlen(server_buf);
            }

            verbose_printf(2, "%s -- %d -- %s\n", server_buf, server_count, ftp_response->response_buffer);
            res = globus_ftp_control_send_command(
                      port_handle,
                      "%s\r\n",
                      port_response_callback,
                      (void*)monitor,
                      server_buf);
            test_result(res, "send port command");
        }
        else
        {
            monitor->result = globus_error_put(GLOBUS_ERROR_NO_INFO);
            monitor->done = GLOBUS_TRUE;
            globus_cond_signal(&monitor->cond);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
}

globus_result_t
send_pasv_cmd(
    globus_ftp_control_handle_t *               send_handle,
    globus_ftp_control_handle_t *               receive_handle)
{
    globus_result_t                             res;
    ftp_test_monitor_t                          monitor;

    ftp_test_monitor_init(&monitor);
    monitor.user_arg = (void *)send_handle;
    res = globus_ftp_control_send_command(
               receive_handle,
               "SPAS\r\n",
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

int 
main(
    int                                         argc,
    char *                                      argv[])
{ 
    globus_result_t                             res;
    int                                         ctr;

    g_parallel = 4;
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
        else if(strcmp(argv[ctr], "--host-receive") == 0 && ctr + 2 <= argc)
        {
            ctr++;
            g_host_r = argv[ctr];
            ctr++;
            g_port_r = (unsigned short)atoi(argv[ctr]);
        }
        else if(strcmp(argv[ctr], "--host-send") == 0 && ctr + 2 <= argc)
        {
            ctr++;
            g_host_s = argv[ctr];
            ctr++;
            g_port_s = (unsigned short)atoi(argv[ctr]);
        }
        else if(strcmp(argv[ctr], "--login-send") == 0 && ctr + 3 <= argc)
        {
            ctr++;
            g_login_s = argv[ctr];
            ctr++;
            g_password_s = argv[ctr];
            ctr++;
            g_file_s = argv[ctr];
        }
        else if(strcmp(argv[ctr], "--login-receive") == 0 && ctr + 3 <= argc)
        {
            ctr++;
            g_login_r = argv[ctr];
            ctr++;
            g_password_r = argv[ctr];
            ctr++;
            g_file_r = argv[ctr];
        }
        else if(strcmp(argv[ctr], "--p") == 0 && ctr + 1 <= argc)
        {
            ctr++;
            g_parallel = atoi(argv[ctr]);
        }
    }

    /*
     *  activate
     */
    res = (globus_result_t)globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    test_result(res, "globus_module_activate failed");

#if 0
    g_test_count++;
    verbose_printf(1, "------------------------------------\n");
    verbose_printf(1, "running transfer test in stream mode\n");
    transfer_test(binary_stream_mode);
    verbose_printf(1, "transfer test in stream mode passed\n");
    verbose_printf(1, "------------------------------------\n");
#endif

#if 1
    g_test_count++;
    verbose_printf(1, "------------------------------------\n");
    verbose_printf(1, "running transfer test in eb mode\n");
    transfer_test(binary_eb_mode);
    verbose_printf(1, "transfer test in eb mode passed\n");
    verbose_printf(1, "------------------------------------\n");
#endif

    res = (globus_result_t)globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);
    test_result(res, "deactivate");

    verbose_printf(1, "%d tests passed.\n", g_test_count);
    printf("Success.\n");
    return 0;
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
verbose_printf(1, "parallelism set to %d\n", g_parallel);
    /* send layout options */
    globus_mutex_unlock(&monitor.mutex);
    ftp_test_monitor_reset(&monitor);
    globus_ftp_control_send_command(
              handle,
/*              "OPTS RETR StripeLayout=Blocked;BlockSize=65536;\r\n",
*/              "OPTS RETR StripeLayout=Partitioned;\r\n",
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

    parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
    parallelism.fixed.size = g_parallel;
    res = globus_ftp_control_local_parallelism(
              handle, 
              &parallelism);
    test_result(res, "local_parallel");

    /*
     *  set sok buffer size
     */
    ftp_test_monitor_reset(&monitor);
    globus_ftp_control_send_command(
              handle, 
              "SITE BUFSIZE %d\r\n",
              signal_callback,
              (void*)&monitor,
              2500000);
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
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

void
retr_callback(
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
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }
        else if(ftp_response->code == 226)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }
        else if(ftp_response->code >= 500)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }

        if(error == GLOBUS_NULL)
        {
            verbose_printf(2, "retr callback : %s\n", 
                ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&monitor->mutex);

}

void
stor_callback(
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
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }
        else if(ftp_response->code == 226)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }
        else if(ftp_response->code >= 500)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
        }
        /* performance marker */
        else if(ftp_response->code == 112)
        {
            char *                            tmp_ptr;
            float                             throughput;
   
            tmp_ptr = strstr(ftp_response->response_buffer, "AllThroughput:");

            tmp_ptr += strlen("AllThroughput:");

            sscanf(tmp_ptr, "%f", &throughput);

            throughput = throughput / 1000000.0 * 8.0;

            verbose_printf(1, "Throughput = %9.3fMbit/s\n", throughput);
        }

        if(error == GLOBUS_NULL)
        {
            verbose_printf(2, "stor callback : %s\n", 
                ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
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
    globus_ftp_control_handle_t             send_handle;
    globus_ftp_control_handle_t             receive_handle;
    ftp_test_monitor_t                      monitor; 
    globus_size_t                           tm;
    float                                   rate;
    float                                   secs;
    globus_bool_t                           brc;
    globus_abstime_t                        start_time;
    globus_abstime_t                        end_time;
    globus_reltime_t                        diff_time;

    ftp_test_monitor_init(&monitor); 

    res = globus_ftp_control_handle_init(&send_handle);
    test_result(res, "send handle init");
    brc = connect_control_handle(
              &send_handle,
              g_login_s,
              g_password_s,
              "/",
              g_host_s,
              g_port_s);
    verbose_printf(2, "connect %d\n", brc);
    
    res = globus_ftp_control_handle_init(&receive_handle);
    test_result(res, "receive handle init");
    brc = connect_control_handle(
              &receive_handle,
              g_login_r,
              g_password_r,
              "/",
              g_host_r,
              g_port_r);
    verbose_printf(2, "connect %d\n", brc);

    verbose_printf(2, "both control connections have been esstaclished\n");

    for(ctr = 0; ctr < TEST_ITEREATION; ctr++)
    {
        send_pasv_cmd(&send_handle, &receive_handle);
        ftp_test_monitor_reset(&monitor);

        mode_cb(&receive_handle);
        mode_cb(&send_handle);

        GlobusTimeAbstimeGetCurrent(start_time);
        verbose_printf(2, "sending STOR\n");
        res = globus_ftp_control_send_command(
                  &receive_handle, 
                  "STOR %s\r\n",
                  stor_callback,
                  (void*)&monitor,
                  g_file_r);
        test_result(res, "send STOR command");

        verbose_printf(2, "sending RETR\n");
        res = globus_ftp_control_send_command(
                  &send_handle, 
                  "RETR %s\r\n",
                  retr_callback,
                  (void*)&monitor,
                  g_file_s);
        test_result(res, "send STOR command");

        /*
         *  wait for end
         */
        verbose_printf(2, "waiting for end\n");
        globus_mutex_lock(&monitor.mutex);
        {
            while(monitor.count < 2)
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

    } /* for */

    disconnect_control_handle(&send_handle);
    res = globus_ftp_control_handle_destroy(&send_handle);
    test_result(res, "deactivate");

    disconnect_control_handle(&receive_handle);
    res = globus_ftp_control_handle_destroy(&receive_handle);
    test_result(res, "deactivate");

    verbose_printf(2, "ending\n");

    return GLOBUS_SUCCESS;
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
    char *                                      tmp_ptr;
    unsigned short                              port;
    int                                         hi;
    int                                         low;
    int                                         ret;
    int                                         i=0;
    globus_bool_t                               done = GLOBUS_FALSE;
    
    int a, b, d, c;
 
    hostname = strchr(astr, '(');

    hostname = strstr(astr, "229-Entering Striped Passive Mode\r\n");
    hostname += strlen("229-Entering Striped Passive Mode\r\n");
    hostname++;
    
    while (!done)
    {
        ret = sscanf(hostname, "%d,%d,%d,%d,%d,%d",  
                &a, &b, &c, &d, &hi, &low);

        if(ret == 6)
        {
            port = hi * 256; 
            port = port | low;
        
        fprintf(stderr,"initing %s, %d\n", hostname, port);
       
        addr[i].host[0] = a;
        addr[i].host[1] = b;
        addr[i].host[2] = c;
        addr[i].host[3] = d;
        addr[i].port = port;

        tmp_ptr = hostname;
        while(!isdigit(tmp_ptr[0]))
        {
            tmp_ptr++;
        }
        hostname = strstr(tmp_ptr, " ");
        fprintf(stderr,"after %s\n", hostname);
       
        
        i++;
        }
        else
        {
            done = GLOBUS_TRUE;
        }
        if(hostname == GLOBUS_NULL)
        {
            done = GLOBUS_TRUE;
        }
   }
    
    *cnt=i;
    return GLOBUS_TRUE;
}   


