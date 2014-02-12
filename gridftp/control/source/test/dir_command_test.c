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

#include "globus_ftp_control.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>

void 
control_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void 
command_sent_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void
list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof);

void 
read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof);

void 
write_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof);

globus_bool_t
pasv_to_host_port(
    char *                                      parse_str,
    globus_ftp_control_host_port_t *            addr);


globus_bool_t
host_port_to_port(
    globus_ftp_control_host_port_t *            addr,
    char                                        str[23]);

globus_result_t
process_user_input(
    globus_ftp_control_handle_t *               handle);

#define DIRECTION_NONE                          0
#define DIRECTION_GET                           1
#define DIRECTION_PUT                           2
#define DIRECTION_LIST                          3

#define BUFFER_SIZE                             1024

typedef struct get_put_info_s
{
    char                                        local_name[512];
    char                                        remote_name[512];
    int                                         direction;
    int                                         buffer_size;
    globus_io_handle_t                          handle;
    globus_bool_t                               opened;
    globus_byte_t *                             buffer;
} get_put_info_t;

globus_result_t 
start_write(
    globus_ftp_control_handle_t *               handle,
    get_put_info_t *                            get_put_info);

globus_bool_t
host_port_to_port(
    globus_ftp_control_host_port_t *            addr, 
    char                                        str[23]);

globus_mutex_t                                  end_mutex;
globus_cond_t                                   end_cond;
globus_bool_t                                   end_done;

globus_mutex_t                                  data_mutex;
globus_cond_t                                   data_cond;
globus_bool_t                                   data_done;

    globus_ftp_control_auth_info_t              auth;

int
dir_command_test(
    globus_ftp_control_handle_t*         handle)
{
    char *                                 hostname;
    unsigned short                         port;
    globus_result_t                        result;

 
    globus_mutex_init(&end_mutex, GLOBUS_NULL);
    globus_cond_init(&end_cond, GLOBUS_NULL);
    end_done = GLOBUS_FALSE;

    globus_mutex_init(&data_mutex, GLOBUS_NULL);
    globus_cond_init(&data_cond, GLOBUS_NULL);
    data_done = GLOBUS_FALSE;

   
    result = globus_ftp_control_connect(
                 handle,
                 "ftp.globus.org",
                 21,
                 control_response_callback,
                 GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        printf("error: could not connect\n");
        exit(1);
    }

    /*
     *  wait for completion
     */
    globus_mutex_lock(&end_mutex);
    {
        while(!end_done)
        {
            globus_cond_wait(&end_cond, &end_mutex);
        }
    }
    globus_mutex_unlock(&end_mutex);
    
    globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);
}

/*
 *  callback for all responses from the server
 */
void 
control_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_bool_t                               done;
    globus_ftp_control_host_port_t              addr;
    char                                        name[512];
    globus_result_t                             result;
    int                                         ctr;


printf("response code %d\n", ftp_response->code);
    /*
     *  if an error occurred end the program.
     */
    if(error != GLOBUS_NULL)
    {
        printf("an error occurred\n");
        globus_mutex_lock(&end_mutex);
        {
            end_done = GLOBUS_TRUE;
            globus_cond_signal(&end_cond);
        }
        globus_mutex_unlock(&end_mutex);
        
        return;
    }

    /* get the command from the user */
    /* request user name */
    if(ftp_response->code == 220 || 
       ftp_response->code == 530)
    {
        printf("%s\n", ftp_response->response_buffer);
        printf("Enter User Name:");
        fflush(stdout);
        gets(name);
        auth.user = strdup(name);

        auth.auth_gssapi_subject = GLOBUS_NULL;
        auth.auth_gssapi_context = GLOBUS_NULL;
        
        printf("Enter password:");
        fflush(stdout);
        gets(name);
        auth.password = strdup(name);

        result= globus_ftp_control_authenticate(
	    handle, 
	    &auth,
	    GLOBUS_FALSE,
	    control_response_callback, 
	    GLOBUS_NULL);
	assert(result==GLOBUS_SUCCESS);
    }
    /* request password */
    else if(ftp_response->code == 331)
    {
        printf("password\n");
    }
    /* password accepted, set to pasv mode */
    else if(ftp_response->code == 230 ||
            ftp_response->code == 226 ||
            ftp_response->code == 550)
    {
/*        int hi, low;
        globus_ftp_control_host_port_init(&addr, "localhost", 0);

        result = globus_ftp_control_local_pasv(handle, &addr);
 
        hi = addr.port / 256;
        low = addr.port - (hi * 256);
        result = globus_ftp_control_send_command(
            handle,
            "PORT 127,0,0,1,%d,%d\r\n",
            control_response_callback,
            GLOBUS_NULL,
            hi, low);
        if(result != GLOBUS_SUCCESS)
        {
            printf("send_command PORT failed\n"); 
            exit(1);
        }
*/

        /* wait to be sure all data is received  if it is a receive reply */
        if(ftp_response->code == 226)
        {
            globus_mutex_lock(&data_mutex);
            {
                while(!data_done)
                {
                    globus_cond_wait(&data_cond, &data_mutex);
                }
            }
            globus_mutex_unlock(&data_mutex);
        }

        result = globus_ftp_control_send_command(
            handle, 
            "PASV\r\n",
            control_response_callback,
            GLOBUS_NULL);
        if(result != GLOBUS_SUCCESS)
        {
            printf("send_command PASV failed\n"); 
            exit(1);
        }
    }
    /* the response for to the pasv call */
    else if(ftp_response->code == 227)
    {
      printf(" response of pasv call\n");
      printf("buf %s\n",ftp_response->response_buffer);
      pasv_to_host_port(ftp_response->response_buffer, &addr);
        result = globus_ftp_control_local_port(handle, &addr);
        if(result != GLOBUS_SUCCESS)
        {
            printf("error:%s\n", ftp_response->response_buffer);
            printf("local_port() failed\n");
        }
        process_user_input(handle);
    }
    else if(ftp_response->code == 221)
    {
        printf("%s", ftp_response->response_buffer);
        printf("later dude\n");
        globus_mutex_lock(&end_mutex);
        {
            end_done = GLOBUS_TRUE;
            globus_cond_signal(&end_cond);
        }
        globus_mutex_unlock(&end_mutex);
    }
    else if(ftp_response->code == 150)
    {
        get_put_info_t *                            get_put_info; 

        get_put_info = (get_put_info_t *)callback_arg;
        printf("data conection check\n");

	/* pending test check over here */
        /* pending_response_test(handle);*/

	printf("buf%s", ftp_response->response_buffer);
        if(get_put_info->direction == DIRECTION_GET)
        {
            globus_ftp_control_data_read(
                handle,
                get_put_info->buffer,
                get_put_info->buffer_size,
                read_data_callback,
                (void *) get_put_info);
        }
        else if(get_put_info->direction == DIRECTION_PUT)
        {
            start_write(handle, get_put_info);
        }
        else if(get_put_info->direction == DIRECTION_LIST)
        {
            globus_ftp_control_data_read(
                handle,
                get_put_info->buffer,
                get_put_info->buffer_size,
                list_read_data_callback,
                (void *) get_put_info);
        }
    }
    else if(ftp_response->code == 426)
    {
        printf("%s", ftp_response->response_buffer);
    }
    else
    {
        printf("%s", ftp_response->response_buffer);
        process_user_input(handle);
    }
}

/*
 * allow: get, put, pwd, cdup, cwd, bin ascii ls
 */
globus_result_t
process_user_input(
    globus_ftp_control_handle_t *               handle)
{
    char                                        in_buf[512];
    char                                        tmp_buf[512];
    char                                        first_arg[512];
    char                                        second_arg[512];
    globus_ftp_control_host_port_t              addr;
    globus_bool_t                               done;
    globus_result_t                             result;
    get_put_info_t *                            get_put_info; 
    int                                         scan_count;
    char *                                      tmp_ptr;

    done = GLOBUS_FALSE;


    while(!done)
    {
        done = GLOBUS_TRUE;
        printf("ftp> ");
        fflush(stdout);

        tmp_ptr = gets(in_buf);
	printf("in_buf is %s\n",in_buf);
        if(tmp_ptr == NULL)
        {
            done = GLOBUS_FALSE;

            /* bad coder, bad bad coder */
            continue;
        }

        memset(tmp_buf, 0, 512);
        sscanf(in_buf, "%s", tmp_buf);
        if(strcmp(tmp_buf, "get") == 0)
        {
            scan_count = sscanf(&in_buf[3], "%s %s", first_arg, second_arg);
            if(scan_count < 1)
            {
                printf("you must include a filename"); 
                done = GLOBUS_FALSE;
            }
            else
            {
                get_put_info = (get_put_info_t *)
                                  globus_malloc(sizeof(get_put_info_t));
                strcpy(get_put_info->remote_name, first_arg);
                if(scan_count == 2)
                {
                    strcpy(get_put_info->local_name, second_arg);
                }
                else
                {
                    strcpy(get_put_info->local_name, first_arg);
                }
                get_put_info->direction = DIRECTION_GET;
                get_put_info->opened = GLOBUS_FALSE;
                get_put_info->buffer_size = BUFFER_SIZE;
                get_put_info->buffer = globus_malloc(BUFFER_SIZE);

                globus_mutex_lock(&data_mutex);
                {
                    data_done = GLOBUS_FALSE;
                }
                globus_mutex_unlock(&data_mutex);
                result = globus_ftp_control_send_command(
                             handle, 
                             "RETR %s\r\n",
                             control_response_callback,
                             (void *)get_put_info,
                             get_put_info->remote_name);
                if(result != GLOBUS_SUCCESS)
                {
                    return result; 
                }

                result = globus_ftp_control_data_connect_read(
                             handle, GLOBUS_NULL, GLOBUS_NULL);
                if(result != GLOBUS_SUCCESS)
                {
                    return result; 
                }
            }
        }   
        else if(strcmp(tmp_buf, "put") == 0)
        {
            scan_count = sscanf(&in_buf[3], "%s %s", first_arg, second_arg);
            if(scan_count < 1)
            {
                printf("you must include a filename"); 
                done = GLOBUS_FALSE;
            }
            else
            {
                get_put_info = (get_put_info_t *)
                                   globus_malloc(sizeof(get_put_info_t));

                if(scan_count == 2)
                {
                    strcpy(get_put_info->local_name, first_arg);
                    strcpy(get_put_info->remote_name, second_arg);
                }
                else
                {
                    strcpy(get_put_info->local_name, first_arg);
                    strcpy(get_put_info->remote_name, first_arg);
                }
                get_put_info->direction = DIRECTION_PUT;
                get_put_info->opened = GLOBUS_FALSE;

                globus_mutex_lock(&data_mutex);
                {
                    data_done = GLOBUS_FALSE;
                }
                globus_mutex_unlock(&data_mutex);

                result = globus_ftp_control_send_command(
                             handle, 
                             "STOR %s\r\n",
                             control_response_callback,
                             (void *)get_put_info,
                             get_put_info->remote_name);
                if(result != GLOBUS_SUCCESS)
                {
                    return result; 
                }
                result = globus_ftp_control_data_connect_write(
                             handle, GLOBUS_NULL, GLOBUS_NULL);
                if(result != GLOBUS_SUCCESS)
                {
                    return result; 
                }
            }
        }   
        else if(strcmp(tmp_buf, "cd") == 0)
        {
            sscanf(&in_buf[2], "%s", tmp_buf);
            globus_ftp_control_send_command(
                handle, 
                "CWD %s\r\n",
                control_response_callback,
                GLOBUS_NULL, 
                tmp_buf);
        }   
        else if(strcmp(tmp_buf, "ls") == 0)
        {
            get_put_info = (get_put_info_t *)
                             globus_malloc(sizeof(get_put_info_t));
            get_put_info->direction = DIRECTION_LIST;
            get_put_info->buffer_size = BUFFER_SIZE;
            get_put_info->buffer = globus_malloc(BUFFER_SIZE);
            
            if(sscanf(&in_buf[2], "%s", get_put_info->remote_name) < 0)
            {
              printf("remote name %s\n",get_put_info->remote_name);  
	      strcpy(get_put_info->remote_name, " ");
            }
             printf("remote path %s\n",get_put_info->remote_name); 
            globus_mutex_lock(&data_mutex);
            {
                data_done = GLOBUS_FALSE;
            }
            globus_mutex_unlock(&data_mutex);

            result = globus_ftp_control_send_command(
                         handle, 
                         "LIST %s\r\n",
                         control_response_callback,
                         (void *)get_put_info,
                         get_put_info->remote_name);
            if(result != GLOBUS_SUCCESS)
            {
                printf("ls failed\n");
                done = GLOBUS_FALSE;
 
                continue;
            }

	    /* data_command_fail_tests check */
	    /* result = data_commands_before_calling_pasvorport_test(handle);*/
	   
            /* data clean up operation check*/
            /* result = data_commands_clean_test(handle);*/
           
	    result = globus_ftp_control_data_connect_read(
	                 handle, GLOBUS_NULL, GLOBUS_NULL);
            if(result != GLOBUS_SUCCESS)
            {
                printf("ls failed\n");
                done = GLOBUS_FALSE;
            }
        }
        else if(strcmp(tmp_buf, "pwd") == 0)
        {
            result = globus_ftp_control_send_command(
                         handle, 
                         "PWD\r\n",
                         control_response_callback,
                         GLOBUS_NULL);
            if(result != GLOBUS_SUCCESS)
            {
                printf("pwd failed\n"); 
            }
        }     
        else if(strcmp(tmp_buf, "bin") == 0)
        {
            globus_ftp_control_send_command(
                handle, 
                "TYPE I\r\n",
                control_response_callback,
                GLOBUS_NULL);
        }   
        else if(strcmp(tmp_buf, "ascii") == 0)
        {
            globus_ftp_control_send_command(
                handle, 
                "TYPE A\r\n",
                control_response_callback,
                GLOBUS_NULL);
        }   
        else if(strcmp(tmp_buf, "quit") == 0)
        {
            globus_ftp_control_quit(
                handle,
                control_response_callback,
                GLOBUS_NULL);
        }
        else if(strlen(tmp_buf) == 0)
        {
            done = GLOBUS_FALSE;
        }
        else 
        {
            printf("%s command not recognized\n", tmp_buf);
            done = GLOBUS_FALSE;
        }
    }

    return GLOBUS_SUCCESS;
}

/*
 * need to do things with put and get
 */
globus_result_t 
start_write(
    globus_ftp_control_handle_t *               handle,
    get_put_info_t *                            get_put_info)
{
    globus_io_attr_t                            attr;
    globus_size_t                               nread;
    globus_result_t                             result;
    globus_bool_t                               eof = GLOBUS_FALSE;
    globus_object_t *                           error;

    globus_io_fileattr_init(
         &attr);
    if(globus_io_file_open( 
           get_put_info->local_name,
           GLOBUS_IO_FILE_CREAT | GLOBUS_IO_FILE_RDONLY,
           GLOBUS_IO_FILE_IRUSR,
           &attr,
           &get_put_info->handle) != GLOBUS_SUCCESS)
      
      printf("local name of file is %s\n",get_put_info->local_name);
    
    {
        printf("Cannot open local file: %s\n", get_put_info->local_name);
        process_user_input(handle);

        return;
    }

    /* can i find out the size of the file? */
    get_put_info->buffer = globus_malloc(BUFFER_SIZE);
    get_put_info->buffer_size = BUFFER_SIZE;

    result = globus_io_read(
                 &get_put_info->handle,
                 get_put_info->buffer,
                 get_put_info->buffer_size,
                 get_put_info->buffer_size,
                 &nread);
    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
        eof = globus_io_eof(error);
        globus_error_put(error);
    }

    result = globus_ftp_control_data_write(
                 handle,
                 get_put_info->buffer,
                 nread,
                 0,
                 eof,
                 write_data_callback,
                 (void *) get_put_info);

    return result;
}

globus_bool_t
host_port_to_port(
    globus_ftp_control_host_port_t *            addr, 
    char                                        str[23])
{
    int                                         ctr;
    int                                         hi;
    int                                         low;
    struct hostent *                            hp;
    struct hostent                              he;
    char                                        buf[512];

    hp = globus_libc_gethostbyname_r(addr->host,
             &he, 
             buf,
             512,
             &ctr);

    for(ctr = 0; ctr < 4; ctr++)
    {
        memcpy(&str[ctr*4], &addr->host[ctr*4], 3);
        str[ctr*4+4] = ',';
    }
    hi = addr->port / 256;
    low = addr->port - hi;

    sprintf(&str[ctr*4+4], "%d,%d\0", hi, low);

    return GLOBUS_TRUE;
}

globus_bool_t
pasv_to_host_port(
    char *                                      astr,
    globus_ftp_control_host_port_t *            addr)
{
    char *                                      hostname;
    char *                                      port_str;
    char *                                      tmp_ptr;
    unsigned short                              port;
    int                                         hi;
    int                                         low;
    int                                         ctr;

   
    hostname = index(astr, '(') + 1;
 
    tmp_ptr = index(hostname, ',');
    for(ctr = 0; ctr < 3; ctr++)
    {
        if(tmp_ptr == GLOBUS_NULL)
        {
            return GLOBUS_FALSE;
        }
        tmp_ptr[0] = '.';
        tmp_ptr++;
        tmp_ptr = index(tmp_ptr, ',');
    }
    tmp_ptr[0] = '\0';

    port_str = tmp_ptr + 1;

    sscanf(port_str, "%d,%d", &hi, &low);
    port = hi * 256;
    port = port | low;

 printf("host address is %s and host name is %s port is %d\n",addr,hostname,port);

    globus_ftp_control_host_port_init(
        addr,
        hostname,
        port);

    return GLOBUS_TRUE;
}

void 
list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof)
{
    get_put_info_t *                            get_put_info;
    globus_size_t                               nwritten;
    globus_io_attr_t                            attr;

    get_put_info = (get_put_info_t *) callback_arg;
     
    if(error != GLOBUS_NULL)
    {
        printf("unable to list files\n");
        process_user_input(handle);

        return;
    }
  
    buffer[length] = '\0';
    printf("%s", buffer);
    /*
     * if done close file 
     * else read more
     *
     *  QUESTION:
     *  if it is finished will the server give me a reply?
     *  if not i need to call process_input()
     */
    if(!eof)
    {
        globus_ftp_control_data_read(
            handle,
            get_put_info->buffer,
            get_put_info->buffer_size,
            list_read_data_callback,
            (void *) get_put_info);
    }
    else
    {
        globus_mutex_lock(&data_mutex);
        {
            data_done = GLOBUS_TRUE;
            globus_cond_signal(&data_cond);
        }
        globus_mutex_unlock(&data_mutex);
    }
}

void 
read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof)
{
    get_put_info_t *                            get_put_info;
    globus_size_t                               nwritten;
    globus_io_attr_t                            attr;

    get_put_info = (get_put_info_t *) callback_arg;
    if(error != GLOBUS_NULL)
    {
        printf("error getting the requested file: %s\n", 
               get_put_info->local_name);
        process_user_input(handle);

        return;
    }
     printf(" the requested file: %s\n", 
               get_put_info->local_name);
    /*  if the file has not been opened yet */
    if(!get_put_info->opened)
    {
        globus_io_fileattr_init(
             &attr);
        if(globus_io_file_open( 
               get_put_info->local_name,
               GLOBUS_IO_FILE_CREAT | GLOBUS_IO_FILE_WRONLY,
               GLOBUS_IO_FILE_IRUSR,
               &attr,
               &get_put_info->handle) != GLOBUS_SUCCESS)
        {
            printf("Cannot create local file: %s\n", get_put_info->local_name);
            globus_ftp_control_abort(           
                handle,
                control_response_callback,
                GLOBUS_NULL);

            return;
        }
        get_put_info->opened = GLOBUS_TRUE;
    }

printf("offset = %d\n", offset);
    globus_io_file_seek(
        &get_put_info->handle,
        offset,
        0);
    globus_io_write(
        &get_put_info->handle,
        buffer,
        length,
        &nwritten);

    /*
     * if done close file 
     * else read more
     *
     *  QUESTION:
     *  if it is finished will the server give me a reply?
     *  if not i need to call process_input()
     */
    if(eof)
    {
        printf("the file has been received %d\n", length + offset);
        globus_io_close(&get_put_info->handle);
        globus_mutex_lock(&data_mutex);
        {
            data_done = GLOBUS_TRUE;
            globus_cond_signal(&data_cond);
        }
        globus_mutex_unlock(&data_mutex);
    }
    else
    {
        globus_free(get_put_info->buffer);
        get_put_info->buffer_size *= 2;
        get_put_info->buffer = globus_malloc(get_put_info->buffer_size);

        globus_ftp_control_data_read(
            handle,
            get_put_info->buffer,
            get_put_info->buffer_size,
            read_data_callback,
            (void *) get_put_info);
    }
}

void 
write_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof)
{
    get_put_info_t *                            get_put_info;
    globus_size_t                               nwritten;
    globus_size_t                               nread;
    globus_result_t                             result;
    globus_bool_t                               eof2;

    get_put_info = (get_put_info_t *) callback_arg;
    if(error != GLOBUS_NULL)
    {
        printf("error getting the requested file: %s\n", 
               get_put_info->remote_name);
        globus_ftp_control_abort(           
            handle,
            control_response_callback,
            GLOBUS_NULL);

        return;
    }

    if(!eof)
    {
        eof2 = GLOBUS_FALSE;
        result = globus_io_read(
                     &get_put_info->handle,
                     get_put_info->buffer,
                     BUFFER_SIZE,
                     BUFFER_SIZE,
                     &nread);
        if(result != GLOBUS_SUCCESS)
        {
            error = globus_error_get(result);
            eof2 = globus_io_eof(error);
            globus_error_put(error);
        }
        globus_ftp_control_data_write(
            handle,
            get_put_info->buffer,
            nread,
            offset,
            eof2,
            write_data_callback,
            (void *) get_put_info);
    }
    else
    {
        globus_io_close(&get_put_info->handle);
        printf("the file has been transfered\n");
        globus_mutex_lock(&data_mutex);
        {
            data_done = GLOBUS_TRUE;
            globus_cond_signal(&data_cond);
        }
        globus_mutex_unlock(&data_mutex);
    }
}
