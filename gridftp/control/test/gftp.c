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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>

globus_result_t
l_get_command(
    char *                                localname,
    char *                                remotename,
    char *                                server_cmd,
    char *                                alg_info);

void
force_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error);

globus_result_t
generic_command(
    char *                                 command,
    int *                                  code);

int
parse_list_args(
    char *                                    list,
    char *                                    arg[],
    int                                       argc);

char *
trim_spaces(
    char *                                      str);

void
mget_list_command(
    globus_fifo_t *                       name_q,
    char *                                wildcard);

globus_result_t
process_command(
    char *                             command);

globus_result_t
build_url_parse(
    char *                                in_url,
    char *                                out_url);

globus_result_t
passive_command(
    char *                                command_str);

globus_result_t
pwd_command(
    char *                                command_str);

globus_result_t
binary_command(
    char *                                command_str);

globus_result_t
ascii_command(
    char *                                command_str);

globus_result_t
eb_command(
    char *                                command_str);

globus_result_t
stream_command(
    char *                                command_str);

globus_result_t
connect_command(
    char *                                command_str);

globus_result_t
user_command(
    char *                                command_str);

globus_result_t
close_command(
    char *                                command_str);

globus_result_t
quit_command(
    char *                                command_str);

globus_result_t
help_command(
    char *                                command_str);

globus_result_t
get_command(
    char *                                command_str);

globus_result_t
eget_command(
    char *                                command_str);

globus_result_t
put_command(
    char *                                command_str);

globus_result_t
list_command(
    char *                                command_str);

globus_result_t
mlsd_command(
    char *                                command_str);

globus_result_t
mlst_command(
    char *                                command_str);

globus_result_t
cd_command(
    char *                                command_str);

globus_result_t
mkdir_command(
    char *                                command_str);

globus_result_t
rmdir_command(
    char *                                command_str);

globus_result_t
delete_command(
    char *                                command_str);

globus_result_t
opts_command(
    char *                                command_str);

globus_result_t
site_command(
    char *                                command_str);

globus_result_t
rhelp_command(
    char *                                command_str);

globus_result_t
lcd_command(
    char *                                command_str);

globus_result_t
subject_command(
    char *                                command_str);

globus_result_t
quote_command(
    char *                                command_str);

globus_result_t
bang_command(
    char *                                command_str);

globus_result_t
size_command(
    char *                                command_str);

globus_result_t
syst_command(
    char *                                command_str);

globus_result_t
parallel_command(
    char *                                command_str);

globus_result_t
buffer_command(
    char *                                command_str);

globus_result_t
tick_command(
    char *                                command_str);

globus_result_t
prompt_command(
    char *                                command_str);

globus_result_t
mput_command(
    char *                                command_str);

globus_result_t
mget_command(
    char *                                command_str);

globus_result_t
spas_command(
    char *                                command_str);

typedef globus_result_t (*command_func_t)(char * str);

typedef struct gftp_monitor_s
{
    globus_mutex_t                     mutex;
    globus_cond_t                      cond;
    globus_bool_t                      done;
    int                                count;

    globus_result_t                    res;
} gftp_monitor_t;

void
gftp_monitor_init(
    gftp_monitor_t *                   monitor);

void
gftp_monitor_reset(
    gftp_monitor_t *                   monitor);

void
gftp_monitor_destroy(
    gftp_monitor_t *                   monitor);

void
generic_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

typedef struct command_entry_s 
{    
    char *                             command;
    char *                             description;
    command_func_t                     func;
} command_entry_t;

/*
 *  TODO: parallel, layout, buffer
 */
command_entry_t                        g_command_table[] = 
{
    {"?", "see redundant", help_command},
    {"!", "escape to the shell", bang_command},
    {"ascii", "request ascii file transfer", ascii_command},
    {"bin", "request binary file transfer", binary_command},
    {"buffer", "set the buffer size", buffer_command},
    {"bye", "terminate ftp session and exit", quit_command},
    {"cd", "change directories", cd_command},
    {"cdup", "server specific command.", site_command},
    {"close", "close the current connection", quit_command},
    {"delete", "delete a file.", delete_command},
    {"dir", "list files", list_command},
    {"disconnect", "terminate the ftp session", quit_command},
    {"eb", "request extended block mode", eb_command},
    {"eget", "extended retrieve.  eget <alg_parms> <remote filename> <local filename>", eget_command},
    {"exit", "terminate ftp session and exit", quit_command},
    {"get", "get a file from the server", get_command},
    {"help", "see redundant", help_command},
    {"image", "request binary file transfer", binary_command},
    {"lcd", "change local working directory.", lcd_command},
    {"ls", "list files", list_command},
    {"mget", "get multiple files", mget_command},
    {"mkdir", "make directory", mkdir_command},
    {"mlsd", "list files", mlsd_command},
    {"mlst", "list file", mlst_command},
    {"mput", "send multiple files", mput_command},
    {"nlist", "nlist files", list_command},
    {"open", "open a new url", connect_command},
    {"opts", "send options", opts_command},
    {"parallel", "set parallelism level for eb mode", parallel_command},
    {"passive", "", passive_command},
    {"prompt", "", prompt_command},
    {"put", "move a file to the server", put_command},
    {"pwd", "print working directory", pwd_command},
    {"quit", "terminate ftp session and exit", quit_command},
    {"quote", "send arbitrary ftp command", quote_command},
    {"recv", "get a file from the server", get_command},
    {"rhelp", "Get help from the server.", rhelp_command},
    {"rmdir", "remove directory.", rmdir_command},
    {"send", "move a file to the server", put_command},
    {"site", "server specific command.", site_command},
    {"size", "show size of remote file", size_command},
    {"spas", "set client for striped writes", spas_command},
    {"stream", "request stream mode", stream_command},
    {"subject", "set the subject name for gsi authentication", subject_command},
    {"system", "show remote system type", syst_command},
    {"tick", "toggle printing byte counter during transfers", tick_command},
    {"user", "", user_command},
};

#define COMMAND_TABLE_SIZE             47

long                                   g_bytes_tranfsered = 0; 
int                                    g_size = -1;
globus_bool_t                          g_passive = GLOBUS_FALSE;
globus_bool_t                          g_prompt = GLOBUS_TRUE;
globus_bool_t                          g_tick = GLOBUS_FALSE;
globus_ftp_control_handle_t            g_control_handle;
globus_bool_t                          g_connected;
gftp_monitor_t                         g_monitor;
globus_url_t                           g_url;
char *                                 g_url_ptr;
globus_bool_t                          g_control_c = GLOBUS_FALSE;
int                                    g_buffer_size = 131072;
int                                    g_parallel = 1;
globus_ftp_control_mode_t              g_mode = GLOBUS_FTP_CONTROL_MODE_STREAM;
globus_bool_t                          g_transfer_in_progress = GLOBUS_FALSE;
int                                    g_file_size = -1;
globus_callback_handle_t               g_callback_handle;
char *                                 g_command_file = GLOBUS_NULL;
FILE *                                 g_infile = GLOBUS_NULL;
char *                                 g_subject = GLOBUS_NULL;
globus_abstime_t                       g_start_time;

globus_ftp_control_dcau_t              g_dcau;
globus_bool_t                          g_spas = GLOBUS_FALSE;

void
abort_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    gftp_monitor_t *                            monitor;

    printf("abort_callback() : %d\n.", ftp_response->code);
}

void
control_c_signal(
    int                                   sig)
{
    globus_result_t                       res;

    if(g_transfer_in_progress)
    {
        g_monitor.count++;
        res = globus_ftp_control_abort(
                  &g_control_handle,
                  generic_response_callback,
                  (void *)GLOBUS_NULL);
        if(res != GLOBUS_SUCCESS)
        {
            printf("abort failed: %s\n",
                globus_object_printable_to_string(globus_error_get(res)));
        }
        g_control_c = GLOBUS_FALSE;
    }

    printf("^C\n");
    g_control_c = GLOBUS_TRUE;
}

void
print_help()
{
    printf("\n");
    printf("Usage: gftp [<-h> <-help> <-f session file>] [hostname]\n");
    printf("   -h/-help:  print this help screen\n");
    printf("   -f:  use the given session file.\n");
    printf("\n");
}

char *
get_input(
    char * prompt, globus_bool_t echo)
{
    struct termios                  term;
    tcflag_t                        bk;
    char *                          tmp_ptr = globus_malloc(1024);

    if(g_infile != GLOBUS_NULL)
    {
        tmp_ptr = fgets(tmp_ptr, 1024, g_infile);
        return tmp_ptr;
    }
    else if(echo)
    {
        printf(prompt);
        return gets(tmp_ptr);
    }
    else
    {
        printf(prompt);
        tcgetattr(STDIN_FILENO, &term);
        bk = term.c_lflag;
        term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        tmp_ptr = gets(tmp_ptr);

        term.c_lflag = bk;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);

        return tmp_ptr;
    }
}

int
main(
    int                                argc,
    char **                            argv)
{
    int                                ctr;
    globus_bool_t                      done = GLOBUS_FALSE;
    char *                             input;
    char *                             trim_input;
    globus_bool_t                      use_file = GLOBUS_FALSE;
    char *                             url_string;
    globus_result_t                    res;
    void *                             sig_res;

    globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);

/*    signal(SIGINT, control_c_signal); 
*/
    gftp_monitor_init(&g_monitor);
    globus_ftp_control_handle_init(&g_control_handle);

    /*
     * parse command line
     */
    for(ctr = 1; ctr < argc; ctr++)
    {
        if(strcmp("-f", argv[ctr]) == 0)
        {
            if(ctr + 1 > argc)
            {
                print_help();
            }
            else
            {
                g_infile = fopen(argv[ctr+1], "r");
                if(g_infile == GLOBUS_NULL)
                {
                    printf("The file: %s could not be open for reading.\n",
                           argv[ctr+1]);
                    return 1;
                }
                ctr++;
            }
        }
        else if(strcmp("-help", argv[ctr]) == 0 || 
                strcmp("-h", argv[ctr]) == 0)
        {
            print_help();
            return 1;
        }
        /*
         * parse the url
         */
        else
        { 
            url_string = globus_malloc(5 + 
                                       strlen(argv[ctr]) + 
                                       2);

            sprintf(url_string, "open %s", argv[ctr]);

            res = connect_command(url_string);
            if(res != GLOBUS_SUCCESS)
            {
                printf("Error: %s.\n", 
                    globus_object_printable_to_string(
                        globus_error_get(res)));
            }
        }
    }

    input = get_input("ftp> ", GLOBUS_TRUE);
    while(input != GLOBUS_NULL && !done)
    {
        trim_input = trim_spaces(input);
        process_command(trim_input);
        if(strcmp(trim_input, "quit") == 0 ||
           strcmp(trim_input, "bye") == 0)
        {
            done = GLOBUS_TRUE;
            globus_free(input);
        }
        else
        {
            globus_free(input);
            input = get_input("ftp> ", GLOBUS_TRUE);
        }
    }

    if(g_infile != GLOBUS_NULL)
    {
        fclose(g_infile);
    }

    globus_ftp_control_handle_destroy(&g_control_handle);
    gftp_monitor_destroy(&g_monitor);

    signal(SIGINT, SIG_DFL); 

    globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);

    return 0;
}

globus_result_t
build_url_parse(
    char *                                in_url,
    char *                                out_url)
{
    char                                  protocol[16];
    char *                                tmp_ptr;
    globus_bool_t                         port_used = GLOBUS_FALSE;
    char *                                host;
    char                                  port[5];

    strcpy(port, "21");

    tmp_ptr = strstr(in_url, "://");
    if(tmp_ptr != GLOBUS_NULL)
    {
        strncpy(protocol, in_url, tmp_ptr - in_url);
        protocol[tmp_ptr - in_url] = '\0';
        in_url = tmp_ptr + 3;
    }
    else
    {
        strcpy(protocol, "ftp");
    }

    tmp_ptr = strstr(in_url, ":");
    if(tmp_ptr != GLOBUS_NULL)
    {
        port_used = GLOBUS_TRUE;

        *tmp_ptr = '\0'; 
        strcpy(port, (tmp_ptr + 1));
    }
    host = in_url;

    if(!port_used && strcmp(protocol, "gsiftp") == 0)
    {
        strcpy(port, "2811");
    } 

    sprintf(out_url, "%s://%s:%s\0", protocol, host, port);

    return GLOBUS_SUCCESS;
}

/*
 *  this funtion blocks until the operation is complete
 */
globus_result_t
process_command(
    char *                             command)
{
    char *                             tmp_buf;
    int                                command_len;
    globus_result_t                    res = GLOBUS_SUCCESS;
    char *                             arg1;
    int                                ctr;
    globus_bool_t                      found = GLOBUS_FALSE;

    command_len = strlen(command);
    if(command_len < 1)
    {
        return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }

    tmp_buf = (char *) globus_malloc(command_len + 1);

    sscanf(command, "%s", tmp_buf);

    for(ctr = 0; ctr < COMMAND_TABLE_SIZE && !found; ctr++) 
    {
        if(strcmp(tmp_buf, g_command_table[ctr].command) == 0)
        {
            res = g_command_table[ctr].func(command);
            if(res != GLOBUS_SUCCESS)
            {
                printf("Error: %s.\n", 
                    globus_object_printable_to_string(
                        globus_error_get(res)));
            }
            found = GLOBUS_TRUE;
        }
        /* special case for bang */
        else if(tmp_buf[0] == '!')
        {
            res = bang_command(command);
            found = GLOBUS_TRUE;
        }
    }

    if(!found)
    {
        printf("Invalid command.\n");
    }

    globus_free(tmp_buf);

    return res;
}

int
parse_list_args(
    char *                                    list,
    char *                                    arg[],
    int                                       argc)
{
    int                                       count = 0;
    char *                                    tmp_ptr;
    char *                                    tmp_ptr2;
    int                                       ctr;

    tmp_ptr = trim_spaces(list);
    for(ctr = 0; ctr < argc; ctr++)
    {
        tmp_ptr2 = strstr(tmp_ptr, " ");
        tmp_ptr2 = trim_spaces(tmp_ptr2);
        if(tmp_ptr2 == GLOBUS_NULL)
        {
            if(strlen(tmp_ptr) > 0)
            {
                count++;
                strcpy(arg[ctr], trim_spaces(tmp_ptr));
            }
            return count;
        }
        else
        {
            count++;
            strncpy(arg[ctr],  tmp_ptr,  tmp_ptr2 -  tmp_ptr);
            arg[ctr][tmp_ptr2-tmp_ptr] = '\0';
        }
        /* trim off the end spaces */
        trim_spaces(arg[ctr]);
        tmp_ptr = tmp_ptr2;
    }

    return count;
}

/**********************************************************************
 * command functions
 *********************************************************************/
void
print_tick(
    float                                    rate)
{
    const int                                progress_size = 55;
    static int                               spinner_ctr = 0;
    char *                                   out_buf;
    int                                      ctr;
    int                                      stars;
    char *                                   spinner = 
                                               "|/-\\|/-\\";

    out_buf = globus_malloc(progress_size);
    if(g_tick)
    {
        if(g_size != -1)
        {
            memset(out_buf, ' ', progress_size);
            out_buf[0] = '[';
            out_buf[progress_size - 2] = ']';
            out_buf[progress_size - 1] = '\0';

            stars = (int)((float)g_bytes_tranfsered / 
                             (float)g_size * (progress_size - 2));
            for(ctr = 0; ctr < stars; ctr++)
            {
                out_buf[ctr + 1] = '*';
            }
            printf("\r%s %4.1f%% %c %6.2f KBps", out_buf, 
                (float)g_bytes_tranfsered / (float)g_size * 100.0, 
                (char)spinner[spinner_ctr],
                rate);
            spinner_ctr++;
            if(spinner_ctr >= strlen(spinner))
            {
                spinner_ctr = 0;
            }
        }
        else
        {
            printf("\rBytes transferred: %d.",
                g_bytes_tranfsered);
        }
        fflush(stdout);
    }
    globus_free(out_buf);
}

globus_result_t
mput_command(
    char *                                command_str)
{
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];
    char *                                cmd;
    char *                                response;
    FILE *                                instr;
    char                                  ls_cmd[512];
    globus_list_t *                       file_list = GLOBUS_NULL;
    char                                  buffer[512];
    globus_bool_t                         put_file = GLOBUS_TRUE;
    globus_result_t                       res;

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc == 1)
    {
        sprintf(ls_cmd, "/bin/ls -c1");
    }
    else
    {
        sprintf(ls_cmd, "/bin/ls -c1 %s", arg[1]);
    }

    instr = popen(ls_cmd, "r");

    if(instr == GLOBUS_NULL)
    {
        printf("mput failed.  Failed to run %s.\n", ls_cmd);
        return GLOBUS_SUCCESS;
    }

    while(fscanf(instr, "%s", ls_cmd) != EOF) 
    {
        if(g_prompt)
        {
            sprintf(buffer, "put %s?", ls_cmd);
            response = get_input(buffer, GLOBUS_TRUE);
            if(strcmp(response, "y") == 0 ||
               strcmp(response, "yes") == 0)
            {
                put_file = GLOBUS_TRUE;
            }
            else
            {
                put_file = GLOBUS_FALSE;
            }
        }

        if(put_file)
        {
            sprintf(buffer, "put %s", ls_cmd);
            res = put_command(buffer);
        }
    }
    pclose(instr);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return GLOBUS_SUCCESS;
}

/*
 *  This command requires a NLST to build the remote file list
 */
globus_result_t
mget_command(
    char *                                command_str)
{
    char *                                name;
    globus_bool_t                         get_file = GLOBUS_TRUE;
    char                                  buffer[512];
    char *                                response;
    globus_result_t                       res;
    globus_fifo_t                         name_q;
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 2);

    globus_fifo_init(&name_q);
    mget_list_command(&name_q, arg[1]);

    while(!globus_fifo_empty(&name_q))
    {
        name = (char *)globus_fifo_dequeue(&name_q);

        if(g_prompt)
        {
            sprintf(buffer, "get %s?", name);
            response = get_input(buffer, GLOBUS_TRUE);

            if(strcmp(response, "y") == 0 ||
               strcmp(response, "yes") == 0)
            {
                get_file = GLOBUS_TRUE;
            }
            else
            {
                get_file = GLOBUS_FALSE;
            }
        }
        else
        {
            get_file = GLOBUS_TRUE;
        }

        if(get_file)
        {
            sprintf(buffer, "get %s", name);
            res = get_command(buffer);
        }

        free(name);
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
prompt_command(
    char *                                command_str)
{
    g_prompt = !g_prompt;

    printf("Interactive mode %s.\n", g_prompt ? "on" : "off");

    return GLOBUS_SUCCESS;
}

globus_result_t
spas_command(
    char *                                command_str)
{
    g_spas = !g_spas;

    printf("Spas mode %s.\n", g_spas ? "on" : "off");

    return GLOBUS_SUCCESS;
}


globus_result_t
tick_command(
    char *                                command_str)
{
    g_tick = !g_tick;

    printf("tick printing is %s.\n", g_tick ? "on" : "off");

    return GLOBUS_SUCCESS;
}

globus_result_t
buffer_command(
    char *                                command_str)
{
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];
    char                                  cmd[512];
    globus_result_t                       res = GLOBUS_SUCCESS;
    globus_ftp_control_tcpbuffer_t        buf_size;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("specify a buffer size.\n");
    }
    else
    {
        g_buffer_size = atoi(arg[1]);
        if(g_buffer_size <= 0)  
        {
            g_buffer_size = 65536;
        }
        buf_size.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        buf_size.fixed.size = g_buffer_size;

        res =  globus_ftp_control_local_tcp_buffer(
                   &g_control_handle, 
                   &buf_size);
        if(res != GLOBUS_SUCCESS)
        {
            goto exit;
        }

        sprintf(cmd, "SITE BUFSIZE %d", g_buffer_size);
        res = site_command(cmd);
        if(res != GLOBUS_SUCCESS)
        {
            goto exit;
        }
        printf("buffer size set to %d.\n",  g_buffer_size);
    }

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
subject_command(
    char *                                command_str)
{
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        g_subject = GLOBUS_NULL;
        printf("subject has been set to NULL\n");
    }
    else
    {
        g_subject = strdup(&command_str[strlen("subject ")]);
        printf("subject has been set to \"%s\".\n", g_subject);
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
syst_command(
    char *                                command_str)
{
    return generic_command("SYST", GLOBUS_NULL);
}

void
size_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    int *                                       size;

    size = (int *)callback_arg;
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.res = globus_error_put(globus_object_copy(error));
            if(size != GLOBUS_NULL)
            {
                *size = -1;
            }
        }
        else
        {
            if(size != GLOBUS_NULL)
            {
                *size = atoi((const char *)&ftp_response->response_buffer[4]);
            }
        }
        g_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

globus_result_t 
get_remote_file_size(
    char *                                filename,
    int *                                 size)
{
    globus_result_t                        res;

    if(!g_connected)
    {
        printf("Not connected.\n");

        return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }

    gftp_monitor_reset(&g_monitor);

    res = globus_ftp_control_send_command(
              &g_control_handle, 
              "SIZE %s\r\n",
              size_callback,
              (void*)size,
              filename);

    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

    return res;
}

globus_result_t
size_command(
    char *                                command_str)
{
    int                                   size = -1;
    globus_result_t                       res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    res = get_remote_file_size(arg[0], &size);

    if(size == -1)
    {
        printf("550 %s: No such file or directory.\n", 
            &command_str[strlen("size ")]);
    }
    else
    {
        printf("file is %d bytes.\n", size);
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
bang_command(
    char *                                command_str)
{
    struct passwd *                       pwent;
    char *                                tmp_buf;
    char *                                cmd;
    char *                                shell;

    pwent = getpwuid(getuid());

    if(pwent == GLOBUS_NULL)
    {
        shell = strdup("/bin/sh");
    }
    else
    {
        shell = pwent->pw_shell;
    }

    tmp_buf = globus_malloc(strlen(pwent->pw_shell) + strlen(command_str) + 1);

    if(strlen(command_str) <= 1)
    {
        sprintf(tmp_buf, "%s", shell);
    }
    else
    { 
        sprintf(tmp_buf, "%s", &command_str[1]);
    }
    system(tmp_buf);
    
    globus_free(tmp_buf);

    return GLOBUS_SUCCESS;
}

globus_result_t
rhelp_command(
    char *                                command_str)
{
    globus_result_t                       res;
    char *                                cmd;

    cmd = globus_malloc(strlen(command_str));
    strcpy(cmd, &command_str[1]);

    res = generic_command(cmd, GLOBUS_NULL);
  
    globus_free(cmd);

    return res;
}

globus_result_t
lcd_command(
    char *                                command_str)
{
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;
    char                                  buf[512];

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("You must specify a directory.\n");
    }
    else
    {
        if(chdir(arg[1]) == 0)
        {
            printf("Local directory now %s\n", getcwd(buf, 512)); 
        }
        else
        {
            printf("local: %s: No such file or directory\n", arg[1]);
        }
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }
    return GLOBUS_SUCCESS;
}


globus_result_t
quote_command(
    char *                                command_str)
{
    return generic_command(
           &command_str[strlen("quote ")], GLOBUS_NULL);
}

globus_result_t
site_command(
    char *                                command_str)
{
    return generic_command(command_str, GLOBUS_NULL);
}

globus_result_t
opts_command(
    char *                                command_str)
{
    globus_result_t                        res;
    char *                                arg[3];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("Please specify the feature and options\n");
        return GLOBUS_SUCCESS;
    }

    sprintf(arg[0], "OPTS %s %s", arg[1], arg[2]);
    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
delete_command(
    char *                                command_str)
{
    globus_result_t                        res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("Please specify the file you wish to delete.\n");
        return GLOBUS_SUCCESS;
    }

    sprintf(arg[0], "DELE %s", arg[1]);
    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
mkdir_command(
    char *                                command_str)
{
    globus_result_t                        res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("Please specify the directory name.\n");
        return GLOBUS_SUCCESS;
    }

    sprintf(arg[0], "MKD %s", arg[1]);
    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
rmdir_command(
    char *                                command_str)
{
    globus_result_t                        res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("Please specify the directory name.\n");
        return GLOBUS_SUCCESS;
    }

    sprintf(arg[0], "RMD %s", arg[1]);
    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
cd_command(
    char *                                command_str)
{
    globus_result_t                       res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("Please specify a remote directory.\n");
        return GLOBUS_SUCCESS;
    }

    sprintf(arg[0], "CWD %s", arg[1]);

    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
mlst_command(
    char *                                command_str)
{
    globus_result_t                       res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        sprintf(arg[0], "mlst");
    }
    else
    {
        sprintf(arg[0], "mlst %s", arg[1]);
    }
    

    res = generic_command(arg[0], GLOBUS_NULL);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

void
auth_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    if(error != GLOBUS_NULL)
    {
        printf("Error: %s\n", globus_object_printable_to_string(error));
    }
    else
    {
        printf("%s\n", ftp_response->response_buffer);
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        g_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

globus_result_t
user_command(
    char *                                      command_str)
{
    globus_ftp_control_auth_info_t              auth;
    char *                                      subject = GLOBUS_NULL;
    char *                                      username = GLOBUS_NULL;
    char *                                      passwd = GLOBUS_NULL;
    char *                                      account = GLOBUS_NULL;
    globus_bool_t                               gsi = GLOBUS_FALSE;
    char                                        prompt[512];
    char *                                      args[2];
    globus_result_t                             res;
    struct passwd *                             pass_info;

    if(!g_connected)
    {
        printf("Not connected.\n");

        return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }

    args[0] = globus_malloc(strlen(command_str)+1);
    args[1] = globus_malloc(strlen(command_str)+1);

    if(g_url.scheme_type == GLOBUS_URL_SCHEME_GSIFTP)
    {
        subject = g_subject;
        gsi = GLOBUS_TRUE;
    }
    else
    {
        if(parse_list_args(command_str, args, 2) <= 1)
        {
            pass_info = getpwuid(getuid());
            sprintf(prompt, "Name (%s:%s):", g_url.host, pass_info->pw_name);
            username = get_input(prompt, GLOBUS_TRUE);
            if(username == GLOBUS_NULL || username[0] == '\0' || 
               username[0] == '\n')
            {  
                username = strdup(pass_info->pw_name);
            }
        }
        else
        {
            username = args[1];
        }
        passwd = get_input("Password:", GLOBUS_FALSE);
        printf("\n");
    }

    res = globus_ftp_control_auth_info_init(
              &auth,
	      GLOBUS_NULL,
	      GLOBUS_FALSE,
              username,
              passwd,
              account,
              subject);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    gftp_monitor_reset(&g_monitor);
    res = globus_ftp_control_authenticate(
              &g_control_handle,
              &auth,
              gsi,
              auth_callback,
              GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        } 
    }
    globus_mutex_unlock(&g_monitor.mutex);

    if(gsi)
    {
        g_dcau.mode = GLOBUS_FTP_CONTROL_DCAU_SELF;
        res = globus_ftp_control_local_dcau(
                  &g_control_handle,
                  &g_dcau,
                  auth.delegated_credential_handle);

    }

    globus_free(args[0]);
    globus_free(args[1]);

    return GLOBUS_SUCCESS;

  err:

    globus_free(args[0]);
    globus_free(args[1]);

    return res;
}

void
connect_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_result_t                             res;

    if(error != GLOBUS_NULL)
    {
        printf("Error: %s\n", globus_object_printable_to_string(error));
    }
    else
    {
        printf("%s\n", ftp_response->response_buffer);
        g_connected = GLOBUS_TRUE;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        g_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);

}

globus_result_t
connect_command(
    char *                                command_str)
{
    globus_result_t                       res;
    char *                                arg[2];
    int                                   argc;
    int                                   ctr;

    if(g_connected)
    {
        printf("Already connected to %s, use close first.\n", g_url.host);
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 4);
    }
    argc = parse_list_args(command_str, arg, 2);
    if(argc < 2)
    {
        printf("please specify a host url to open.\n");
        res = GLOBUS_SUCCESS;

        goto exit;
    }

    g_url_ptr = globus_malloc(strlen(command_str) + 23);

    build_url_parse(arg[1], g_url_ptr);
    globus_url_parse(g_url_ptr, &g_url);

    gftp_monitor_reset(&g_monitor);
    res = globus_ftp_control_connect(
              &g_control_handle,
              g_url.host,
              g_url.port,
              connect_callback,
              GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        } 
    }
    globus_mutex_unlock(&g_monitor.mutex);

    res = user_command("user");

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }
    return res;
}

globus_result_t
quit_command(
    char *                                command_str)
{
    globus_result_t                       res;

    if(!g_connected)
    {
        return GLOBUS_SUCCESS;
    }

    if(g_subject != GLOBUS_NULL)
    {
        globus_free(g_subject);
    }
    g_subject = GLOBUS_NULL;

    gftp_monitor_reset(&g_monitor);
    res = globus_ftp_control_quit(
              &g_control_handle,
              generic_response_callback,
              GLOBUS_NULL);

    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);

    g_connected = GLOBUS_FALSE;

    return GLOBUS_SUCCESS;
}

globus_result_t
passive_command(
    char *                                command_str)
{
    g_passive = !g_passive;
    printf("passive mode %s.\n", g_passive ? "on" : "off");

    return GLOBUS_SUCCESS;
}

globus_result_t
pwd_command(
    char *                                command_str)
{
    globus_result_t                       res;

    res = generic_command("PWD", GLOBUS_NULL);

    return res;
}

globus_result_t
help_command(
    char *                                command_str)
{
    int                                   ctr;
    int                                   ctr2;
    int                                   argc;
    char *                                arg[2];
    char                                  slot[10];

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }

    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        ctr = 0;
        while(ctr < COMMAND_TABLE_SIZE)
        {
            for(ctr2 = 0; ctr2 < 5 && ctr < COMMAND_TABLE_SIZE; ctr2++)
            {
                sprintf(slot, "          ");
                strncpy(slot, g_command_table[ctr].command, 
                         strlen(g_command_table[ctr].command));
                printf("%s\t", slot);
                ctr++;
            }
            printf("\n");
        }
    }
    else
    {
        for(ctr = 0; ctr < COMMAND_TABLE_SIZE; ctr++)
        {
            if(strcmp(arg[1], g_command_table[ctr].command) == 0)
            {
                printf("%s:\n\t    %s\n", 
                    arg[1], g_command_table[ctr].description);
            }
        }
    }


    return GLOBUS_SUCCESS;
}

globus_result_t
binary_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   code;

    res = generic_command("TYPE I", &code);
    if(res == GLOBUS_SUCCESS && code == 200)
    {
        res = globus_ftp_control_local_type(
                  &g_control_handle,
                  GLOBUS_FTP_CONTROL_TYPE_IMAGE,
                  0);
   }

    return res;
}

globus_result_t
ascii_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   code;

    res = generic_command("TYPE A", &code);
    if(res == GLOBUS_SUCCESS && code == 200)
    {
        res = globus_ftp_control_local_type(
                  &g_control_handle,
                  GLOBUS_FTP_CONTROL_TYPE_ASCII,
                  0);
    }

    return res;
}

globus_result_t
eb_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   code;

    res = generic_command("MODE E", &code);
    if(res == GLOBUS_SUCCESS && code == 200)
    {
        g_mode = GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK;
        res = globus_ftp_control_local_mode(
                  &g_control_handle,
                  GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
    }

    return res;
}

globus_result_t
stream_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   code;

    res = generic_command("MODE S", &code);
    if(res == GLOBUS_SUCCESS && code == 200)
    {
        g_mode = GLOBUS_FTP_CONTROL_MODE_STREAM;
        res = globus_ftp_control_local_mode(
                  &g_control_handle,
                 GLOBUS_FTP_CONTROL_MODE_STREAM);
    }

    return res;
}

/**********************************************************************
 *  callback for generic command
 *********************************************************************/
globus_result_t
parallel_command(
    char *                                command_str)
{
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];
    globus_ftp_control_parallelism_t      parallel;
    globus_result_t                       res = GLOBUS_SUCCESS;

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(argc < 2)
    {
        printf("specify a number of data connections.\n");
    }
    else
    {
        g_parallel = atoi(arg[1]);
        if(g_parallel <= 0)  
        {
            g_parallel = 1;
        }
    
        parallel.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
        parallel.fixed.size = g_parallel;
        res = globus_ftp_control_local_parallelism(
                  &g_control_handle,
                  &parallel);
        if(res != GLOBUS_SUCCESS)
        {
            goto exit;
        }
  
        printf("parallelism set to %d.\n",  g_parallel);
    }

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

void
generic_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    int *                                       code;

    code = (int *)callback_arg;
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.res = globus_error_put(globus_object_copy(error));
        }
        g_monitor.done = GLOBUS_TRUE;
        g_monitor.count--;
        globus_cond_signal(&g_monitor.cond);
        if(code != GLOBUS_NULL)
        {
            *code = ftp_response->code;
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);

    if(error == GLOBUS_NULL)
    {
        printf("%s", ftp_response->response_buffer);
    }
}

/*
 *  This function can be used for most commands that do not use the data 
 *  channel.
 */
globus_result_t
generic_command(
    char *                                 command,
    int *                                  code)
{
    globus_result_t                        res;

    if(!g_connected)
    {
        printf("Not connected.\n");

        return GLOBUS_SUCCESS;
    }

    gftp_monitor_reset(&g_monitor);

    res = globus_ftp_control_send_command(
              &g_control_handle, 
              "%s\r\n",
              generic_response_callback,
              (void*)code,
              command);

    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

    return res;
}

void
gftp_monitor_init(
    gftp_monitor_t *                   monitor)
{
    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->mutex, GLOBUS_NULL);

    gftp_monitor_reset(monitor);
}

void
gftp_monitor_reset(
    gftp_monitor_t *                   monitor)
{
    monitor->done = GLOBUS_FALSE;
    monitor->res = GLOBUS_SUCCESS;
    monitor->count = 0;
}

void
gftp_monitor_destroy(
    gftp_monitor_t *                   monitor)
{
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
}

/**********************************************************
 *     get and put functions 
 *********************************************************/
void
force_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error)
{
    globus_mutex_lock(&g_monitor.mutex);
    {
        g_monitor.count--;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);

}

void
spas_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    int                                   hi;
    int                                   low;
    char *                                tmp_ptr;
    globus_list_t *                       list = GLOBUS_NULL;
    globus_ftp_control_host_port_t *      addr;
    globus_ftp_control_host_port_t *      spas_addr; 
    int                                   ctr;

    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.res = globus_error_put(globus_object_copy(error));
        }
        else
        {
     
            if(ftp_response->code == 229)
            {
                tmp_ptr = strstr((const char *)ftp_response->response_buffer,
                              "(");
                while(tmp_ptr != GLOBUS_NULL)
                {
                    addr = (globus_ftp_control_host_port_t * )
                       globus_malloc(sizeof(globus_ftp_control_host_port_t));

                    sscanf(tmp_ptr, "(%d,%d,%d,%d,%d,%d)",
                        &addr->host[0],
                        &addr->host[1],
                        &addr->host[2],
                        &addr->host[3],
                        &hi,
                        &low); 
                    addr->port = (hi * 256) + low;

                    globus_list_insert(&list, addr);

                    tmp_ptr++;
                    tmp_ptr = strstr(
                                  (const char *)tmp_ptr,
                                  "(");
                }
                spas_addr = (globus_ftp_control_host_port_t * )
                         globus_malloc(sizeof(globus_ftp_control_host_port_t)
                                       * globus_list_size(list));

                ctr = 0;
                while(!globus_list_empty(list))
                {
                    addr = (globus_ftp_control_host_port_t *)
                               globus_list_first(list);
                    globus_list_remove(&list, list);

                    globus_ftp_control_host_port_copy(&spas_addr[ctr], addr);
                    globus_free(addr);

                    ctr++;
                }
        
                g_monitor.res = globus_ftp_control_local_spor(
                                    &g_control_handle,
                                    spas_addr,
                                    ctr);
                globus_free(spas_addr);
                g_monitor.done = GLOBUS_TRUE;
                globus_cond_signal(&g_monitor.cond);
            }
            else
            {
                g_monitor.res = globus_error_put(
                         globus_error_construct_string(
                             GLOBUS_FTP_CONTROL_MODULE,
                             GLOBUS_NULL,
                             "spas failed: %s",
                             ftp_response->response_buffer));
            }
            printf("%s\n", ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
pasv_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_ftp_control_host_port_t *      addr;
    int                                   hi;
    int                                   low;
    char *                                tmp_ptr;

    addr = (globus_ftp_control_host_port_t *)callback_arg;

    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.res = globus_error_put(globus_object_copy(error));
        }
        else
        {
            if(ftp_response->code == 227)
            {
                tmp_ptr = strstr((const char *)ftp_response->response_buffer, 
                              "(");
                sscanf(tmp_ptr, "(%d,%d,%d,%d,%d,%d)",
                    &addr->host[0],
                    &addr->host[1],
                    &addr->host[2],
                    &addr->host[3],
                    &hi,
                    &low);
                addr->port = (hi * 256) + low;

                printf("(%d,%d,%d,%d,%d,%d)",
                    addr->host[0],
                    addr->host[1],
                    addr->host[2],
                    addr->host[3],
                    hi,
                    low);

            }
            else
            {
                g_monitor.res = globus_error_put(
                         globus_error_construct_string(
                             GLOBUS_FTP_CONTROL_MODULE,
                             GLOBUS_NULL,
                             "pasv failed: %s",
                             ftp_response->response_buffer));
            }
            printf("%s\n", ftp_response->response_buffer);
        }
        g_monitor.res = globus_ftp_control_local_port(
                            &g_control_handle,
                            addr);
        g_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

globus_result_t
pasv_mode()
{
    globus_ftp_control_host_port_t        addr;
    globus_result_t                       res;

    gftp_monitor_reset(&g_monitor);
    if(!g_spas)
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "PASV\r\n",
                  pasv_callback,
                  &addr);
    }
    else
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "SPAS\r\n",
                  spas_callback,
                  &addr);
    }
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
  
    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }


    return res;
}

globus_result_t
port_mode()
{
    globus_result_t                       res;
    globus_ftp_control_host_port_t        addr;
    char                                  buf[64];
    int                                   hi;
    int                                   low;

    globus_ftp_control_host_port_init(&addr, GLOBUS_NULL, 0);
    res = globus_ftp_control_local_pasv(
              &g_control_handle,
              &addr);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    hi = addr.port / 256;
    low = addr.port % 256;

    sprintf(buf, "PORT %d,%d,%d,%d,%d,%d", 
                addr.host[0],
                addr.host[1],
                addr.host[2],
                addr.host[3],
                hi,
                low); 
    res = generic_command(buf, GLOBUS_NULL);

    return res;
}

/*
 * get
 */
void
get_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    int                                         fd;
    globus_result_t                             res;
    int                                         nbytes;
    float                                       rate;
    globus_abstime_t                            new_time;
    globus_reltime_t                            diff_time;
    long                                        utime;

    fd = (int)callback_arg;

    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error == GLOBUS_NULL)
        {
            lseek(fd, (off_t)offset, SEEK_SET);
            nbytes = write(fd, buffer, (size_t)length);
            if(nbytes != length)
            {
                printf("An error occured while writting the file.\n");
            }
            if(eof)
            {
                globus_free(buffer);
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
            else
            {
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          g_buffer_size, 
                          get_read_data_callback,
                          (void *)fd);
            }
            g_bytes_tranfsered += length;
            GlobusTimeAbstimeGetCurrent(new_time);
            GlobusTimeAbstimeDiff(diff_time, new_time, g_start_time);
            GlobusTimeAbstimeCopy(g_start_time, new_time);
            GlobusTimeReltimeToUSec(utime, diff_time);
            rate = (float)length / (float)(utime / 1000000.0) / 1000.0;

            print_tick(rate);
        }
        else
        {
            globus_free(buffer);
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
get_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_byte_t *                             buffer;
    globus_result_t                             res;
    int                                         localfd;
    int                                         ctr;

    localfd = (int)callback_arg;
   
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
        else
        {
            if(ftp_response->code == 150)
            {
                for(ctr = 0; ctr < g_parallel * 2; ctr++)
                {
                    buffer = globus_malloc(g_buffer_size);   
                    res = globus_ftp_control_data_read(
                              handle,
                              buffer,
                              g_buffer_size, 
                              get_read_data_callback,
                              (void *)localfd);

                    if(res != GLOBUS_SUCCESS)
                    {
                        g_monitor.res = res;
                    }
                    else
                    {
                        g_monitor.count++;
                    }
                }
            }
            else if(ftp_response->code == 226)
            {
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
            else
            {
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
            } 
            printf("%s\n", ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
start_transfer()
{
    g_transfer_in_progress = GLOBUS_TRUE;
    g_bytes_tranfsered = 0;
    g_control_c = GLOBUS_FALSE;
    GlobusTimeAbstimeGetCurrent(g_start_time);   
}

void
stop_transfer()
{
    g_transfer_in_progress = GLOBUS_FALSE;
    g_control_c = GLOBUS_FALSE;
    g_size = -1;
}

globus_result_t
eget_command(
    char *                                command_str)
{
    char *                                localname;
    char *                                remotename;
    char *                                alg_info;
    char *                                arg[4];
    int                                   ctr;
    int                                   argc;
    globus_result_t                       res;

    for(ctr = 0; ctr < 4; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 4);

    if(argc < 3)
    {
        printf("Must specify a file name and the appropriate alg info.\n");

        return GLOBUS_SUCCESS;
    }
    else if(argc < 4)
    {
        localname = arg[2];
        remotename = arg[2];
    }
    else if(argc < 5)
    {
        remotename = arg[2];
        localname = arg[3];
    }

    alg_info = arg[1];

    res = l_get_command(
               localname,
               remotename,
               "ERET",
               alg_info);

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
get_command(
    char *                                command_str)
{
    char *                                localname;
    char *                                remotename;
    char *                                arg[3];
    int                                   ctr;
    int                                   argc;
    globus_result_t                       res;

    for(ctr = 0; ctr < 3; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 3);

    if(argc < 2)
    {
        printf("Must specify a file name.\n");

        return GLOBUS_SUCCESS;
    }
    else if(argc < 3)
    {
        localname = arg[1];
        remotename = arg[1];
    }
    else if(argc < 4)
    {
        remotename = arg[1];
        localname = arg[2];
    }

    res = l_get_command(
               localname,
               remotename,
               "RETR",
               "");

    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }

    return res;
}

globus_result_t
l_get_command(
    char *                                localname,
    char *                                remotename,
    char *                                server_cmd,
    char *                                alg_info)
{
    int                                   ctr;
    globus_bool_t                         passive = GLOBUS_FALSE;
    globus_result_t                       res;
    int                                   fd;

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    if(g_mode == GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK)
    {
        char                          par_buf[128]; 
        int                           par_code;

        /* set layout buffer and parallelism info */ 
        sprintf(par_buf, "OPTS RETR Parallelism=%d;", g_parallel);
        res = generic_command(par_buf, &par_code);
        if(res != GLOBUS_SUCCESS)
        {   
            goto exit;
        }

        res = port_mode();
    }
    else
    {
        if(g_passive)
        {
            res = pasv_mode();
        }
        else
        {
            res = port_mode();
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    fd = open(localname, O_CREAT | O_WRONLY,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0)
    {
        printf("Invalid local file: %s.\n", localname);
        goto exit;
    }

    res = get_remote_file_size(remotename, &g_size);
    if(res != GLOBUS_SUCCESS)
    {
        g_size = -1;
    }

    gftp_monitor_reset(&g_monitor);
    g_monitor.count = 1;
    start_transfer();
    res = globus_ftp_control_send_command(
              &g_control_handle, 
              "%s %s %s\r\n",
              get_callback,
              (void *)fd,
              server_cmd,
              alg_info,
              remotename);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    res = globus_ftp_control_data_connect_read(
              &g_control_handle, GLOBUS_NULL, GLOBUS_NULL);
    assert(res == GLOBUS_SUCCESS);

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(g_monitor.count > 0)
        {
            globus_cond_wait(&g_monitor.mutex, &g_monitor.cond);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);

    close(fd);

  exit:
    stop_transfer();
    return res;
}

/*
 * list
 */
void
list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    globus_result_t                             res;

    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error == GLOBUS_NULL)
        {
            write(STDOUT_FILENO, buffer, length);

            if(!eof)
            {
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          g_buffer_size, 
                          list_read_data_callback,
                          GLOBUS_NULL);
                if(res != GLOBUS_SUCCESS)
                {
                    g_monitor.res = res;
                }
            }
            else
            {
                globus_free(buffer);
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
        }
        else 
        {
            globus_free(buffer);
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
list_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_byte_t *                             buffer;
    globus_result_t                             res;
    
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.done = GLOBUS_TRUE;
            globus_cond_signal(&g_monitor.cond);
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
        }
        else
        {
            if(ftp_response->code == 150)
            {
                buffer = globus_malloc(g_buffer_size);   
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          g_buffer_size, 
                          list_read_data_callback,
                          GLOBUS_NULL);
                if(res != GLOBUS_SUCCESS)
                {
                    g_monitor.res = res;
                }
                else
                {
                    g_monitor.count++;
                }
                globus_cond_signal(&g_monitor.cond);
            }
            else if(ftp_response->code == 226 || ftp_response->code == 425)
            {
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
            else
            {
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
            } 
            printf("%s\n", ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

globus_result_t
list_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];
    char                                  cmd[5];

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 2);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(g_mode == GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK)
    {
        /* set layout buffer and parallelism info */ 
        res = port_mode();
    }
    else
    {
        if(g_passive)
        {
            res = pasv_mode();
        }
        else
        {
            res = port_mode();
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    if(strcmp(arg[0], "nlist") == 0 || 
       strcmp(arg[0], "ls") == 0)
    {
        sprintf(cmd, "NLST");
    }
    else
    {
        sprintf(cmd, "LIST");
    }

    gftp_monitor_reset(&g_monitor);
    g_monitor.count++;
    if(argc > 1)
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "%s %s\r\n",
                  list_callback,
                  GLOBUS_NULL,
                  cmd,
                  arg[1]);
    }
    else
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "%s\r\n",
                  list_callback,
                  GLOBUS_NULL,
                  cmd);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    res = globus_ftp_control_data_connect_read(
              &g_control_handle, GLOBUS_NULL, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(g_monitor.count != 0)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }
    return res;
}

globus_result_t
mlsd_command(
    char *                                command_str)
{
    globus_result_t                       res;
    int                                   ctr;
    int                                   argc;
    char *                                arg[2];
    char                                  cmd[5];

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 2; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 2);
    }
    argc = parse_list_args(command_str, arg, 2);

    if(g_mode == GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK)
    {
        /* set layout buffer and parallelism info */ 
        res = port_mode();
    }
    else
    {
        if(g_passive)
        {
            res = pasv_mode();
        }
        else
        {
            res = port_mode();
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    sprintf(cmd, "MLSD");

    gftp_monitor_reset(&g_monitor);
    g_monitor.count++;
    if(argc > 1)
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "%s %s\r\n",
                  list_callback,
                  GLOBUS_NULL,
                  cmd,
                  arg[1]);
    }
    else
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "%s\r\n",
                  list_callback,
                  GLOBUS_NULL,
                  cmd);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    res = globus_ftp_control_data_connect_read(
              &g_control_handle, GLOBUS_NULL, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(g_monitor.count != 0)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }
    return res;
}

char *
trim_spaces(
    char *                                      str)
{
    int                                         ctr;
    char *                                      tmp_ptr;
    char *                                      back_ptr;

    if(str == GLOBUS_NULL)
    {
        return GLOBUS_NULL;
    } 

    tmp_ptr = str;
    ctr = 0;
    while(ctr < strlen(str) && isspace(*tmp_ptr))
    {
        tmp_ptr++;
        ctr++;
    }

    back_ptr = str + strlen(str) - 1;
    ctr = 0;
    while(ctr < strlen(str) && isspace(*back_ptr))
    {
        *back_ptr = '\0';
        back_ptr--;
        ctr++;
    }

    return tmp_ptr;
}

void
put_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                               offset,
    globus_bool_t                               eof)
{
    gftp_monitor_t *                            monitor;
    float                                       rate;
    globus_abstime_t                            new_time;
    globus_reltime_t                            diff_time;
    long                                        utime;

    monitor = (gftp_monitor_t *)callback_arg;

    if(error != GLOBUS_NULL)
    {
            printf("*Error*: %s\n", 
                globus_object_printable_to_string(error));
    }

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->count--;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);

    if(error == GLOBUS_NULL)
    {
        g_bytes_tranfsered += length;
        GlobusTimeAbstimeGetCurrent(new_time);
        GlobusTimeAbstimeDiff(diff_time, new_time, g_start_time);
        GlobusTimeAbstimeCopy(g_start_time, new_time);
        GlobusTimeReltimeToUSec(utime, diff_time);
        rate = (float)length / (float)(utime / 1000000.0) / 1000.0;

        print_tick(rate);
    }
    if(eof)
    {
        globus_mutex_lock(&g_monitor.mutex);
        {
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
        globus_mutex_lock(&g_monitor.mutex);
    }

    globus_free(buffer);
}

void
put_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_byte_t *                             buffer;
    globus_result_t                             res;
    int                                         localfd;
    int                                         ctr;
    int                                         nbytes;
    int                                         offset = 0;
    globus_bool_t                               eof = GLOBUS_FALSE;
    gftp_monitor_t                              monitor;

    gftp_monitor_init(&monitor);

    localfd = (int)callback_arg;
    
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            printf("*Error*: %s\n", 
                globus_object_printable_to_string(error));
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
        else
        {
            printf("%s\n", ftp_response->response_buffer);

            if(ftp_response->code == 150)
            {
                g_monitor.count++;
                while(!eof)
                {
                    buffer = globus_malloc(g_buffer_size);   

                    nbytes = read(localfd, buffer, g_buffer_size);
                    if(nbytes == 0)
                    {
                        eof = GLOBUS_TRUE;
                    }
                    monitor.count++;
                    res = globus_ftp_control_data_write(
                              handle,
                              buffer,
                              nbytes,
                              offset,
                              eof,
                              put_write_callback,
                              (void *)&monitor);
                    if(res != GLOBUS_SUCCESS)
                    {
                        /* need to do a force close here */
                        g_monitor.res = res;
                        eof = GLOBUS_TRUE;
                        monitor.count--;
                    }
                    offset += nbytes;

                    /* 
                     * allow g_parallel * 2 callbacks to be outstanding
                     * at one time 
                     */
                    globus_mutex_lock(&monitor.mutex);
                    {
                        while(monitor.count == g_parallel * 2)
                        {
                            globus_cond_wait(&monitor.cond, &monitor.mutex);
                        }
                    }
                    globus_mutex_unlock(&monitor.mutex);
                }
                /*
                 * wait for all callbacks to return
                 */
                globus_mutex_lock(&monitor.mutex);
                {
                    while(monitor.count > 0)
                    {
                        globus_cond_wait(&monitor.cond, &monitor.mutex);
                    }
                }
                globus_mutex_unlock(&monitor.mutex);
            }
            else if(ftp_response->code == 226)
            {
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
            else if(ftp_response->code > 400)
            {
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
            } 
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);

}

globus_result_t
put_command(
    char *                                command_str)
{
    char *                                arg[3];
    int                                   ctr;
    int                                   argc;
    char *                                localname;
    char *                                remotename;
    globus_bool_t                         passive = GLOBUS_FALSE;
    globus_result_t                       res = GLOBUS_SUCCESS;
    int                                   fd;
    globus_ftp_control_layout_t           layout;
    struct stat                           stat_buf;

    if(!g_connected)
    {
        printf("Not connected.\n");
        return GLOBUS_SUCCESS;
    }

    for(ctr = 0; ctr < 3; ctr++)
    {
        arg[ctr] = globus_malloc(strlen(command_str) + 1);
    }
    argc = parse_list_args(command_str, arg, 3);

    if(argc < 2)
    {
        printf("Must specify a file name.\n");

        return GLOBUS_SUCCESS;
    }
    else if(argc < 3)
    {
        localname = arg[1];
        remotename = arg[1];
    }
    else if(argc < 4)
    {
        localname = arg[1];
        remotename = arg[2];
    }

    if(g_mode == GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK)
    {
        stat(localname, &stat_buf);

        /* set layout buffer and parallelism info */ 
        layout.mode = GLOBUS_FTP_CONTROL_STRIPING_PARTITIONED;
        layout.partitioned.size = stat_buf.st_size;

        globus_ftp_control_local_layout(
            &g_control_handle,
            &layout,
            0);

        res = pasv_mode();
    }
    else
    {
        if(g_passive)
        {
            res = pasv_mode();
        }
        else
        {
            res = port_mode();
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    fd = open(localname, O_RDONLY);
    if(fd < 0)
    {
        printf("file %s is not localfile.\n", localname);
        goto exit;
    }

    gftp_monitor_reset(&g_monitor);
    g_monitor.count = 1;
    g_transfer_in_progress = GLOBUS_TRUE;
    res = globus_ftp_control_send_command(
              &g_control_handle,
              "STOR %s\r\n",
              put_callback,
              (void *)fd,
              remotename);
    if(res != GLOBUS_SUCCESS)
    {
        goto close_exit;
    }
    res = globus_ftp_control_data_connect_write(
              &g_control_handle, GLOBUS_NULL, GLOBUS_NULL);
    assert(res == GLOBUS_SUCCESS);

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(g_monitor.count > 0)
        {
            globus_cond_wait(&g_monitor.mutex, &g_monitor.cond);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);

  close_exit:
    close(fd);

  exit:
    for(ctr = 0; ctr < 2; ctr++)
    {
        globus_free(arg[ctr]);
    }
    return res;
}

char *
create_name_list(
    globus_fifo_t *                             name_q,
    char *                                      first,
    globus_byte_t *                             in_buffer,
    int                                         len)
{
    char *                                      tmp_ptr;
    char *                                      tmp_ptr2;
    char *                                      start;
    int                                         ctr = 0;
    char *                                      buffer;
    char *                                      remainder = GLOBUS_NULL;
    globus_list_t *                             name_list = GLOBUS_NULL;
    int                                         first_len = 0;

    if(first != GLOBUS_NULL)
    {
        first_len = strlen(first);
        buffer = globus_malloc(len + 1 + first_len);
        memcpy(buffer, first, first_len);
        memcpy(&buffer[first_len], in_buffer, len);
        buffer[len+first_len] = '\0';
   
        free(first);
    }
    else
    {
        buffer = globus_malloc(len + 1);
        memcpy(buffer, in_buffer, len);
        buffer[len] = '\0';
    }

    start = buffer;
    tmp_ptr = strstr(start, "\n");
    while(tmp_ptr != GLOBUS_NULL)
    {
        tmp_ptr[0] = '\0';
        tmp_ptr2 = strdup(start);

        globus_fifo_enqueue(name_q, tmp_ptr2);

        start = &tmp_ptr[1];

        tmp_ptr = strstr(start, "\n");
    }

    if(start[0] != '\0')
    {
        remainder = strdup(start);
    }

    globus_free(buffer);

    return remainder;
}
    


/*
 * list
 */
void
mget_list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    globus_result_t                             res;
    globus_fifo_t *                             name_q;
    static char *                               first_word = GLOBUS_NULL;

    name_q = (globus_fifo_t *)callback_arg;

    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error == GLOBUS_NULL)
        {
            first_word = create_name_list(
                             name_q, first_word, buffer, length);

            if(!eof)
            {
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          g_buffer_size, 
                          mget_list_read_data_callback,
                          GLOBUS_NULL);
                if(res != GLOBUS_SUCCESS)
                {
                    g_monitor.res = res;
                }
            }
            else
            {
                if(first_word != GLOBUS_NULL)
                {
                    globus_fifo_enqueue(name_q, first_word);
                }
                globus_free(buffer);
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
        }
        else 
        {
            globus_free(buffer);
            g_monitor.count--;
            globus_cond_signal(&g_monitor.cond);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
mget_list_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_byte_t *                             buffer;
    globus_result_t                             res;
    
    globus_mutex_lock(&g_monitor.mutex);
    {
        if(error != GLOBUS_NULL)
        {
            g_monitor.done = GLOBUS_TRUE;
            globus_cond_signal(&g_monitor.cond);
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
        }
        else
        {
            if(ftp_response->code == 150)
            {
                buffer = globus_malloc(g_buffer_size);   
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          g_buffer_size, 
                          mget_list_read_data_callback,
                          callback_arg);
                if(res != GLOBUS_SUCCESS)
                {
                    g_monitor.res = res;
                }
                else
                {
                    g_monitor.count++;
                }
                globus_cond_signal(&g_monitor.cond);
            }
            else if(ftp_response->code == 226)
            {
                g_monitor.count--;
                globus_cond_signal(&g_monitor.cond);
            }
            else
            {
                res = globus_ftp_control_data_force_close(
                          handle,
                          force_close_callback,
                          GLOBUS_NULL);
            } 
            printf("%s\n", ftp_response->response_buffer);
        }
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
mget_list_command(
    globus_fifo_t *                       name_q,
    char *                                wildcard)
{
    globus_result_t                       res;
    int                                   ctr;

    if(g_mode == GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK)
    {
        /* set layout buffer and parallelism info */ 
        res = port_mode();
    }
    else
    {
        if(g_passive)
        {
            res = pasv_mode();
        }
        else
        {
            res = port_mode();
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    gftp_monitor_reset(&g_monitor);
    g_monitor.count++;
    if(wildcard != GLOBUS_NULL)
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "NLST %s\r\n",
                  mget_list_callback,
                  name_q,
                  wildcard);
    }
    else
    {
        res = globus_ftp_control_send_command(
                  &g_control_handle, 
                  "NLST\r\n",
                  mget_list_callback,
                  name_q);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    res = globus_ftp_control_data_connect_read(
              &g_control_handle, GLOBUS_NULL, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(g_monitor.count != 0)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        res = g_monitor.res;
    }
    globus_mutex_unlock(&g_monitor.mutex);

  exit:
    return;
}

