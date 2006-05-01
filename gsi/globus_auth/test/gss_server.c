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

/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "globus_auth.h"
#include "gss_misc.h"
#include "gaa.h"
#include "gaa_utils.h"

#ifndef gss_nt_service_name
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#endif

#ifndef gss_nt_user_name
#define gss_nt_user_name GSS_C_NT_USER_NAME
#endif

#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

void usage()
{
     fprintf(stderr, "Usage: gss-server [-port port] [-verbose]\n");
     fprintf(stderr, "       [-inetd] [-logfile file] [service_name]\n");
     fprintf(stderr, "       [-cf cffile]\n");
     exit(1);
}

FILE *log;

int verbose = 0;
int expimp = 0; /* export_sec_context then import_sec_context */

char *users = 0;

/*
 * Function: server_acquire_creds
 *
 * Purpose: imports a service name and acquires credentials for it
 *
 * Arguments:
 *
 *     service_name    (r) the ASCII service name
 *     server_creds    (w) the GSS-API service credentials
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * The service name is imported with gss_import_name, and service
 * credentials are acquired with gss_acquire_cred.  If either opertion
 * fails, an error message is displayed and -1 is returned; otherwise,
 * 0 is returned.
 */
int server_acquire_creds(service_name, server_creds)
     char *service_name;
     gss_cred_id_t *server_creds;
{
     gss_buffer_desc name_buf;
     gss_name_t server_name = GSS_C_NO_NAME;
     OM_uint32 maj_stat, min_stat;

     if (service_name) {
     name_buf.value = service_name;
     name_buf.length = strlen(name_buf.value) + 1;
     maj_stat = gss_import_name(&min_stat, &name_buf, 
                (gss_OID) gss_nt_user_name, &server_name);
     if (maj_stat != GSS_S_COMPLETE) {
      display_status("importing name", maj_stat, min_stat);
      return -1;
     }
     }

     maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
                 GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
                 server_creds, NULL, NULL);
     if (maj_stat != GSS_S_COMPLETE) {
      display_status("acquiring credentials", maj_stat, min_stat);
      return -1;
     }

     (void) gss_release_name(&min_stat, &server_name);

     return 0;
}

/*
 * Function: server_establish_context
 *
 * Purpose: establishses a GSS-API context as a specified service with
 * an incoming client, and returns the context handle and associated
 * client name
 *
 * Arguments:
 *
 *     s        (r) an established TCP connection to the client
 *     service_creds    (r) server credentials, from gss_acquire_cred
 *     context        (w) the established GSS-API context
 *     client_name    (w) the client's ASCII name
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * Any valid client request is accepted.  If a context is established,
 * its handle is returned in context and the client name is returned
 * in client_name and 0 is returned.  If unsuccessful, an error
 * message is displayed and -1 is returned.
 */
int server_establish_context(s, server_creds, context, client_name, ret_flags)
     int s;
     gss_cred_id_t server_creds;
     gss_ctx_id_t *context;
     gss_buffer_t client_name;
     OM_uint32 *ret_flags;
{
     gss_buffer_desc send_tok, recv_tok;
     gss_name_t client;
     gss_OID doid;
     OM_uint32 maj_stat, min_stat;
     gss_buffer_desc    oid_name;

     *context = GSS_C_NO_CONTEXT;
     
     do {
      if (recv_token(s, &recv_tok) < 0)
           return -1;

      if (verbose && log) {
          fprintf(log, "Received token (size=%d): \n", recv_tok.length);
          print_token(&recv_tok);
      }

      maj_stat =
           gss_accept_sec_context(&min_stat,
                      context,
                      server_creds,
                      &recv_tok,
                      GSS_C_NO_CHANNEL_BINDINGS,
                      &client,
                      &doid,
                      &send_tok,
                      ret_flags,
                      NULL,     /* ignore time_rec */
                      NULL);     /* ignore del_cred_handle */

      if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
           display_status("accepting context", maj_stat, min_stat);
           (void) gss_release_buffer(&min_stat, &recv_tok);
           return -1;
      }

      (void) gss_release_buffer(&min_stat, &recv_tok);

      if (send_tok.length != 0) {
          if (verbose && log) {
          fprintf(log,
              "Sending accept_sec_context token (size=%d):\n",
              send_tok.length);
          print_token(&send_tok);
          }
           if (send_token(s, &send_tok) < 0) {
            fprintf(log, "failure sending token\n");
            return -1;
           }

           (void) gss_release_buffer(&min_stat, &send_tok);
      }
      if (verbose && log) {
          if (maj_stat == GSS_S_CONTINUE_NEEDED)
          fprintf(log, "continue needed...\n");
          else
          fprintf(log, "\n");
          fflush(log);
      }
     } while (maj_stat == GSS_S_CONTINUE_NEEDED);

     /* display the flags */
     display_ctx_flags(*ret_flags);

#if 0
     if (verbose && log) {
     maj_stat = gss_oid_to_str(&min_stat, doid, &oid_name);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("converting oid->string", maj_stat, min_stat);
         return -1;
     }
     fprintf(log, "Accepted connection using mechanism OID %.*s.\n",
         (int) oid_name.length, (char *) oid_name.value);
     (void) gss_release_buffer(&min_stat, &oid_name);
     }
#endif

     maj_stat = gss_display_name(&min_stat, client, client_name, &doid);
     if (maj_stat != GSS_S_COMPLETE) {
      display_status("displaying name", maj_stat, min_stat);
      return -1;
     }
     maj_stat = gss_release_name(&min_stat, &client);
     if (maj_stat != GSS_S_COMPLETE) {
      display_status("releasing name", maj_stat, min_stat);
      return -1;
     }
     return 0;
}

/*
 * Function: create_socket
 *
 * Purpose: Opens a listening TCP socket.
 *
 * Arguments:
 *
 *     port        (r) the port number on which to listen
 *
 * Returns: the listening socket file descriptor, or -1 on failure
 *
 * Effects:
 *
 * A listening socket on the specified port and created and returned.
 * On error, an error message is displayed and -1 is returned.
 */
int create_socket(port)
     u_short port;
{
     struct sockaddr_in saddr;
     int s;
     int on = 1;
     
     saddr.sin_family = AF_INET;
     saddr.sin_port = htons(port);
     saddr.sin_addr.s_addr = INADDR_ANY;

     if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("creating socket");
      return -1;
     }
     /* Let the socket be reused right away */
     (void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
     if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
      perror("binding socket");
      (void) close(s);
      return -1;
     }
     if (listen(s, 5) < 0) {
      perror("listening on socket");
      (void) close(s);
      return -1;
     }
     return s;
}

static float timeval_subtract(tv1, tv2)
    struct timeval *tv1, *tv2;
{
    return ((tv1->tv_sec - tv2->tv_sec) +
        ((float) (tv1->tv_usec - tv2->tv_usec)) / 1000000);
}

/*
 * Yes, yes, this isn't the best place for doing this test.
 * DO NOT REMOVE THIS UNTIL A BETTER TEST HAS BEEN WRITTEN, THOUGH.
 *                     -TYT
 */
int test_import_export_context(context)
    gss_ctx_id_t *context;
{
    OM_uint32    min_stat, maj_stat;
    gss_buffer_desc context_token, copied_token;
    struct timeval tm1, tm2;
    
#if 1
    /*
     * Attempt to save and then restore the context.
     */
    gettimeofday(&tm1, (struct timezone *)0);
    if (verbose && log) {
        fprintf(log, "Starting the export\n");
    }
    maj_stat = gss_export_sec_context(&min_stat, context, &context_token);
    
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("exporting context", maj_stat, min_stat);
        return 1;
    }
    gettimeofday(&tm2, (struct timezone *)0);
    if (verbose && log)
        fprintf(log, "Exported context: %d bytes, %7.4f seconds\n",
            context_token.length, timeval_subtract(&tm2, &tm1));
    copied_token.length = context_token.length;
    copied_token.value = malloc(context_token.length);
    if (copied_token.value == 0) {
        fprintf(log, "Couldn't allocate memory to copy context token.\n");
        return 1;
    }
    memcpy(copied_token.value, context_token.value, copied_token.length);
    maj_stat = gss_import_sec_context(&min_stat, &copied_token, context);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("importing context", maj_stat, min_stat);
        return 1;
    }
    gettimeofday(&tm1, (struct timezone *)0);
    if (verbose && log)
        fprintf(log, "Importing context: %7.4f seconds\n",
            timeval_subtract(&tm1, &tm2));
    (void) gss_release_buffer(&min_stat, &context_token);
#endif
    return 0;
}

/*
 * Function: sign_server
 *
 * Purpose: Performs the "sign" service.
 *
 * Arguments:
 *
 *     s        (r) a TCP socket on which a connection has been
 *            accept()ed
 *     service_name    (r) the ASCII name of the GSS-API service to
 *             establish a context as
 * 
 * Returns: -1 on error
 *
 * Effects:
 *
 * sign_server establishes a context, and performs a single sign request.
 *
 * A sign request is a single GSS-API sealed token.  The token is
 * unsealed and a signature block, produced with gss_sign, is returned
 * to the sender.  The context is the destroyed and the connection
 * closed.
 *
 * If any error occurs, -1 is returned.
 */
int sign_server(s, server_creds,handle, users)
     int s;
     gss_cred_id_t server_creds;
     globus_authorization_handle_t handle;
     char **users;
{
     gss_buffer_desc client_name, xmit_buf, msg_buf, repl_buf;
     gss_ctx_id_t context;
     OM_uint32 maj_stat, min_stat;
     char rbuf[8192];
     char *repl;
     int i;
     int conf_state = 0;
     int ret_flags = 0;
     char    *cp;
     globus_result_t result;
     char *          errstr;
     int             errnum;

     /* Establish a context with the client */
     if (server_establish_context(s, server_creds, &context,
                  &client_name, &ret_flags) < 0)
    return(-1);

     printf("Accepted connection: \"%.*s\"\n",
        (int) client_name.length, (char *) client_name.value);
     (void) gss_release_buffer(&min_stat, &client_name);
     
    if((result = globus_authorization_handle_set_gss_ctx(
                    handle,context)) != GLOBUS_SUCCESS)
     {
        globus_result_get_error_string(result, &errstr);
        globus_result_get_error_type(result, &errnum);
        globus_result_destroy(result);
        fprintf(stderr,"%s\n",errstr);
        return(errnum);
     }   
        
    while (recv_token(s, &xmit_buf) >= 0) {
        maj_stat = gss_unwrap(&min_stat, context, &xmit_buf, &msg_buf,
                  &conf_state, (gss_qop_t *) NULL);
        if (maj_stat != GSS_S_COMPLETE) {
        display_status("unsealing message", maj_stat, min_stat);
        return(-1);
        }

        (void) gss_release_buffer(&min_stat, &xmit_buf);

        fprintf(log, "Received message: ");
        cp = msg_buf.value;
        if (isprint(cp[0]) && isprint(cp[1]))
        fprintf(log, "\"%s\"\n", cp);
        else {
        printf("\n");
        print_token(&msg_buf);
        }
        repl = process_msg(handle, cp, rbuf, sizeof(rbuf), users);
        repl_buf.value = (repl ? repl : "");
        repl_buf.length = strlen(repl_buf.value)+1;

        /* Send the signature block to the client */
        if (send_token(s, &repl_buf) < 0)
        return(-1);
    }

     /* Delete context */
     maj_stat = gss_delete_sec_context(&min_stat, &context, NULL);
     if (maj_stat != GSS_S_COMPLETE) {
    display_status("deleting context", maj_stat, min_stat);
    return(-1);
     }

     fflush(log);

     return(0);
}

int
main(argc, argv)
     int argc;
     char **argv;
{
     char *         service_name;
     gss_cred_id_t  server_creds;
     OM_uint32      min_stat;
     u_short        port = 4444;
     int            s;
     int            once = 0;
     int            do_inetd = 0;
     char *         cfname = 0;
     globus_authorization_handle_t handle;
     globus_result_t result;
     char *         errstr;
     int            errnum;

     log = stdout;
     display_file = stdout;


     argc--; argv++;
     while (argc) {
      if (strcmp(*argv, "-port") == 0) {
           argc--; argv++;
           if (!argc) usage();
           port = atoi(*argv);
      } else if (strcmp(*argv, "-verbose") == 0) {
          verbose = 1;
      } else if (strcmp(*argv, "-expimp") == 0) {
          expimp++;   
      } else if (strcmp(*argv, "-once") == 0) {
          once = 1;
      } else if (strcmp(*argv, "-inetd") == 0) {
          do_inetd = 1;
      } else if (strcmp(*argv, "-cf") == 0) {
          argc--; argv++;
          if (!argc) usage();
          cfname = *argv;
      } else if (strcmp(*argv, "-logfile") == 0) {
          argc--; argv++;
          if (!argc) usage();
          log = fopen(*argv, "a");
          display_file = log;
          if (!log) {
          perror(*argv);
          exit(1);
          }
      } else
           break;
      argc--; argv++;
     }
     if (argc != 1) {
       if (argc == 0)  {
         service_name = NULL;
       } else
         usage();
     } else
       service_name = *argv;

     if (server_acquire_creds(service_name, &server_creds) < 0)
     return -1;

     if((result = globus_authorization_handle_init(
                    &handle, cfname)) != GLOBUS_SUCCESS)
     {
        globus_result_get_error_string(result, &errstr);
        globus_result_get_error_type(result, &errnum);
        globus_result_destroy(result);
        fprintf(stderr,"%s\n",errstr);
        return(errnum);
     }   

     if (do_inetd) {
        close(1);
        close(2);

        sign_server(0,server_creds,handle,&users);
        close(0);
     } 
     else {
        int stmp;

        if ((stmp = create_socket(port))) 
        {
            do{
                /* Accept a TCP connection */
                if ((s = accept(stmp, NULL, 0)) < 0) {
                    perror("accepting connection");
                } 
                else {
                    /* this return value is not checked, because there's
                    not really anything to do if it fails */
                    sign_server(s, server_creds, handle , &users);
                }
            }while(!once);
     
            (void) close(s);
            close(stmp);
            globus_authorization_handle_destroy(&handle);
            (void) gss_release_cred(&min_stat, &server_creds); 
        }     
        /*NOTREACHED*/ 
        return 0;
    }
}
