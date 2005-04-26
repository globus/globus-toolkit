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

extern char *process_msg(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize, char **users);
extern gaa_status process_assert(gaa_ptr gaa, gaa_sc_ptr sc, char **users, char *outbuf, int outbsize);
extern gaa_status process_getpolicy(globus_authorization_handle_t handle, char *outbuf, int outbsize);
extern gaa_status process_request(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize);
extern void process_print(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_inquire(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_clear(gaa_sc_ptr *sc);
extern init_sc(gaa_ptr gaa, gaa_sc_ptr *sc, void *context);
extern gaa_status process_pull(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize);
