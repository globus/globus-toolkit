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




globus_bool_t
fail_test(
    globus_ftp_control_handle_t *               control_handle)
{

}


globus_bool_t
test_one(
    globus_ftp_control_handle_t *               control_handle)
{
    globus_result_t                             result;

    result = globus_ftp_control_send_command(
                 control_handle,
                 ....);
   if(result == GLOBUS_SUCESS)
   {
       return GLOBUS_FALSE;
   }
}
