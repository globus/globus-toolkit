


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
