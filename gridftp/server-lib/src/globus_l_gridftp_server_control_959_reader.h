/*
 *  959 protocol module for gridftp_server_control library
 *
 *  Interface to the 959 protocol module.  A user can extend or override
 *  commands to the 959 protocol.
 */

#if !defined(GLOBUS_GRIDFTP_SERVER_PMOD_959_H)
#define GLOBUS_GRIDFTP_SERVER_PMOD_959_H 1

#include "globus_gridftp_server_control_pmod.h"

struct globus_l_gsp_959_handle_s;
struct globus_l_gsp_959_read_ent_s;

globus_result_t
globus_l_gsc_959_init();

globus_result_t
globus_gsc_pmod_959_intermediate_reply(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg);

void
globus_gsc_pmod_959_finished_op(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg);

globus_result_t
globus_gsc_pmod_959_get_server(
    globus_gridftp_server_control_t *               out_server,
    globus_gsc_pmod_959_handle_t                    handle);

/*
 *  the oepration is only valid for the life of this function
 */
typedef void
(*globus_gsc_959_command_func_t)(
    globus_gsc_op_959_t *                   op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg);

typedef void
(*globus_gsc_pmod_959_abort_func_t)(
    globus_gsc_op_959_t *                   op,
    void *                                  user_arg);

typedef enum globus_gsc_959_command_desc_e
{
    GLOBUS_GSC_959_COMMAND_POST_AUTH = 0x01,
    GLOBUS_GSC_959_COMMAND_PRE_AUTH = 0x02
} globus_gsc_959_command_desc_t;

globus_result_t
globus_gsc_pmod_959_command_add(
    globus_gsc_pmod_959_handle_t            handle,
    const char *                            command_name,
    globus_gsc_pmod_959_command_func_t      command_func,
    globus_gsc_959_command_desc_t           desc,
    const char *                            help,
    void *                                  user_arg);

globus_result_t
globus_gsc_pmod_959_get_cred(
    globus_gsc_op_959_t *                   op,
    gss_cred_id_t *                         out_cred,
    gss_cred_id_t *                         out_del_cred);

char *
globus_gsc_pmod_959_get_help(
    globus_gsc_pmod_959_handle_t            handle,
    const char *                            command_name);

void
globus_gsc_959_panic(
    globus_gsc_op_959_t *                   op);

extern globus_i_gridftp_server_control_pmod_t       globus_i_gsc_959_proto_mod;

#endif
