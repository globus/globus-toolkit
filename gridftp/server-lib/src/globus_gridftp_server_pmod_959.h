#if !defined(GLOBUS_GRIDFTP_SERVER_PMOD_959_H)
#define GLOBUS_GRIDFTP_SERVER_PMOD_959_H 1

#include "globus_gridftp_server.h"

struct globus_l_gsp_959_handle_s;
struct globus_l_gsp_959_read_ent_s;


typedef struct globus_l_gsp_959_handle_s *  globus_gs_pmod_959_handle_t;
typedef struct globus_l_gsp_959_read_ent_s * globus_gs_pmod_959_op_t;

globus_result_t
globus_l_gsp_959_init();

void
globus_gs_pmod_959_finished_op(
    globus_gs_pmod_959_op_t                 op,
    int                                     reply_code,
    char *                                  reply_msg);

typedef void
(*globus_gs_pmod_959_command_func_t)(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg);

globus_result_t
globus_gs_pmod_959_command_add(
    globus_gs_pmod_959_handle_t             handle,
    const char *                            command_name,
    globus_gs_pmod_959_command_func_t       command_func,
    void *                                  user_arg);

extern globus_i_gridftp_server_pmod_t       globus_i_gsp_959_proto_mod;

#endif
