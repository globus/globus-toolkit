#if !defined(GLOBUS_GRIDFTP_SERVER_PMOD_959_H)
#define GLOBUS_GRIDFTP_SERVER_PMOD_959_H 1

struct globus_l_gsp_959_handle_s;
struct globus_l_gsp_959_read_ent_s;


typedef struct globus_l_gsp_959_handle_s *  globus_gs_pmod_959_handle_t;
typedef struct globus_l_gsp_959_read_ent_s * globus_gs_pmod_959_op_t;

void
globus_gs_pmod_959_finished_op(
    globus_gs_pmod_959_op_t                 op,
    globus_result_t                         result);

typedef globus_result_t
(*globus_gs_pmod_959_command_func_t)(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            full_command,
    void *                                  user_arg);

/*
 *  This can be called locked
 */
typedef void
(*globus_gs_pmod_959_reply_format_func_t)(
    globus_gs_pmod_959_handle_t             handle,
    globus_result_t                         result,
    void *                                  user_arg,
    int *                                   out_reply_code,
    char **                                 out_reply_msg);

globus_result_t
globus_gs_pmod_959_command_add(
    globus_gs_pmod_959_handle_t             handle,
    const char *                            command_name,
    globus_gs_pmod_959_command_func_t       command_func,
    globus_gs_pmod_959_reply_format_func_t  reply_format_func,
    void *                                  user_arg);

#endif
