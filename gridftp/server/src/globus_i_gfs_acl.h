#ifndef GLOBUS_I_GFS_ACL_H
#define GLOBUS_I_GFS_ACL_H

struct globus_i_gfs_acl_handle_s;

typedef enum globus_l_gfs_acl_type_e
{
    GLOBUS_L_GFS_ACL_TYPE_INIT,
    GLOBUS_L_GFS_ACL_TYPE_AUTHORIZE
} globus_i_gfs_acl_type_t;

/*
 *  user functions.  used by control.c or DSI implementation if it choses.
 */
typedef void
(*globus_gfs_acl_cb_t)(
    const char *                        resource_id,
    void *                              user_arg,
    globus_result_t                     result);


globus_result_t
globus_gfs_acl_authorize(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    const char *                        action,
    const char *                        object,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg);

int
globus_i_gfs_acl_init(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    const gss_ctx_id_t                  context,
    const char *                        user_id,
    const char *                        resource_id,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg);

void
globus_i_gfs_acl_destroy(
    struct globus_i_gfs_acl_handle_s *  acl_handle);

/*
 *  interface implementation functions
 */
enum
{
    GLOBUS_GFS_ACL_COMPLETE,
    GLOBUS_GFS_ACL_WOULD_BLOCK,
};

typedef int
(*globus_gfs_acl_init_t)(
    void **                             out_handle,
    const gss_ctx_id_t                  context,
    const char *                        user_id,
    const char *                        resource_id,
    int                                 request_id,
    globus_result_t *                   out_res);

typedef int
(*globus_gfs_acl_authorize_t)(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    int                                 request_id,
    globus_result_t *                   out_res);

void
globus_gfs_acl_authorized_finished(
    int                                 request_id,
    globus_result_t                     result);

typedef void
(*globus_gfs_acl_destroy_t)(
    void *                              out_handle);

typedef struct globus_gfs_acl_module_s
{
    globus_gfs_acl_init_t               init_func;
    globus_gfs_acl_authorize_t          authorize_func;
    globus_gfs_acl_destroy_t            destroy_func;
} globus_gfs_acl_module_t;

typedef struct globus_i_gfs_acl_handle_s
{
    gss_ctx_id_t                        context;
    globus_i_gfs_acl_type_t             type;
    char *                              user_id;
    char *                              auth_action;
    char *                              auth_object;
    globus_gfs_acl_cb_t                 cb;
    void *                              user_arg;
    globus_list_t *                     module_list;
    globus_list_t *                     current_list;
    globus_result_t                     cached_res;
} globus_i_gfs_acl_handle_t;

void
globus_gfs_acl_add_module(
    globus_gfs_acl_module_t *           module);

#endif
