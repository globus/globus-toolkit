/*
 *  user functions.  used by control.c or DSI implementation if it choses.
 */
#include "globus_i_gridftp_server.h"
#include "globus_gsi_authz.h"
#include "globus_i_gfs_acl.h"


static void
globus_gfs_acl_cas_cb(
    void *                              callback_arg,
    globus_gsi_authz_handle_t           handle,
    globus_result_t                     result)
{
    globus_gfs_acl_authorized_finished((int)callback_arg, result);
}

static
void
tmp_cb(
    void *                              callback_arg)
{
    globus_gfs_acl_authorized_finished((int)callback_arg, GLOBUS_SUCCESS);
}

static int
globus_gfs_acl_cas_init(
    void **                             out_handle,
    const gss_ctx_id_t                  context,
    const char *                        user_id,
    const char *                        resource_id,
    int                                 request_id,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;

    *out_res = globus_gsi_authz_handle_init(
        &cas_handle,
        resource_id,
        context,
        globus_gfs_acl_cas_cb,
        (void *) request_id);
    if(*out_res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    *out_handle = cas_handle;
    return GLOBUS_GFS_ACL_WOULD_BLOCK;
/*
globus_callback_register_oneshot(
    NULL,
    NULL,
    tmp_cb,
    request_id);

*out_res = GLOBUS_SUCCESS;
    return GLOBUS_GFS_ACL_WOULD_BLOCK;
*/


  err:
    return GLOBUS_GFS_ACL_COMPLETE;
}

static int
globus_gfs_acl_cas_authorize(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    int                                 request_id,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;

    cas_handle = (globus_gsi_authz_handle_t) out_handle;

    *out_res = globus_gsi_authorize(
        cas_handle,
        action,
        object,
        globus_gfs_acl_cas_cb,
        (void *) request_id);
    if(*out_res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_GFS_ACL_WOULD_BLOCK;

  err:

*out_res = GLOBUS_SUCCESS;

    return GLOBUS_GFS_ACL_COMPLETE;
}


static void
globus_gfs_acl_cas_destroy(
    void *                              out_handle)
{
    globus_gsi_authz_handle_t           cas_handle;

    cas_handle = (globus_gsi_authz_handle_t) out_handle;

//    globus_gsi_authz_handle_destroy(cas_handle, NULL, NULL);
}

globus_gfs_acl_module_t                 globus_gfs_acl_cas_module = 
{
    globus_gfs_acl_cas_init,
    globus_gfs_acl_cas_authorize,
    globus_gfs_acl_cas_destroy
};

