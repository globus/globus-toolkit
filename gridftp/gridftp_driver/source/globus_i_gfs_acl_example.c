#include "globus_gridftp_server.h"

#define EXAMPLE_ACL_NAME "globus_gfs_acl_example"

static
int
globus_gfs_acl_example_init(
    void **                             out_handle,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    printf("globus_gfs_acl_example_init\n");

    return GLOBUS_GFS_ACL_COMPLETE;
}

static
int
globus_gfs_acl_example_authorize(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    printf("globus_gfs_acl_example_authorize\n");

    return GLOBUS_GFS_ACL_COMPLETE;
}

static
int
globus_gfs_acl_example_audit(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    const char *                        message)
{
    return GLOBUS_GFS_ACL_COMPLETE;
}

static
void
globus_gfs_acl_example_destroy(
    void *                              out_handle)
{
}

static
int
gfs_example_acl_activate();

static
int
gfs_example_acl_deactivate();


GlobusExtensionDefineModule(EXAMPLE_ACL_NAME) =
{
    EXAMPLE_ACL_NAME,
    gfs_example_acl_activate,
    gfs_example_acl_deactivate,
    NULL,
    NULL,
    NULL
};

globus_gfs_acl_module_t                 globus_gfs_acl_example_module = 
{
    globus_gfs_acl_example_init,
    globus_gfs_acl_example_authorize,
    globus_gfs_acl_example_destroy,
    globus_gfs_acl_example_audit
};

static
int
gfs_example_acl_activate()
{
    int                                 rc;

    rc = globus_extension_registry_add(
        GLOBUS_GFS_ACL_REGISTRY,
        EXAMPLE_ACL_NAME,
        GlobusExtensionMyModule(EXAMPLE_ACL_NAME),
        &globus_gfs_acl_example_module);

    return rc;
}

static
int
gfs_example_acl_deactivate()
{
    globus_extension_registry_remove(
        GLOBUS_GFS_ACL_REGISTRY, EXAMPLE_ACL_NAME);

    return 0;
}




