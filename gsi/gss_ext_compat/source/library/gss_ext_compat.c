#include "globus_gss_ext_compat.h"

OM_uint32
GSS_CALLCONV gss_release_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t                    restriction_buffers)
{ return GSS_S_EXT_COMPAT; }


OM_uint32
GSS_CALLCONV gss_import_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        output_token,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{ return GSS_S_EXT_COMPAT; }


OM_uint32
GSS_CALLCONV gss_export_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        output_token)
{ return GSS_S_EXT_COMPAT; }

OM_uint32
GSS_CALLCONV gss_init_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           time_req,
    gss_buffer_t                        output_token)
{ return GSS_S_EXT_COMPAT; }

OM_uint32
GSS_CALLCONV gss_accept_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec,
    gss_cred_id_t *                     cred_handle,
    gss_OID *                           desired_mech,
    gss_buffer_t                        output_token)
{ return GSS_S_EXT_COMPAT; }


OM_uint32
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       oid,
    const gss_buffer_set_t              buf_set)
{ return GSS_S_EXT_COMPAT; }


OM_uint32
GSS_CALLCONV gss_inquire_cred_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       oid,
    const gss_buffer_set_t              buf)
{ return GSS_S_EXT_COMPAT; }


OM_uint32
GSS_CALLCONV gss_set_sec_context_option(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle,
    const gss_OID                       option,
    const gss_buffer_t                  value)
{ return GSS_S_EXT_COMPAT; }
