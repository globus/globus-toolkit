/*
 * gsi_socket_voms.c
 *
 * See gsi_socket.h for documentation.
 */

#include "myproxy_common.h"
#include "gsi_socket_priv.h"

static int
GSI_SOCKET_set_error_string(GSI_SOCKET *self,
                            char *buffer)
{
    if (self->error_string) {
        free(self->error_string);
    }
    self->error_string = strdup(buffer);
    return GSI_SOCKET_SUCCESS;
}

static int
add_fqan(char ***fqans, const char *fqan)
{
   int current_len;
   char **new_fqans;

   if (fqans==NULL) {
      return GSI_SOCKET_ERROR;
   }


   current_len = 0;
   if (*fqans != NULL) {
      while ((*fqans)[current_len] != NULL)
	 current_len++;
   }

   new_fqans = realloc(*fqans, (current_len + 2) * sizeof(*new_fqans));
   if (new_fqans == NULL) {
      return GSI_SOCKET_ERROR;
   }

   new_fqans[current_len] = strdup(fqan);
   new_fqans[current_len+1] = NULL;
   *fqans = new_fqans;

   return 0;
}

static gss_OID_desc gss_ext_x509_cert_chain_oid_desc =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 
static gss_OID_desc * gss_ext_x509_cert_chain_oid =
                &gss_ext_x509_cert_chain_oid_desc;

static int
GSI_SOCKET_get_peer_cert_chain(GSI_SOCKET *self,
                               X509 **cert,
                               STACK_OF(X509) **cert_chain)
{
    OM_uint32 major_status = 0;
    OM_uint32 minor_status = 0;
    gss_buffer_set_t buffer_set = NULL;
    int i;

    *cert = NULL;
    *cert_chain = NULL;

    major_status = gss_inquire_sec_context_by_oid(&minor_status,
                                                  self->gss_context,
                                                  gss_ext_x509_cert_chain_oid,
                                                  &buffer_set);
    if (major_status != GSS_S_COMPLETE) {
        GSI_SOCKET_set_error_string(self, "gsi_inquire_sec_context_by_oid() failed in GSI_SOCKET_get_peer_cert_chain()");
        return GSI_SOCKET_ERROR;
    }

    *cert_chain = sk_X509_new_null();

    for (i = 0; i < buffer_set->count; i++) {
        const unsigned char *p;
        X509 *c;
                    
        p = buffer_set->elements[i].value;
        c = d2i_X509(NULL, &p, buffer_set->elements[i].length);

        if (i == 0) {
            *cert = c;
        } else {
            if (sk_X509_insert(*cert_chain,
                               c, sk_X509_num(*cert_chain)) == SSL_ERROR) {
                GSI_SOCKET_set_error_string(self, "sk_X509_insert() failed in GSI_SOCKET_get_peer_cert_chain()");
                gss_release_buffer_set(&minor_status, &buffer_set);
                return GSI_SOCKET_ERROR;
            }
        }
    }

    gss_release_buffer_set(&minor_status, &buffer_set);
    return GSI_SOCKET_SUCCESS;
}

int
GSI_SOCKET_get_peer_fqans(GSI_SOCKET *self, char ***fqans)
{
   char **local_fqans = NULL;
   int ret;
   struct vomsdata *voms_data = NULL;
   struct voms **voms_cert  = NULL;
   char **fqan = NULL;
   int voms_err;
   char *err_msg, *err_str;
   X509 *cert = NULL;
   STACK_OF(X509) *cert_chain = NULL;

   voms_data = VOMS_Init(NULL, NULL);
   if (voms_data == NULL) {
      GSI_SOCKET_set_error_string(self,
                    "Failed to read VOMS attributes, VOMS_Init() failed");
      return GSI_SOCKET_ERROR;
   }

   if (GSI_SOCKET_get_peer_cert_chain(self,
                                      &cert,
                                      &cert_chain) != GSI_SOCKET_SUCCESS) {
      GSI_SOCKET_set_error_string(self, "Failed to read VOMS attributes, GSI_SOCKET_get_peer_cert_chain( failed");
      return GSI_SOCKET_ERROR;
   }

   ret = VOMS_Retrieve(cert,
                       cert_chain,
                       RECURSE_CHAIN, voms_data, &voms_err);
   if (ret == 0) {
      if (voms_err == VERR_NOEXT) {
	 /* No VOMS extensions present, return silently */
	 ret = 0;
	 goto end;
      } else {
         err_msg = VOMS_ErrorMessage(voms_data, voms_err, NULL, 0);
         err_str = (char *)malloc(strlen(err_msg)+50);
         snprintf(err_str, strlen(err_msg)+50,
                  "Failed to read VOMS attributes: %s", err_msg);
         GSI_SOCKET_set_error_string(self, err_str);
	 free(err_msg);
     free(err_str);
	 ret = GSI_SOCKET_ERROR;
	 goto end;
      }
   }

   for (voms_cert = voms_data->data; voms_cert && *voms_cert; voms_cert++) {
      for (fqan = (*voms_cert)->fqan; fqan && *fqan; fqan++) {
	 add_fqan(&local_fqans, *fqan);
      }
   }

   *fqans = local_fqans;
   ret = 0;

end:
   if (voms_data)
      VOMS_Destroy(voms_data);
   if (cert)
       X509_free(cert);
   if (cert_chain)
       sk_X509_pop_free(cert_chain, X509_free);

   return ret;
}
