/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "globus_error_openssl.h"
#include "openssl/err.h"
#include "openssl/asn1.h"
#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "version.h"

#define GLOBUS_GSI_OPENSSL_ERROR_TEST_MODULE \
        (&globus_i_gsi_openssl_error_test_module)

static int 
globus_l_openssl_error_test_activate(void);

static int 
globus_l_openssl_error_test_deactivate(void);

globus_module_descriptor_t              
                                    globus_i_gsi_openssl_error_test_module =
{
    "globus_openssl_error_test",
    globus_l_openssl_error_test_activate,
    globus_l_openssl_error_test_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static int
globus_l_openssl_error_test_activate(void)
{
    globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    return GLOBUS_SUCCESS;
}

static int
globus_l_openssl_error_test_deactivate(void)
{
    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    return GLOBUS_SUCCESS;
}


int main(int argc, char * argv[])
{

    globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_TEST_MODULE);

#if defined(ASN1_F_X509_NAME_NEW)
    ERR_put_error(ERR_LIB_ASN1, ASN1_F_X509_NAME_NEW, ASN1_R_TOO_LONG,
                  __FILE__, __LINE__);
#elif defined(ASN1_F_X509_NAME_EX_NEW)
    ERR_put_error(ERR_LIB_ASN1, ASN1_F_X509_NAME_EX_NEW, ASN1_R_TOO_LONG,
                  __FILE__, __LINE__);
#endif
    
    ERR_put_error(ERR_LIB_BIO, BIO_F_BIO_WRITE, BIO_R_BROKEN_PIPE,
                  __FILE__, __LINE__);

    ERR_put_error(ERR_LIB_ASN1, ASN1_F_I2D_RSA_PUBKEY, 
                  ASN1_R_DECODE_ERROR, __FILE__, __LINE__);

    {
        globus_object_t *               error1;
        
        error1 = globus_error_wrap_openssl_error(
            GLOBUS_GSI_OPENSSL_ERROR_TEST_MODULE,
            (const int) 42,
            NULL,
            NULL,
            0,
            "Test Error: %s:%d",
            "blah",
            42);
        
        fprintf(stdout, "%s\n", globus_object_printable_to_string(error1));

        while((error1 = globus_error_base_get_cause(error1)) != NULL)
        {
            
            fprintf(stdout, "%s\n", globus_object_printable_to_string(error1));
        }

        globus_object_free(error1);
    }

    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_TEST_MODULE);

    return 0;
}
