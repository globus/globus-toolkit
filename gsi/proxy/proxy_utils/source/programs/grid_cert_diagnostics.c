#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "openssl/bn.h"

char *
indent_string(const char * str)
{
    char * new_line;
    char * old_line;
    char * output;
    int i=1;

    for (new_line = (char *) str; new_line != NULL; new_line = strchr(new_line+1, '\n'))
    {
        i++;
    }

    output = malloc(strlen(str) + (i*4) + 1);
    i = 0;

    for (new_line = strchr(str, '\n'), old_line = (char *) str;
         new_line != NULL;
         old_line = new_line+1, new_line = strchr(new_line+1, '\n'))
    {
        memcpy(output+i, "    ", 4);
        i += 4;
        memcpy(output+i, old_line, new_line - old_line);
        i += new_line - old_line;
        output[i++] = '\n';
    }
    output[i] = 0;

    return output;
}

int main(int argc, char * argv[])
{
    int                                 rc;
    globus_module_descriptor_t *        failed_module;
    globus_result_t                     result;
    char                                *cert_dir = NULL;
    char                                *cert = NULL;
    char                                *key = NULL;
    char                                *p;
    char                                *subject_name;
    char                                *home;
    globus_gsi_cred_handle_t            handle;
    X509 *                              x509_cert;
    EVP_PKEY *                          pubkey = NULL;
    EVP_PKEY *                          privkey = NULL;
    globus_fifo_t                       cert_list = NULL;
    globus_gsi_callback_data_t          callback_data;
    globus_bool_t                       personal = GLOBUS_FALSE;
    int                                 ch;
    globus_module_descriptor_t *        modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_SYSCONFIG_MODULE,
        GLOBUS_GSI_CREDENTIAL_MODULE,
        GLOBUS_GSI_CALLBACK_MODULE,
        NULL
    };

    while ((ch = getopt(argc, argv, "ph")) != -1)
    {
        switch (ch)
        {
        case 'p':
            personal = GLOBUS_TRUE;
            break;
        default:
        case 'h':
            printf("Usage: %s [-p] [-h]\n"
                   " OPTIONS:\n"
                   "   -p                         "
                   "Perform checks on use certificates [default: no]\n"
                   "   -h                         "
                   "Print this help message\n", argv[0]);
            exit(1);
        }
    }


    rc = globus_module_activate_array(modules, &failed_module);
    if (rc != GLOBUS_SUCCESS)
    {
        printf("Internal error: error activating %s: %d\n",
                failed_module->module_name, rc);
        goto out;
    }

    result = globus_gsi_cred_handle_init(
            &handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        printf("Internal error: initializing credential handle\n");
        goto out;
    }

    printf("Checking Environment Variables\n"
           "==============================\n");
    printf("Checking if X509_CERT_DIR is set... ");
    cert_dir = getenv("X509_CERT_DIR");
    printf("%s\n", cert_dir ? cert_dir : "no");
    printf("Checking if X509_USER_CERT is set... ");
    cert = getenv("X509_USER_CERT");
    printf("%s\n", cert ? cert : "no");
    printf("Checking if X509_USER_KEY is set... ");
    key = getenv("X509_USER_KEY");
    printf("%s\n", key ? key : "no");
    printf("Checking if X509_USER_PROXY is set... ");
    key = getenv("X509_USER_PROXY");
    printf("%s\n", key ? key : "no");

    printf("\nChecking Security Directories\n"
           "=======================\n");
    printf("Determining trusted cert path... ");
    result = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&cert_dir);
    if (result != GLOBUS_SUCCESS)
    {
        printf("failed\n%s",
               indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
        goto out;
    }
    else
    {
        printf("%s\n", cert_dir);
    }

    printf("Checking for cog.properties... ");
    result = GLOBUS_GSI_SYSCONFIG_GET_HOME_DIR(&home);
    if (result == GLOBUS_SUCCESS)
    {
        char * cog_properties_path = globus_common_create_string(
                "%s/.globus/cog.properties",
                home);
        if (cog_properties_path == NULL)
        {
            printf("failed\n");
        }
        else if (access(cog_properties_path, F_OK) == 0)
        {
            printf("found\n"
"    WARNING: If the cog.properties file contains security properties, \n"
"             Java apps will ignore the security paths described in the GSI\n"
"             documentation\n");
        }
        else
        {
            printf("not found\n");
        }
    }
    else
    {
        printf("failed\n%s\n",
               indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
    }

    result = globus_gsi_callback_data_init(&callback_data);
    if (result != GLOBUS_SUCCESS)
    {
        printf("failed\n%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
        goto out;
    }
    result = globus_gsi_callback_set_cert_dir(callback_data, cert_dir);
    if (result != GLOBUS_SUCCESS)
    {
        printf("Internal error: setting cert_dir\n%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
        goto out;
    }

    if (personal)
    {
        printf("\nChecking Default Credentials\n"
               "==============================\n");
        printf("Determining certificate and key file names... ");
        result = GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME(&cert, &key);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s",
                   indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            goto out;
        }
        else
        {
            printf("ok\n");
        }

        if (cert)
        {
            printf("Certificate Path: \"%s\"\n", cert);
        }
        if (key)
        {
            printf("Key Path: \"%s\"\n", key);
        }

        if (!strncmp(cert, "SC:", 3))
        {
            EVP_set_pw_prompt("Enter card pin:");
        }
        else
        {
            EVP_set_pw_prompt("Enter GRID pass phrase for this identity: ");
        }

        if ((p = strrchr(cert, '.')) != NULL && !strcmp(p, ".p12"))
        {
            printf("Reading pkcs12 credentials\n");
            result = globus_gsi_cred_read_pkcs12(handle, cert);
        }
        else
        {
            printf("Reading certificate... ");
            result = globus_gsi_cred_read_cert(handle, cert);
        }

        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            goto out;
        }
        else
        {
            printf("ok\n");
        }

        if ((p = strrchr(key, '.')) == NULL || strcmp(p, ".p12"))
        {
            printf("Reading private key...\n");
            result = globus_gsi_cred_read_key(handle, key, NULL);

            if (result != GLOBUS_SUCCESS)
            {
                globus_object_t * error;

                error = globus_error_peek(result);

                if(globus_error_match_openssl_error(error,
                                            ERR_LIB_PEM,
                                            PEM_F_PEM_DO_HEADER,
                                            PEM_R_BAD_DECRYPT))
                {
                    printf("failed\nUnable to decrypt private key: incorrect passphrase or corrupted file.\n");
                }
                else
                {
                    printf("failed\n%s\n",
                        indent_string(
                            globus_error_print_friendly(globus_error_peek(result))));
                }
                goto out;
            }
            else
            {
                printf("ok\n");
            }
        }

        printf("Checking Certificate Subject... ");
        result = globus_gsi_cred_get_subject_name(handle, &subject_name);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
        }
        else
        {
            printf("\"%s\"\n", subject_name);
        }

        printf("Checking cert... ");
        result = globus_gsi_cred_get_cert(handle, &x509_cert);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
        }
        else
        {
            printf("ok\n");
        }

        printf("Checking key... ");
        result = globus_gsi_cred_get_key(handle, &privkey);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
        }
        else
        {
            printf("ok\n");
        }

        pubkey = X509_PUBKEY_get(X509_get_X509_PUBKEY(x509_cert));
        printf("Checking that certificate contains an RSA key... ");
        if (EVP_PKEY_type(pubkey->type) != EVP_PKEY_RSA)
        {
            printf("failed\nKey type is %d\n",
                   EVP_PKEY_type(pubkey->type));
            goto out;
        }
        else
        {
            printf("ok\n");
        }

        printf("Checking that private key is an RSA key... ");
        if (EVP_PKEY_type(privkey->type) != EVP_PKEY_RSA)
        {
            printf("failed\nPrivate key is %d\n",
                    EVP_PKEY_type(privkey->type));
            goto out;
        }
        else
        {
            printf("ok\n");
        }


        printf("Checking that public and private keys have the same modulus... ");
        if (BN_cmp(pubkey->pkey.rsa->n, privkey->pkey.rsa->n))
        {
            printf("failed\n"
                   "Private key modulus: %s\n"
                   "Public key modulus : %s\n",
                   BN_bn2hex(pubkey->pkey.rsa->n), 
                   BN_bn2hex(privkey->pkey.rsa->n));
            printf("Certificate and and private key don't match");
            goto out;
        }
        else
        {
            printf("ok\n");
        }

        printf("Checking certificate trust chain... ");

        result = globus_gsi_cred_verify_cert_chain(
            handle, callback_data);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
        }
        else
        {
            printf("ok\n");
        }
    }
    rc = globus_fifo_init(&cert_list);
    if (rc != GLOBUS_SUCCESS)
    {
        printf("Internal error: out of memory\n");
        goto out;
    }

    printf("\nChecking trusted certificates...\n"
           "================================\n");
    printf("Getting trusted certificate list...\n");
    result = GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES(cert_dir, &cert_list);
    if (result != GLOBUS_SUCCESS)
    {
        printf("%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
        goto out;
    }
    while (! globus_fifo_empty(&cert_list))
    {
        char * ca_cert_file = globus_fifo_dequeue(&cert_list);
        char * ca_subject_name;

        printf("Checking CA file %s... ", ca_cert_file);
              
        result = globus_gsi_cred_read_cert(handle, ca_cert_file);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }
        result = globus_gsi_cred_get_subject_name(handle, &ca_subject_name);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }

        printf("ok\nVerifying certificate chain for \"%s\"... ",
               ca_cert_file);
        result = globus_gsi_cred_verify_cert_chain(
            handle, callback_data);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }
        printf("ok\n");
    }

out:
    globus_module_deactivate_all();

    return 0;
}
