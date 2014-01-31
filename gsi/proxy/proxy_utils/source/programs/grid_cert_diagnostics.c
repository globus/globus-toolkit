/*
 * Copyright 1999-2010 University of Chicago
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

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "globus_gss_assist.h"
#include "openssl/bn.h"
#ifdef _WIN32
#include <getopt.h>
#else
#include <regex.h>
#endif

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
    char                                *location = NULL;
    char                                *cert_dir = NULL;
    char                                *cert = NULL;
    char                                *key = NULL;
    char                                *gridmap = NULL;
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
    char *                              local_user = NULL;
    int                                 ch;
    globus_bool_t                       do_ntp_check = GLOBUS_FALSE;
    FILE *                              ntpdate;
    char                                ntpbuffer[256];
    char *                              cert_to_check = NULL;
    globus_module_descriptor_t *        modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_SYSCONFIG_MODULE,
        GLOBUS_GSI_CREDENTIAL_MODULE,
        GLOBUS_GSI_CALLBACK_MODULE,
        NULL
    };

    while ((ch = getopt(argc, argv, "phc:n")) != -1)
    {
        switch (ch)
        {
        case 'p':
            personal = GLOBUS_TRUE;
            break;
        case 'c':
            cert_to_check = strdup(optarg);
            break;
        case 'n':
            do_ntp_check = GLOBUS_TRUE;
            break;
        default:
        case 'h':
            printf("Usage: %s [-p] [-h] [-c CERT] [-n]\n"
                   " OPTIONS:\n"
                   "   -p                         "
                   "Perform checks on use certificates [default: no]\n"
                   "   -h                         "
                   "Print this help message\n"
                   "   -c CERT                    "
                   "Check the validity of the certificate located in the file CERT, or standard input, if CERT is '-'\n"
#ifndef TARGET_ARCH_WIN32
                   "   -n                         "
                   "Enable NTP check for time synchronization\n"
#endif
                   , argv[0]);
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

    printf("Checking if HOME is set... ");
    home = getenv("HOME");
    printf("%s\n", home ? home : "no");
    printf("Checking if GLOBUS_LOCATION is set... ");
    location = getenv("GLOBUS_LOCATION");
    printf("%s\n", location ? location : "no");
    if (!location)
    {
        printf("Checking for default GLOBUS_LOCATION... ");
        globus_location(&location);
        printf("%s\n", location ? location : "no");
    }

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
    printf("Checking if GRIDMAP is set... ");
    gridmap = getenv("GRIDMAP");
    printf("%s\n", gridmap ? gridmap : "no");


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

    printf("Checking for default gridmap location... ");
    result = GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap);
    if (result != GLOBUS_SUCCESS)
    {
        printf("failed\n%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
    }
    else
    {
        printf("%s\n", gridmap);
    }

    printf("Checking if default gridmap exists... ");
    result = GLOBUS_GSI_SYSCONFIG_FILE_EXISTS(gridmap);
    if (result != GLOBUS_SUCCESS)
    {
        printf("failed\n%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
    }
    else
    {
        printf("yes\n");
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
    result = globus_gsi_callback_set_check_policy_for_self_signed_certs(callback_data, GLOBUS_FALSE);
    if (result != GLOBUS_SUCCESS)
    {
        printf("Internal error: setting check self-signed policy\n%s\n",
                indent_string(
                    globus_error_print_friendly(globus_error_peek(result))));
        goto out;
    }

#   ifndef TARGET_ARCH_WIN32
    if (do_ntp_check)
    {
        printf("\nChecking clock synchronization\n"
                "=============================\n");
        printf("Running ntpdate -u -q 0.pool.ntp.org... ");
        ntpdate = popen("ntpdate -u -q 0.pool.ntp.org", "r");
        if (ntpdate == NULL)
        {
            printf("failed\n");
        }
        else
        {
            regex_t offset_regex;
            globus_bool_t matched_good = GLOBUS_FALSE;
            double offset;
            double matched_good_offset;

            if (regcomp(&offset_regex, "offset ([+.0-9-]+)", REG_EXTENDED) < 0)
            {
                printf("failed\n");
                goto close_ntpdate;
            }
            while (fgets(ntpbuffer, sizeof(ntpbuffer)-1, ntpdate) != NULL)
            {
                regmatch_t offset_match[2];

                if (regexec(&offset_regex,
                            ntpbuffer,
                            sizeof(offset_match)/sizeof(offset_match[0]),
                            offset_match,
                            0) != REG_NOMATCH)
                {
                    offset = strtod(&ntpbuffer[offset_match[1].rm_so], NULL);

                    if (offset < 1.0 && offset > -1.0)
                    {
                        matched_good = GLOBUS_TRUE;
                        matched_good_offset = offset;
                    }
                    else
                    {
                        printf("WARNING: clock skew %f seconds\n", offset);
                        goto free_regex;
                    }
                }
            }
    free_regex:
            regfree(&offset_regex);
    close_ntpdate:
            rc = pclose(ntpdate);
            if (rc != 0)
            {
                printf("WARNING: ntpdate failed\n");
            }
            else if (matched_good)
            {
                printf("ok (clock skew %f second)\n", offset);
            }
            else if (offset > 1 || offset < -1)
            {
                printf("ERROR: ntp skew greater than 1 second\n");
                goto out;
            }
            else
            {
                printf("WARNING: unable to parse ntpdate output\n");
            }
        }
    }
#   endif

    if (personal)
    {
        printf("\nChecking Default Credentials\n"
               "============================\n");
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

        printf("Checking if subject is in gridmap... ");
        rc = globus_gss_assist_gridmap(subject_name, &local_user);
        if (rc != 0)
        {
            printf("error parsing gridmap %s\n", gridmap);
        }
        else if (local_user != NULL)
        {
            printf("%s\n", local_user);
        }
        else
        {
            printf("no\n");
        }

    }
    if (cert_to_check)
    {
        printf("\nChecking Certificate\n"
               "====================\n");
        if (strcmp(cert_to_check, "-") == 0)
        {
            BIO * cert_bio;
            printf("Checking cert from stdin... ");

            if((cert_bio = BIO_new_fp(stdin, BIO_NOCLOSE)) == NULL)
            {
                printf("failed\nError opening BIO to read from stdin\n");
                goto out;
            }

            result = globus_gsi_cred_read_cert_bio(handle, cert_bio);
            if (result != GLOBUS_SUCCESS)
            {
                printf("failed\n%s\n",
                        indent_string(
                            globus_error_print_friendly(
                                    globus_error_peek(result))));
                BIO_free(cert_bio);
                goto out;
            }
            else
            {
                printf("ok\n");
            }

            BIO_free(cert_bio);
        }
        else
        {
            printf("Checking cert at %s... ", cert_to_check);

            result = globus_gsi_cred_read_cert(handle, cert_to_check);

            if (result != GLOBUS_SUCCESS)
            {
                printf("failed\n%s\n",
                        indent_string(
                            globus_error_print_friendly(
                                    globus_error_peek(result))));
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
        unsigned long hash;
        X509_NAME * x509_subject_name;
        char * signing_policy_filename;
        char hash_string[16];

        printf("Checking CA file %s... ", ca_cert_file);
              
        result = globus_gsi_cred_read_cert(handle, ca_cert_file);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }
        printf("ok\nChecking that certificate hash matches filename... ");
        result = globus_gsi_cred_get_X509_subject_name(
            handle, &x509_subject_name);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }

        hash = X509_NAME_hash(x509_subject_name);
        sprintf(hash_string, "%08lx.0", hash);

        if (strstr(ca_cert_file, hash_string) == 0)
        {
            printf("failed\n    CA hash '%s' does not match CA filename\n", hash_string); 
            continue;
        }
        printf("ok\nChecking CA certificate name for %s...", hash_string);
        result = globus_gsi_cred_get_subject_name(handle, &ca_subject_name);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }

        printf("ok (%s)\nChecking if signing policy exists for %s... ", ca_subject_name, hash_string);
        result = GLOBUS_GSI_SYSCONFIG_GET_SIGNING_POLICY_FILENAME(
                x509_subject_name,
                cert_dir,
                &signing_policy_filename);
        if (result != GLOBUS_SUCCESS)
        {
            printf("failed\n%s\n",
                    indent_string(
                        globus_error_print_friendly(globus_error_peek(result))));
            continue;
        }
        free(signing_policy_filename);

        printf("ok\nVerifying certificate chain for %s... ",
               hash_string);
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
