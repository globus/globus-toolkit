
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "globus_i_gsi_cert_utils.h"
#include "version.h"

int globus_i_gsi_cert_utils_debug_level = 0;

static int globus_l_gsi_cert_utils_activate(void);
static int globus_l_gsi_cert_utils_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_cert_utils_module =
{
    "globus_cert_utils",
    globus_l_gsi_cert_utils_activate,
    globus_l_gsi_cert_utils_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_cert_utils_activate(void)
{
    int                                 result;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_cert_utils_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSI_CERT_UTILS_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_cert_utils_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_cert_utils_debug_level < 0)
        {
            globus_i_gsi_cert_utils_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_CERT_UTILS_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_cert_utils_debug_fstream = fopen(tmp_string, "w");
        if(globus_i_gsi_cert_utils_debug_fstream == NULL)
        {
            result = GLOBUS_NULL;
            goto exit;
        }
    }
    else
    {
        /* if the env. var. isn't set, use stderr */
        globus_i_gsi_cert_utils_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    result = globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

 exit:

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return result;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_cert_utils_deactivate(void)
{
    int                                 result;
    static char *                       _function_name_ =
        "globus_l_gsi_cert_utils_deactivate";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    result = globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;

    fclose(globus_i_gsi_cert_utils_debug_fstream);
    return result;
}
/* globus_l_gsi_cert_utils_deactivate() */

globus_result_t
globus_gsi_cert_utils_make_time(
    ASN1_UTCTIME *                      ctm,
    time_t *                            newtime)
{
    char *                              str;
    time_t                              offset;
    char                                buff1[24];
    char *                              p;
    int                                 i;
    struct tm                           tm;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cert_utils_make_time";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    p = buff1;
    i = ctm->length;
    str = (char *)ctm->data;
    if ((i < 11) || (i > 17))
    {
        *newtime = 0;
    }
    memcpy(p,str,10);
    p += 10;
    str += 10;

    if ((*str == 'Z') || (*str == '-') || (*str == '+'))
    {
        *(p++)='0'; *(p++)='0';
    }
    else
    {
        *(p++)= *(str++); *(p++)= *(str++);
    }
    *(p++)='Z';
    *(p++)='\0';

    if (*str == 'Z')
    {
        offset=0;
    }
    else
    {
        if ((*str != '+') && (str[5] != '-'))
        {
            *newtime = 0;
        }
        offset=((str[1]-'0')*10+(str[2]-'0'))*60;
        offset+=(str[3]-'0')*10+(str[4]-'0');
        if (*str == '-')
        {
            offset=-offset;
        }
    }

    tm.tm_isdst = 0;
    tm.tm_year = (buff1[0]-'0')*10+(buff1[1]-'0');

    if (tm.tm_year < 70)
    {
        tm.tm_year+=100;
    }
        
    tm.tm_mon   = (buff1[2]-'0')*10+(buff1[3]-'0')-1;
    tm.tm_mday  = (buff1[4]-'0')*10+(buff1[5]-'0');
    tm.tm_hour  = (buff1[6]-'0')*10+(buff1[7]-'0');
    tm.tm_min   = (buff1[8]-'0')*10+(buff1[9]-'0');
    tm.tm_sec   = (buff1[10]-'0')*10+(buff1[11]-'0');

    /*
     * mktime assumes local time, so subtract off
     * timezone, which is seconds off of GMT. first
     * we need to initialize it with tzset() however.
     */

    tzset();

#if defined(HAVE_TIME_T_TIMEZONE)
    *newtime = (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
    *newtime = (mktime(&tm) + offset*60*60 - _timezone);
#else
    *newtime = (mktime(&tm) + offset*60*60);
#endif

    result = GLOBUS_SUCCESS;
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_gsi_cert_utils_check_proxy_name(
    X509 *                                    cert,
    globus_gsi_cert_utils_proxy_type_t *      type)
{
    X509_NAME *                         subject;
    X509_NAME *                         name;
    X509_NAME_ENTRY *                   ne;
    ASN1_STRING *                       data;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_i_gsi_cred_X509_check_proxy_name";
    
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    *type = GLOBUS_NOT_PROXY;
    subject = X509_get_subject_name(cert);
    if((ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1))
       == NULL)
    {
        GLOBUS_GSI_CERT_UTILS_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CERT_UTILS_ERROR_GETTING_NAME_ENTRY_OF_SUBJECT,
            ("Can't get X509 name entry from subject"));
        goto exit;
    }

    if (!OBJ_cmp(ne->object, OBJ_nid2obj(NID_commonName)))
    {
        /* the name entry is of the type: common name */
        data = X509_NAME_ENTRY_get_data(ne);
        if (data->length == 5 && !memcmp(data->data,"proxy",5))
        {
            *type = GLOBUS_FULL_PROXY;
        }
        else if (data->length == 13 && !memcmp(data->data,"limited proxy",13))
        {
            *type = GLOBUS_LIMITED_PROXY;
        }
        else if (data->length == 16 && 
                 !memcmp(data->data,"restricted proxy",16))
        {
	    *type = GLOBUS_RESTRICTED_PROXY;
        } 

        if(*type != GLOBUS_NOT_PROXY)
        {
            /* its some kind of proxy - now we check if the subject
             * matches the signer, by adding the proxy name entry CN
             * to the signer's subject
             */

            GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF(
                2, (globus_i_gsi_cert_utils_debug_fstream, 
                    "Subject is %s\n", data->data));

            if((name = X509_NAME_dup(
                       X509_get_issuer_name(cert))) == NULL)
            {
                GLOBUS_GSI_CERT_UTILS_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_COPYING_SUBJECT,
                    ("Error copying X509_NAME struct"));
                goto exit;
            }
            
            if((ne = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
                                                   V_ASN1_APP_CHOOSE,
                                                   data->data, -1)) == NULL)
            {
                GLOBUS_GSI_CERT_UTILS_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_GETTING_CN_ENTRY,
                    ("Error creating X509 name entry of: %s", data->data));
                goto free_name;
            }
            
            if(!X509_NAME_add_entry(name, ne, X509_NAME_entry_count(name),0))
            {
                ne = NULL;
                GLOBUS_GSI_CERT_UTILS_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_ADDING_CN_TO_SUBJECT,
                    ("Error adding name entry with value: %s, to subject",
                     data->data));
                goto free_name_entry;
            }
            
            if (X509_NAME_cmp(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                *type = GLOBUS_ERROR_PROXY;
            }
        }
    }

    result = GLOBUS_SUCCESS;
    
 free_name_entry:

    if(ne != NULL)
    {
        X509_NAME_ENTRY_free(ne);
    }

 free_name:

    if(name != NULL)
    {
        X509_NAME_free(name);
    }

 exit:

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return result;
}
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char *
globus_i_gsi_cert_utils_create_string(
    const char *                        format,
    ...)
{
    va_list                             ap;
    char *                              new_string;
    static char *                       _function_name_ =
        "globus_i_gsi_cert_utils_create_string";
    
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    globus_libc_lock();
    
    va_start(ap, format);

    new_string = globus_i_gsi_cert_utils_v_create_string(format, ap);

    va_end(ap);

    globus_libc_unlock();

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return new_string;
}

char *
globus_i_gsi_cert_utils_v_create_string(
    const char *                        format,
    va_list                             ap)
{
    int                                 length;
    int                                 len = 128;
    char *                              new_string = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_cert_utils_v_create_string";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;
    if((new_string = globus_malloc(len)) == NULL)
    {
        return NULL;
    }

    while(1)
    {
        length = vsnprintf(new_string, len, format, ap);
        if(length > -1 && length < len)
        {
            break;
        }

        if(length > -1)
        {
            len = length + 1;
        }
        else
        {
            len *= 2;
        }

        if((new_string = realloc(new_string, len)) == NULL)
        {
            return NULL;
        }
    }
    
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return new_string;
}

#endif
