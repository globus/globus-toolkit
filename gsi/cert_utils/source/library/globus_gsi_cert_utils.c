
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "globus_i_gsi_cert_utils.h"
#include "version.h"
#include "config.h"
#include <ctype.h>

int                               globus_i_gsi_cert_utils_debug_level = 0;
FILE *                            globus_i_gsi_cert_utils_debug_fstream = NULL;

static int globus_l_gsi_cert_utils_activate(void);
static int globus_l_gsi_cert_utils_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_gsi_cert_utils_module =
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

    if(globus_i_gsi_cert_utils_debug_fstream != stderr)
    {
        fclose(globus_i_gsi_cert_utils_debug_fstream);
    }

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

/**
 * @name Get X509 Name
 * @ingroup globus_gsi_cert_utils
 */
/* @{ */
/**
 * Get the X509_NAME from a subject string.
 * OpenSSL doesn't provide this function, primarily because
 * its dangerous to use.  If you are getting an X509_NAME from
 * just a string, its impossible to verify its integrity.
 *
 * @param subject_string
 *        The subject in the format: "/O=Grid/OU=..."
 * @param length
 *        The length of the subject string
 * @param x509_name
 *        The resulting X509_NAME object
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_cert_utils_get_x509_name(
    char *                              subject_string,
    int                                 length,
    X509_NAME *                         x509_name)
{
    globus_result_t                     result;
    char *                              local_copy = NULL;
    char *                              name_entry_str = NULL;
    char *                              name_value_str = NULL;
    char *                              index = NULL;
    char *                              index2 = NULL;
    char *                              uc_index = NULL;
    X509_NAME_ENTRY *                   x509_name_entry = NULL;
    int                                 nid;
    int                                 res;
    static char *                       _function_name_ =
        "globus_gsi_cert_utils_get_x509_name";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    local_copy = malloc(length + 1);
    if(local_copy == NULL)
    {
        GLOBUS_GSI_CERT_UTILS_MALLOC_ERROR(result);
        goto exit;
    }

    memcpy(local_copy, subject_string, length);
    local_copy[length] = '\0';

    index = local_copy;
    if (*index == '/')
    {
        /* skip first / */
        name_entry_str = index + 1;                 
        while ((name_entry_str != NULL) && (*name_entry_str != '\0'))
        {
            /* point at name = */
            index = strchr(name_entry_str,'=');
            if (index == NULL)
            {
                GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT,
                    ("The subject_string cannot be convert to an "
                     "X509_NAME, unexpected format"));
                goto exit;
            }
            /* terminate name string */
            *index = '\0';           

            name_value_str = index + 1;

            /* find next =, then last / */
            index = strchr(name_value_str, '=');   
            if (index != NULL)
            {
                /* for now set = to \0 */
                *index = '\0';	
                    
                /* find last / in  value */
                index2 = strrchr(name_value_str, '/');   

                /* reset = */
                *index = '=';	

                if (index2 != NULL)
                {
                    /* terminate value string */
                    *index2 = '\0'; 
                }
            }

            nid = OBJ_txt2nid(name_entry_str);
            
            if (nid == NID_undef)
            {
                /* 
                 * not found, lets try upper case instead
                 */
                uc_index = name_entry_str;
                while (*uc_index != '\0')
                {
                    *uc_index = toupper(*uc_index);
                    uc_index++;
                }

                nid = OBJ_txt2nid(name_entry_str);
                if (nid == NID_undef)
                {
                    GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(
                        result,
                        GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT,
                        ("The name entry: %s is not "
                         "recognized as a valid OID", name_entry_str));
                    goto exit;
                }
            }

            x509_name_entry = X509_NAME_ENTRY_create_by_NID(
                &x509_name_entry,
                nid,
                V_ASN1_APP_CHOOSE, 
                (unsigned char *) name_value_str,
                -1);

            if (x509_name_entry == NULL)
            {
                GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT,
                    ("Error with name entry: %s, with a value of: %s",
                     name_entry_str, name_value_str));
                goto exit;
            }
            
            res = X509_NAME_add_entry(x509_name, x509_name_entry, 
                                      X509_NAME_entry_count(x509_name), 0);
            if (!res)
            {
                GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT,
                    ("Couldn't add name entry to  X509_NAME object"));
                goto exit;
            }
            
            name_entry_str = index2 + 1;
        }
    }
    else
    {
        GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(
            result,
            GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT,
            ("The X509 name doesn't start with a /"));
        goto exit;
    }

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_PRINT(2, "ORIGINAL SUBJECT STRING: ");
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_FNPRINTF(2, (length, subject_string));
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF(
        2, (globus_i_gsi_cert_utils_debug_fstream,
            "\nGENERATED X509_NAME STRING: %s\n",
            X509_NAME_oneline(x509_name, NULL, 0)));

 exit:

    if(x509_name_entry != NULL)
    {
        X509_NAME_ENTRY_free(x509_name_entry);
    }

    if(local_copy != NULL)
    {
        globus_libc_free(local_copy);
    }

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return result;
}
/* @} */

char *
globus_gsi_cert_utils_create_string(
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

    new_string = globus_gsi_cert_utils_v_create_string(format, ap);

    va_end(ap);

    globus_libc_unlock();

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return new_string;
}

char *
globus_gsi_cert_utils_create_nstring(
    int                                 length,
    const char *                        format,
    ...)
{
    va_list                             ap;
    char *                              new_string;
    static char *                       _function_name_ =
        "globus_i_gsi_cert_utils_create_nstring";
    
    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;

    globus_libc_lock();
    
    va_start(ap, format);

    new_string = globus_gsi_cert_utils_v_create_nstring(length, format, ap);

    va_end(ap);

    globus_libc_unlock();

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return new_string;
}

char *
globus_gsi_cert_utils_v_create_string(
    const char *                        format,
    va_list                             ap)
{
    int                                 length;
    int                                 len = 128;
    char *                              new_string = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_cert_utils_v_create_string";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;
    if((new_string = malloc(len)) == NULL)
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

char *
globus_gsi_cert_utils_v_create_nstring(
    int                                 length,
    const char *                        format,
    va_list                             ap)
{
    char *                              new_string = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_cert_utils_v_create_string";

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER;
    if((new_string = malloc(length + 1)) == NULL)
    {
        return NULL;
    }

    length = vsnprintf(new_string, length + 1, format, ap);

    GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT;
    return new_string;
}
