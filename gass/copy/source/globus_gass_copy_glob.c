
#include <glob.h>
#include <fnmatch.h>
#include "globus_gass_copy.h"
#include "version.h"



/************************************************************
 * glob support
 ***********************************************************/


/*    
todo:
comment and doxygen code

*/


typedef enum
{
    GLOBUS_GASS_COPY_FTP_OP_NLST,
    GLOBUS_GASS_COPY_FTP_OP_MLSD
} globus_l_gass_copy_ftp_op_t;

typedef enum
{
    GLOBUS_GASS_COPY_FTP_LIST_ENTRY_ASSUMED_FILE,
    GLOBUS_GASS_COPY_FTP_LIST_ENTRY_FILE,
    GLOBUS_GASS_COPY_FTP_LIST_ENTRY_DIR,
    GLOBUS_GASS_COPY_FTP_LIST_ENTRY_OTHER
} globus_l_gass_copy_ftp_list_entry_t;
    

typedef struct
{
    globus_mutex_t                     mutex;
    globus_cond_t                      cond;
    globus_result_t                    result;
    int                                callbacks_left;
    globus_fifo_t *                    url_list;
    globus_size_t                      buffer_length;
    char *                             base_url;
    int                                base_url_len;
    char *                             glob_pattern;
    char *                             list_buffer;
    globus_l_gass_copy_ftp_op_t        list_op;
    globus_gass_copy_handle_t *        handle;
    globus_gass_copy_attr_t *          attr;
    globus_hashtable_t                 recurse_hash;
} globus_l_gass_copy_glob_info_t; 

static
globus_result_t
globus_l_gass_copy_glob_expand_file_url(
     const char *                      url, 
     globus_gass_copy_attr_t *         attr, 
     globus_fifo_t *                   url_list);

static
globus_result_t
globus_l_gass_copy_glob_expand_ftp_url(
     globus_gass_copy_handle_t *       handle, 
     const char *                      url, 
     globus_gass_copy_attr_t *         attr, 
     globus_fifo_t *                   url_list);

static
void
globus_l_gass_copy_ftp_client_op_done_callback(
        void *                         user_arg,
        globus_ftp_client_handle_t *   handle,
        globus_object_t *              err);

static
globus_result_t
globus_l_gass_copy_glob_parse_ftp_list(
    globus_l_gass_copy_glob_info_t *   info);
    
static
globus_result_t
globus_l_gass_copy_glob_ftp_list(
    globus_l_gass_copy_glob_info_t *   info);
    

static    
void
globus_l_gass_copy_ftp_client_list_read_callback(
    void *                             user_arg,
    globus_ftp_client_handle_t *       handle,
    globus_object_t *                  err,
    globus_byte_t *                    buffer,
    globus_size_t                      length,
    globus_off_t                       offset,
    globus_bool_t                      eof);

static
globus_result_t
globus_l_gass_copy_mkdir_file(
    char *                              url);
    
static
globus_result_t
globus_l_gass_copy_mkdir_ftp(
    globus_gass_copy_handle_t * handle,
    char * url,
    globus_gass_copy_attr_t * attr);


#define GLOBUS_GASS_COPY_FTP_LIST_BUFFER_SIZE 256*1024



globus_result_t 
globus_gass_copy_glob_expand_url( 
     globus_gass_copy_handle_t *       handle, 
     const char *                      url, 
     globus_gass_copy_attr_t *         attr, 
     globus_fifo_t *                   url_list)
{ 
    static char *   myname = "globus_gass_copy_glob_expand_url";
    globus_result_t                    result;
    int                                retval;
    globus_url_scheme_t                scheme_type;
    char *                             url_copy;
    int                                url_len;
    globus_bool_t                      glob = GLOBUS_TRUE;
    globus_bool_t                      url_needs_free = GLOBUS_FALSE;
    
    retval = globus_url_get_scheme(url, &scheme_type);
    if(retval != 0)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url scheme. "
                "globus_url_get_scheme returned %d",
                myname,
                retval));
        goto error;
    }
            
    url_len = strlen(url);
    /* check if url contains glob characters,
       and append * if it is a directory */
    if(strcspn(url, "[]*?") == url_len)
    {
        url_copy = (char *)
            globus_malloc((url_len + 2) * sizeof(char));
    
        if(url_copy == GLOBUS_NULL)
        {
            result = globus_error_put(
                globus_error_construct_string(
                    GLOBUS_GASS_COPY_MODULE,
                    GLOBUS_NULL,
                    "[%s]: Memory allocation error",
                    myname));
            goto error;
        }
        
        strcpy(url_copy, url);

        if(url_copy[url_len - 1] == '/')
        {        
            url_copy[url_len++] = '*';
            url_copy[url_len] = '\0'; 
            url_needs_free = GLOBUS_TRUE;
        }
        else
        {    
            globus_fifo_enqueue(url_list, url_copy);
            glob = GLOBUS_FALSE;
            result = GLOBUS_SUCCESS;
        }
    }
    else
    {
        url_copy = (char *) url;
    }
    if(glob)
    {
        
        switch (scheme_type)
        {
          case GLOBUS_URL_SCHEME_FTP:
          case GLOBUS_URL_SCHEME_GSIFTP:
            result = globus_l_gass_copy_glob_expand_ftp_url(
                handle,
                url_copy,
                attr,
                url_list);
    
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
            break;
    
          case GLOBUS_URL_SCHEME_FILE:
            result = globus_l_gass_copy_glob_expand_file_url(
                url_copy,
                attr,
                url_list);
    
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
            break;
          
          default:
            result = globus_error_put(
                globus_error_construct_string(
                    GLOBUS_GASS_COPY_MODULE,
                    GLOBUS_NULL,
                    "[%s]: Globbing used with unsupported url scheme.",
                    myname));
            goto error;
            break;    
        }
    }        
    
error:
    if(url_needs_free)
    {
        globus_free(url_copy);
    }

    return result;
}


static
globus_result_t
globus_l_gass_copy_glob_expand_file_url(
    const char *                       url, 
    globus_gass_copy_attr_t *          attr, 
    globus_fifo_t *                    url_list)
{
    static char *   myname = "globus_l_gass_copy_glob_expand_file_url";
    glob_t                             file_list;
    globus_result_t                    result;
    int                                retval;
    int                                file_len;
    globus_url_t                       parsed_url;
    char *                             matched_url;
    int                                i;
    char *                             base_url;
    char *                             p;
    int                                base_url_len;
    struct stat                        stat_buf;
    char *                             dev_inode;
    globus_l_gass_copy_glob_info_t     info;
    
    retval = globus_url_parse_loose(url, &parsed_url);
    
    if(retval != 0 || parsed_url.url_path == GLOBUS_NULL)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url scheme. "
                "globus_url_parse_loose returned %d",
                myname,
                retval));
        goto error_url;
    }    
                
    p = strstr(url, parsed_url.url_path);
    base_url_len = p - url;
    
    base_url = globus_libc_strdup(url);
    base_url[base_url_len] = '\0';
    
    retval = glob(
        parsed_url.url_path,
        GLOB_MARK,
        NULL,
        &file_list);

    if(retval != 0 && retval != GLOB_NOMATCH)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: glob() returned %d",
                myname,
                retval));
        goto error_glob;
    }

    globus_hashtable_init(
        &info.recurse_hash,
        4096,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);


    for(i = 0; i < file_list.gl_pathc; i++)
    {
        file_len = strlen(file_list.gl_pathv[i]);

        retval = stat(file_list.gl_pathv[i], &stat_buf);
        if(retval != 0)
        {
            goto error_stat;
        }
        
        if(S_ISDIR(stat_buf.st_mode))
        {
            dev_inode = globus_malloc(1000 * sizeof(char));
            sprintf(
                dev_inode,
                "%lx-%lx;",
                (unsigned long) stat_buf.st_dev, 
                (unsigned long) stat_buf.st_ino);
            
            retval = globus_hashtable_insert(
                &info.recurse_hash,
                dev_inode,
                dev_inode);
            if(retval != GLOBUS_SUCCESS)
            {
                continue;
            }
        }        
        
        matched_url = (char *) 
            globus_malloc((base_url_len + file_len + 1) * sizeof(char));
         
        if(matched_url == GLOBUS_NULL)
        {
             result = globus_error_put(
                globus_error_construct_string(
                    GLOBUS_GASS_COPY_MODULE,
                    GLOBUS_NULL,
                    "[%s]: Memory allocation error",
                    myname));
            goto error_malloc;
        }
             
        sprintf(matched_url, "%s%s", base_url, file_list.gl_pathv[i]);
        
        globus_fifo_enqueue(url_list, matched_url);        
    }
        
    globfree(&file_list);    
    globus_url_destroy(&parsed_url);
    globus_hashtable_destroy(&info.recurse_hash);

    globus_free(base_url);
    
    return GLOBUS_SUCCESS;    
   
error_malloc:
error_stat:
    globfree(&file_list);
    
error_glob:
    globus_url_destroy(&parsed_url);
    globus_hashtable_destroy(&info.recurse_hash);
    globus_free(matched_url);
    globus_free(base_url);

error_url:

    return result;
}    


static
globus_result_t
globus_l_gass_copy_glob_expand_ftp_url(
    globus_gass_copy_handle_t *        handle, 
    const char *                       url, 
    globus_gass_copy_attr_t *          attr, 
    globus_fifo_t *                    url_list)
{
    static char *   myname = "globus_l_gass_copy_glob_expand_ftp_url";    
    globus_result_t                    result;    
    globus_l_gass_copy_glob_info_t     info;
    globus_ftp_client_tristate_t       feature_response;
    globus_ftp_client_features_t       features;
    


    info.base_url = globus_libc_strdup(url);
    info.glob_pattern = strrchr(info.base_url, '/');
    
    if(info.glob_pattern == GLOBUS_NULL  || *info.glob_pattern == '\0')
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: Bad URL",
                myname));
        goto error_url;
    }

    *(info.glob_pattern++) = '\0';
    
    info.base_url_len = strlen(info.base_url);
    info.list_buffer = GLOBUS_NULL;
    info.buffer_length = 0;
    info.url_list = url_list;
    info.result = GLOBUS_SUCCESS;
    info.handle = handle;
    info.attr = attr;
    
    globus_hashtable_init(
        &info.recurse_hash,
        4096,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
        
    globus_mutex_init(&info.mutex, GLOBUS_NULL);
    globus_cond_init(&info.cond, GLOBUS_NULL);

    result = globus_ftp_client_features_init(&features);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_feat;
    }

    info.callbacks_left = 1;
    result = globus_ftp_client_feat(
                 &handle->ftp_handle,
                 info.base_url,
                 attr->ftp_attr,
                 &features,
                 globus_l_gass_copy_ftp_client_op_done_callback,
                 &info);
     
    if(result != GLOBUS_SUCCESS)
    {
        goto error_feat;
    }
                 
    globus_mutex_lock(&info.mutex);
    while(info.callbacks_left > 0)
    {
        globus_cond_wait(&info.cond, &info.mutex);
    }
    result = info.result;
    globus_mutex_unlock(&info.mutex);
  
    if(result == GLOBUS_SUCCESS)
    {    
        result = globus_ftp_client_is_feature_supported(
                    &features, 
                    &feature_response, 
                    GLOBUS_FTP_CLIENT_FEATURE_MLST);
                    
        globus_ftp_client_features_destroy(&features);
    
        if(result != GLOBUS_SUCCESS)
        {
            goto error_feat;
        }
    }    
    else
    {
        feature_response = GLOBUS_FTP_CLIENT_FALSE;
    }
    
    if(feature_response == GLOBUS_FTP_CLIENT_TRUE)
    {       
        info.list_op = GLOBUS_GASS_COPY_FTP_OP_MLSD;
    }
    else    
    {
        info.list_op = GLOBUS_GASS_COPY_FTP_OP_NLST;
    }

    

    result = globus_l_gass_copy_glob_ftp_list(&info);    
         
    if(result != GLOBUS_SUCCESS)
    {
        goto error_list;
    }

    result = globus_l_gass_copy_glob_parse_ftp_list(&info);   
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_list;
    } 

    if(info.list_buffer != GLOBUS_NULL)
    {        
        globus_free(info.list_buffer);
    }
   
    globus_cond_destroy(&info.cond);
    globus_mutex_destroy(&info.mutex);
    
    globus_hashtable_destroy(&info.recurse_hash);
    
    globus_free(info.base_url);

    return GLOBUS_SUCCESS;


error_list:
error_feat:
    globus_cond_destroy(&info.cond);
    globus_mutex_destroy(&info.mutex);
    
    globus_hashtable_destroy(&info.recurse_hash);

error_url:
    globus_free(info.base_url);

    return result;
}

static
globus_result_t
globus_l_gass_copy_glob_ftp_list(
    globus_l_gass_copy_glob_info_t *    info)
{
    static char *   myname = "globus_l_gass_copy_glob_ftp_list";    

    globus_result_t                     result;
    globus_byte_t *                     read_buffer;
    
    read_buffer = (globus_byte_t *)
        globus_malloc(GLOBUS_GASS_COPY_FTP_LIST_BUFFER_SIZE * 
            sizeof(globus_byte_t));

    if(read_buffer == GLOBUS_NULL)
    {
        result = globus_error_put(
            globus_error_construct_string(
            GLOBUS_GASS_COPY_MODULE,
            GLOBUS_NULL,
            "[%s]: Memory allocation error",
            myname));
        goto error_malloc;
    }        

    
    info->callbacks_left = 2;        
    if(info->list_op == GLOBUS_GASS_COPY_FTP_OP_MLSD)
    {
        result = globus_ftp_client_machine_list(
                     &info->handle->ftp_handle,
                     info->base_url,
                     info->attr->ftp_attr,
                     globus_l_gass_copy_ftp_client_op_done_callback,
                     info);
    }
    else    
    {
        result = globus_ftp_client_list(
                     &info->handle->ftp_handle,
                     info->base_url,
                     info->attr->ftp_attr,
                     globus_l_gass_copy_ftp_client_op_done_callback,
                     info);
    }

    if(result != GLOBUS_SUCCESS)
    {
        goto error_list;
    }

    result = globus_ftp_client_register_read(
                 &info->handle->ftp_handle,
                 read_buffer,
                 GLOBUS_GASS_COPY_FTP_LIST_BUFFER_SIZE,
                 globus_l_gass_copy_ftp_client_list_read_callback,
                 info);

    if(result != GLOBUS_SUCCESS)
    {
        globus_ftp_client_abort(&info->handle->ftp_handle);
        
        globus_mutex_lock(&info->mutex);
        info->callbacks_left--;
        while(info->callbacks_left > 0)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
        globus_mutex_unlock(&info->mutex);
        
        goto error_read;    
    }

    globus_mutex_lock(&info->mutex);
    while(info->callbacks_left > 0)
    {
        globus_cond_wait(&info->cond, &info->mutex);
    }
    result = info->result;
    globus_mutex_unlock(&info->mutex);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_read;
    }

    if(read_buffer != (globus_byte_t *) info->list_buffer)
    {        
        globus_free(read_buffer);
    }



    return GLOBUS_SUCCESS;


error_read:
error_list:

    if(read_buffer != GLOBUS_NULL)
    {        
        globus_free(read_buffer);
    }


error_malloc:
    return result;


}


static
void
globus_l_gass_copy_ftp_client_op_done_callback(
    void *                             user_arg,
    globus_ftp_client_handle_t *       handle,
    globus_object_t *                  err)
{
    static char *   myname = "globus_l_gass_copy_ftp_client_op_done_callback";    
    globus_l_gass_copy_glob_info_t * info;

    info = (globus_l_gass_copy_glob_info_t *) user_arg;
           
    globus_mutex_lock(&info->mutex);
    if (err != GLOBUS_SUCCESS && info->result == GLOBUS_SUCCESS)
    {
        info->result = globus_error_put(
            globus_object_copy(err));
    }
    info->callbacks_left--;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);
    
    return;
}



static
globus_result_t
globus_l_gass_copy_glob_parse_ftp_list(
    globus_l_gass_copy_glob_info_t *   info)
{
    static char *   myname = "globus_l_gass_copy_glob_parse_ftp_list";
    globus_result_t                    result;
    int                                i;
    int                                filename_len;
    int                                rc;
    globus_l_gass_copy_ftp_list_entry_t     filetype;
    char *                             space;
    char *                             temp_p;
    char *                             filename;
    char *                             matched_url;

    char *                             startline;
    char *                             endline;
    char *                             startfact;
    char *                             endfact;
    char *                             factval;
    globus_bool_t                      recurse_into_dir;
       
    startline = info->list_buffer;
    
    while(startline < (info->list_buffer + info->buffer_length))
    {
        filetype = GLOBUS_GASS_COPY_FTP_LIST_ENTRY_ASSUMED_FILE;
        recurse_into_dir = GLOBUS_TRUE;
        
        while(*startline == '\r' || 
              *startline == '\n')
        {
            startline++;
            continue;
        }
        
        endline = startline;
        while(*endline != '\r' &&
              *endline != '\n')
        {
            endline++;
        } 
        *endline = '\0';
    
        space = strchr(startline, ' ');
    
        if (info->list_op == GLOBUS_GASS_COPY_FTP_OP_NLST)
        {
            filename = startline;
        }
        else 
        {
            if (space == GLOBUS_NULL)
            {
                result = globus_error_put(
                    globus_error_construct_string(
                        GLOBUS_GASS_COPY_MODULE,
                        GLOBUS_NULL,
                        "[%s]: Bad MLSD output",
                        myname));
                          
                goto error_invalid_mlsd;
            }
            *space = '\0';            
            filename = space + 1;
            startfact = startline;
            
            while(startfact != space)
                  /* && 
                  filetype == GLOBUS_GASS_COPY_FTP_LIST_ENTRY_ASSUMED_FILE) */
            {
                endfact = strchr(startfact, ';');
                *endfact = '\0';
                
                for(i = 0; startfact[i] != '\0'; i++)
                {
                    startfact[i] = tolower(startfact[i]);
                }
    
                factval = strchr(startfact, '=');
                *(factval++) = '\0';
            
                if(strcmp(startfact, "type") == 0)
                {
                    if(strcmp(factval, "dir") == 0)
                    {
                        filetype = GLOBUS_GASS_COPY_FTP_LIST_ENTRY_DIR;
                    }
                    else if(strcmp(factval, "file") == 0)
                    {
                        filetype = GLOBUS_GASS_COPY_FTP_LIST_ENTRY_FILE;
                    }
                    else
                    {
                        filetype = GLOBUS_GASS_COPY_FTP_LIST_ENTRY_OTHER;
                    } 
                }                 
                if(strcmp(startfact, "unique") == 0)
                {
                    rc = globus_hashtable_insert(
                        &info->recurse_hash,
                        factval,
                        factval);
                    if(rc != GLOBUS_SUCCESS)
                    {
                        recurse_into_dir = GLOBUS_FALSE;
                    }
                        
                }                 
                startfact = endfact + 1;                                 
            } 
        }

        temp_p = strrchr(filename, '/');
        if (temp_p != GLOBUS_NULL)
        {
            filename = temp_p + 1;
        }

        switch(filetype)
        {
          case GLOBUS_GASS_COPY_FTP_LIST_ENTRY_FILE:
          case GLOBUS_GASS_COPY_FTP_LIST_ENTRY_ASSUMED_FILE:
            
            if(fnmatch(
                   info->glob_pattern,
                   filename,
                   FNM_PERIOD) == 0)
            {
                
                matched_url = (char *) 
                    globus_malloc((info->base_url_len + strlen(filename) + 2) * 
                                   sizeof(char));
                
                if(matched_url == GLOBUS_NULL)
                {
                    result = globus_error_put(
                        globus_error_construct_string(
                            GLOBUS_GASS_COPY_MODULE,
                            GLOBUS_NULL,
                            "[%s]: Memory allocation error",
                            myname));
                    goto error_malloc;
                }
                
                sprintf(matched_url, "%s/%s", info->base_url, filename);
                
                globus_fifo_enqueue(info->url_list, matched_url);
            }
            break;
          
          case GLOBUS_GASS_COPY_FTP_LIST_ENTRY_DIR:
            if(recurse_into_dir)
            {
                filename_len = strlen(filename);
     
                matched_url = (char *) 
                    globus_malloc((info->base_url_len + filename_len + 3) * 
                                   sizeof(char));
                
                if(matched_url == GLOBUS_NULL)
                {
                    result = globus_error_put(
                        globus_error_construct_string(
                            GLOBUS_GASS_COPY_MODULE,
                            GLOBUS_NULL,
                            "[%s]: Memory allocation error",
                            myname));
                    goto error_malloc;
                }

                sprintf(matched_url, "%s/%s/", info->base_url, filename);
                globus_fifo_enqueue(info->url_list, matched_url);
            }
                           
            break;
            
          case GLOBUS_GASS_COPY_FTP_LIST_ENTRY_OTHER: 
          default:
            
            break;
              
        }
        startline = endline + 1;
    }
    
    return GLOBUS_SUCCESS;
    
error_invalid_mlsd:
error_malloc:

    return result;    
    
}



static
void
globus_l_gass_copy_ftp_client_list_read_callback(
    void *                             user_arg,
    globus_ftp_client_handle_t *       handle,
    globus_object_t *                  err,
    globus_byte_t *                    buffer,
    globus_size_t                      length,
    globus_off_t                       offset,
    globus_bool_t                      eof)
{
    static char *   myname = "globus_l_gass_copy_ftp_client_list_read_callback";    
    globus_l_gass_copy_glob_info_t *   info;
    globus_result_t                    result;
    char *                             temp_p = NULL;
    
    info = (globus_l_gass_copy_glob_info_t *) user_arg;

    if(err != GLOBUS_SUCCESS)
    {
        goto error_before_callback;
    }

    if(info->list_buffer == GLOBUS_NULL && eof && offset == 0)
    {
        info->list_buffer = (char *) buffer;
        info->buffer_length = length;
        buffer = GLOBUS_NULL;
    }
    else
    {
        if((length + offset) > info->buffer_length)
        {
            temp_p = (char *) 
                globus_realloc(info->list_buffer, length + offset);
            if(temp_p == GLOBUS_NULL)
            {
                result = globus_error_put(
                    globus_error_construct_string(
                        GLOBUS_GASS_COPY_MODULE,
                        GLOBUS_NULL,
                        "[%s]: Memory allocation error",
                        myname));
                goto error_malloc;
            }
    
            info->list_buffer = temp_p;
            info->buffer_length = length + offset;
        }       

        memcpy(
            info->list_buffer + offset,
            buffer, 
            length);
    }
    
    if(!eof)
    {
        result = globus_ftp_client_register_read(
                    handle,
                    buffer,
                    GLOBUS_GASS_COPY_FTP_LIST_BUFFER_SIZE,
                    globus_l_gass_copy_ftp_client_list_read_callback,
                    (void *) info);

        if(result != GLOBUS_SUCCESS)
        {
           goto error_register_read;
        } 
    }
    else
    {
        
        globus_mutex_lock(&info->mutex);
        info->callbacks_left--;
        globus_cond_signal(&info->cond);
        globus_mutex_unlock(&info->mutex);


    }        

    return;


error_register_read:
error_malloc:
error_before_callback:

    globus_mutex_lock(&info->mutex);
    if (info->result == GLOBUS_SUCCESS)
    {
        if (err != GLOBUS_SUCCESS)
        { 
            info->result = globus_error_put(
                globus_object_copy(err));
        }
        else
        {
            info->result = result;
        }
    }
    info->callbacks_left--;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);

    return;
}


globus_result_t
globus_gass_copy_mkdir(
    globus_gass_copy_handle_t * handle,
    char * url,
    globus_gass_copy_attr_t * attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{   
    static char *   myname = "globus_gass_copy_mkdir";    

    globus_result_t                     result;
    globus_gass_copy_url_mode_t         url_mode;
    
    result = globus_gass_copy_get_url_mode(url, &url_mode);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    if(url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
    {
        result = globus_l_gass_copy_mkdir_ftp(handle, url, attr);

        if(result != GLOBUS_SUCCESS)
        {
            goto error_ftp_mkdir;
        }
    }
    else if(url_mode == GLOBUS_GASS_COPY_URL_MODE_IO)
    {
        result = globus_l_gass_copy_mkdir_file(url);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_file_mkdir;
        }
    }
    else
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: unsupported URL scheme: %s",
                myname,
                url));
        goto error_exit;
    }
    
    return GLOBUS_SUCCESS;
    
error_ftp_mkdir:
error_file_mkdir:

error_exit:

    return result;
    
}


static
globus_result_t
globus_l_gass_copy_mkdir_ftp(
    globus_gass_copy_handle_t *         handle,
    char *                              url,
    globus_gass_copy_attr_t *           attr)
{
    static char *   myname = "globus_l_gass_copy_mkdir_ftp";    

    globus_result_t                     result;
    globus_l_gass_copy_glob_info_t      info;
    
    info.callbacks_left = 1;
    info.result = GLOBUS_SUCCESS;
    globus_cond_init(&info.cond, GLOBUS_NULL);
    globus_mutex_init(&info.mutex, GLOBUS_NULL);
   
 
    result = globus_ftp_client_mkdir(
        &handle->ftp_handle,
        url,
        attr->ftp_attr,
        globus_l_gass_copy_ftp_client_op_done_callback,
        &info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_mkdir;
    }

    globus_mutex_lock(&info.mutex);
    while(info.callbacks_left > 0)
    {
        globus_cond_wait(&info.cond, &info.mutex);
    }
    result = info.result;
    globus_mutex_unlock(&info.mutex);
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_mkdir;
    }

    globus_cond_destroy(&info.cond);
    globus_mutex_destroy(&info.mutex);

    return GLOBUS_SUCCESS;

error_mkdir:

    globus_cond_destroy(&info.cond);
    globus_mutex_destroy(&info.mutex);


    return result;

}



static
globus_result_t
globus_l_gass_copy_mkdir_file(
    char *                              url)
{
    static char *   myname = "globus_l_gass_copy_mkdir_file";    
    int                                 rc;
    globus_url_t                        parsed_url;
    globus_result_t                     result;
    
    rc = globus_url_parse(url, &parsed_url);
    
    if(rc != 0)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url: "
                "globus_url_parse returned %d",
                myname,
                rc));
        goto error_url;
    }
    
    if(parsed_url.url_path == GLOBUS_NULL)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url: "
                "url has no path",
                myname));
        goto error_null_path;
    }
    
    rc = mkdir(parsed_url.url_path, 0777);

    if(rc != 0)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error creating directory: "
                "mkdir returned %d",
                myname,
                rc));
        goto error_mkdir;
    }
   
    globus_url_destroy(&parsed_url); 
    return GLOBUS_SUCCESS;

error_mkdir:    
error_null_path:
    globus_url_destroy(&parsed_url);
    
error_url:

    return result;
    
}
