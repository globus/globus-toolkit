#include "globus_gass_copy.h"
#ifndef TARGET_ARCH_WIN32

#include <glob.h>
#include <fnmatch.h>

#endif


/************************************************************
 * glob support
 ***********************************************************/


/*    
todo:
come up with minimal globbing support for windows
*/


typedef enum
{
    GLOBUS_GASS_COPY_FTP_OP_NLST,
    GLOBUS_GASS_COPY_FTP_OP_MLSD
} globus_l_gass_copy_ftp_op_t;


typedef struct
{
    globus_mutex_t                     mutex;
    globus_cond_t                      cond;
    globus_object_t *                  err;
    int                                callbacks_left;
    globus_size_t                      buffer_length;
    char *                             url;
    char *                             base_url;
    int                                base_url_len;
    char *                             glob_pattern;
    char *                             list_buffer;
    globus_l_gass_copy_ftp_op_t        list_op;
    globus_gass_copy_handle_t *        handle;
    globus_gass_copy_attr_t *          attr;
    globus_gass_copy_glob_entry_cb_t   entry_cb;
    void *                             entry_user_arg;
    
} globus_l_gass_copy_glob_info_t; 

static
globus_result_t
globus_l_gass_copy_glob_expand_file_url(
    globus_l_gass_copy_glob_info_t *   info);

static
globus_result_t
globus_l_gass_copy_glob_expand_ftp_url(
    globus_l_gass_copy_glob_info_t *   info);

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
globus_l_gass_copy_ftp_client_op_done_callback(
        void *                         user_arg,
        globus_ftp_client_handle_t *   handle,
        globus_object_t *              err);

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
     globus_gass_copy_handle_t *        handle, 
     const char *                       url, 
     globus_gass_copy_attr_t *          attr,
     globus_gass_copy_glob_entry_cb_t   entry_cb,
     void *                             user_arg)
{ 
    static char *   myname = "globus_gass_copy_glob_expand_url";
    globus_l_gass_copy_glob_info_t *    info;
    globus_result_t                     result;
    int                                 retval;
    globus_url_scheme_t                 scheme_type;
    int                                 url_len;
    int                                 path_len;
    globus_bool_t                       glob = GLOBUS_TRUE;
    globus_gass_copy_glob_stat_t        info_stat;  
    char *                              path;

    info = (globus_l_gass_copy_glob_info_t *)
        globus_malloc(sizeof(globus_l_gass_copy_glob_info_t));
    
    info->handle = handle;
    info->attr = attr;
    info->url = globus_libc_strdup(url);
    info->entry_cb = entry_cb;
    info->entry_user_arg = user_arg;
                

    retval = globus_url_get_scheme(info->url, &scheme_type);

    if(retval)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url scheme.",
                myname));
        goto error;
    }
    
    /* find start of path so we ignore potential globbing chars in host/port */
    url_len = strlen(info->url);
    if(scheme_type != GLOBUS_URL_SCHEME_FILE &&
        (path = strchr(info->url, '/')) &&
        (path = strchr(path + 1, '/')) &&
        (path = strchr(path + 1, '/')))
    {
        path_len = strlen(path);
    }
    else
    {
        path = info->url;
        path_len = url_len;
    }
    
    /* check if url contains glob characters,
       and append * if it is a directory */
       
    if(strcspn(path, "[]*?") == path_len)
    {        
        /* no globbing chars in path */
#ifndef TARGET_ARCH_WIN32
        if(info->url[url_len - 1] == '/')
        {   
            info->url = (char *) globus_realloc(
                info->url, (url_len + 2) * sizeof(char));
                
            info->url[url_len++] = '*';
            info->url[url_len] = '\0'; 
        }
        else
#endif
        {    
            info_stat.type = GLOBUS_GASS_COPY_GLOB_ENTRY_UNKNOWN;
            info_stat.unique_id = GLOBUS_NULL;
            info_stat.symlink_target = GLOBUS_NULL;
            info_stat.mode = -1;
            info_stat.mdtm = -1;
            info_stat.size = -1;
            
            info->entry_cb(
                info->url,
                &info_stat,
                info->entry_user_arg);
                 
            glob = GLOBUS_FALSE;
            result = GLOBUS_SUCCESS;
        }
    }

    if(glob)
    {
#ifndef TARGET_ARCH_WIN32
        switch (scheme_type)
        {
          case GLOBUS_URL_SCHEME_FTP:
          case GLOBUS_URL_SCHEME_GSIFTP:
            result = globus_l_gass_copy_glob_expand_ftp_url(info);
            break;
            
          case GLOBUS_URL_SCHEME_FILE:
            result = globus_l_gass_copy_glob_expand_file_url(info);
            break;
              
          default:
            result = globus_error_put(
                globus_error_construct_string(
                    GLOBUS_GASS_COPY_MODULE,
                    GLOBUS_NULL,
                    "[%s]: Globbing not supported with URL scheme.",
                    myname));
            goto error;
            break;    
        }
#else
            result = globus_error_put(
                globus_error_construct_string(
                    GLOBUS_GASS_COPY_MODULE,
                    GLOBUS_NULL,
                    "[%s]: Globbing not supported under Windows.",
                    myname));
            goto error;
#endif    
    }        

    globus_free(info->url);
    globus_free(info);
    return result;
            
error:
    globus_free(info->url);
    globus_free(info);
    return result;
}


static
globus_result_t
globus_l_gass_copy_glob_expand_file_url( 
    globus_l_gass_copy_glob_info_t *    info)
{
    static char *   myname = "globus_l_gass_copy_glob_expand_file_url";

#ifndef TARGET_ARCH_WIN32
    glob_t                              file_list;
#endif

    globus_result_t                     result;
    int                                 retval;
    int                                 file_len;
    globus_url_t                        parsed_url;
    int                                 i;
    char *                              base_url;
    char *                              p;
    int                                 base_url_len;
    struct stat                         stat_buf;
    char                                unique_id[32];
    globus_gass_copy_glob_entry_t       type;
    globus_gass_copy_glob_stat_t        info_stat;  
    char                                matched_url[4096];
    
    retval = globus_url_parse_loose(info->url, &parsed_url);
    
    if(retval != 0 || parsed_url.url_path == GLOBUS_NULL)
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: error parsing url path.",
                myname));
        goto error_url;
    }    
                
    p = strstr(info->url, parsed_url.url_path);
    base_url_len = p - info->url;
    
    base_url = globus_libc_strdup(info->url);
    base_url[base_url_len] = '\0';
    
#ifndef TARGET_ARCH_WIN32
    retval = glob(
        parsed_url.url_path,
        GLOB_MARK,
        NULL,
        &file_list);

#ifdef GLOB_NOMATCH
    if(retval != 0 && retval != GLOB_NOMATCH)
#else /* GLOB_NOMATCH */
    if(retval != 0 && file_list.gl_pathc != 0)
#endif /* GLOB_NOMATCH */
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


    for(i = 0; i < file_list.gl_pathc; i++)
    {
        file_len = strlen(file_list.gl_pathv[i]);
        *unique_id = '\0';

        retval = stat(file_list.gl_pathv[i], &stat_buf);
        if(retval != 0)
        {
            goto error_stat;
        }
        
        if(S_ISDIR(stat_buf.st_mode))
        {
            type = GLOBUS_GASS_COPY_GLOB_ENTRY_DIR;
        }
        else
        {                 
            type = GLOBUS_GASS_COPY_GLOB_ENTRY_FILE;
        } 
        
        sprintf(
            unique_id,
            "%lx-%lx;",
            (unsigned long) stat_buf.st_dev, 
            (unsigned long) stat_buf.st_ino);
                              
        sprintf(
            matched_url, 
            "%s%s", 
            base_url, 
            file_list.gl_pathv[i]);

            info_stat.type = type;
            info_stat.unique_id = unique_id;
            info_stat.symlink_target = GLOBUS_NULL;
            info_stat.mode = -1;
            info_stat.mdtm = -1;
            info_stat.size = -1;
            
            info->entry_cb(
                matched_url,
                &info_stat,
                info->entry_user_arg);
    }
        
    globfree(&file_list);
#endif 
    globus_url_destroy(&parsed_url);

    globus_free(base_url);
    
    return GLOBUS_SUCCESS;    
   
error_stat:
#ifndef TARGET_ARCH_WIN32
    globfree(&file_list);
#endif 
   
error_glob:
    globus_url_destroy(&parsed_url);
    globus_free(base_url);

error_url:

    return result;
}    


static
globus_result_t
globus_l_gass_copy_glob_expand_ftp_url(
    globus_l_gass_copy_glob_info_t *    info)
{
    static char *   myname = "globus_l_gass_copy_glob_expand_ftp_url";    
    globus_result_t                    result;    
    globus_ftp_client_tristate_t       feature_response;
    globus_ftp_client_features_t       features;
    


    info->base_url = globus_libc_strdup(info->url);
    info->glob_pattern = strrchr(info->base_url, '/');
    
    if(info->glob_pattern == GLOBUS_NULL || *info->glob_pattern == '\0')
    {
        result = globus_error_put(
            globus_error_construct_string(
                GLOBUS_GASS_COPY_MODULE,
                GLOBUS_NULL,
                "[%s]: Bad URL",
                myname));
        goto error_url;
    }

    *(info->glob_pattern++) = '\0';
    
    info->base_url_len = strlen(info->base_url);
    info->list_buffer = GLOBUS_NULL;
    info->buffer_length = 0;
    info->err = GLOBUS_NULL;
            
    globus_mutex_init(&info->mutex, GLOBUS_NULL);
    globus_cond_init(&info->cond, GLOBUS_NULL);

    result = globus_ftp_client_features_init(&features);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_feat;
    }

    info->callbacks_left = 1;
    result = globus_ftp_client_feat(
        &info->handle->ftp_handle,
        info->base_url,
        info->attr->ftp_attr,
        &features,
        globus_l_gass_copy_ftp_client_op_done_callback,
        info);
     
    if(result != GLOBUS_SUCCESS)
    {
        goto error_feat;
    }
                 
    globus_mutex_lock(&info->mutex);
    while(info->callbacks_left)
    {
        globus_cond_wait(&info->cond, &info->mutex);
    }
    if(info->err)
    {
        result = globus_error_put(info->err);
        info->err = GLOBUS_NULL;
    }
    globus_mutex_unlock(&info->mutex);
  
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
        info->list_op = GLOBUS_GASS_COPY_FTP_OP_MLSD;
    }
    else    
    {
        info->list_op = GLOBUS_GASS_COPY_FTP_OP_NLST;
    }

    

    result = globus_l_gass_copy_glob_ftp_list(info);    
         
    if(result != GLOBUS_SUCCESS)
    {
        goto error_list;
    }

    result = globus_l_gass_copy_glob_parse_ftp_list(info);   
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_list;
    } 

    if(info->list_buffer != GLOBUS_NULL)
    {        
        globus_free(info->list_buffer);
    }
   
    globus_cond_destroy(&info->cond);
    globus_mutex_destroy(&info->mutex);
        
    globus_free(info->base_url);

    return GLOBUS_SUCCESS;


error_list:
error_feat:
    globus_cond_destroy(&info->cond);
    globus_mutex_destroy(&info->mutex);
    
error_url:
    globus_free(info->base_url);

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
    while(info->callbacks_left)
    {
        globus_cond_wait(&info->cond, &info->mutex);
    }
    globus_mutex_unlock(&info->mutex);

    if(info->err)
    {
        result = globus_error_put(info->err);
        info->err = GLOBUS_NULL;
    }

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
    if(info->err)
    {
        globus_object_free(info->err);
        info->err = GLOBUS_NULL;
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
    globus_l_gass_copy_glob_info_t * info;

    info = (globus_l_gass_copy_glob_info_t *) user_arg;
           
    globus_mutex_lock(&info->mutex);
    if (err && !info->err)
    {
        info->err = globus_object_copy(err);
    }
    info->callbacks_left--;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);
    
    return;
}



static
globus_result_t
globus_l_gass_copy_glob_parse_ftp_list(
    globus_l_gass_copy_glob_info_t *    info)
{
    static char *   myname = "globus_l_gass_copy_glob_parse_ftp_list";
    globus_result_t                     result;
    int                                 i;
    char *                              space;
    char *                              temp_p;
    char *                              filename;
    char *                              startline;
    char *                              endline;
    char *                              startfact;
    char *                              endfact;
    char *                              factval;
    
    char                                matched_url[4096];
    char *                              unique_id;
    globus_gass_copy_glob_entry_t       type;
    globus_gass_copy_glob_stat_t        info_stat;  
       
    startline = info->list_buffer;
    
    while(startline < (info->list_buffer + info->buffer_length))
    {
        type = GLOBUS_GASS_COPY_GLOB_ENTRY_UNKNOWN;
        unique_id = GLOBUS_NULL;
        
        while(*startline == '\r' || 
              *startline == '\n')
        {
            startline++;
            
        }
        
        endline = startline;
        while(endline < info->list_buffer + info->buffer_length && 
            *endline != '\r' && *endline != '\n')
        {
            endline++;
        } 
        *endline = '\0';
    
        if (info->list_op == GLOBUS_GASS_COPY_FTP_OP_NLST)
        {
            filename = startline;
        }
        else 
        {
            space = strchr(startline, ' ');
            if (space == GLOBUS_NULL)
            {
                result = globus_error_put(
                    globus_error_construct_string(
                        GLOBUS_GASS_COPY_MODULE,
                        GLOBUS_NULL,
                        "[%s]: Bad MLSD response",
                        myname));
                          
                goto error_invalid_mlsd;
            }
            *space = '\0';            
            filename = space + 1;
            startfact = startline;
            
            while(startfact != space)
            {
                endfact = strchr(startfact, ';');
                if(endfact)
                {             
                    *endfact = '\0';
                }
                else
                {                                     
/*
                 older MLST-draft spec says ending fact can be missing
                 the final semicolon... not a problem to support this,
                 no need to die.  (ncftpd does this) 
                    
                    result = globus_error_put(
                        globus_error_construct_string(
                            GLOBUS_GASS_COPY_MODULE,
                            GLOBUS_NULL,
                            "[%s]: Bad MLSD response",
                            myname));
                          
                    goto error_invalid_mlsd;
*/

                    endfact = space - 1;   
                }
                
                for(i = 0; startfact[i] != '\0'; i++)
                {
                    startfact[i] = tolower(startfact[i]);
                }

                factval = strchr(startfact, '=');
                if(!factval)
                {             
                    result = globus_error_put(
                        globus_error_construct_string(
                            GLOBUS_GASS_COPY_MODULE,
                            GLOBUS_NULL,
                            "[%s]: Bad MLSD response",
                            myname));
                          
                    goto error_invalid_mlsd;
                }
                *(factval++) = '\0';
            
                if(strcmp(startfact, "type") == 0)
                {
                    if(strcmp(factval, "dir") == 0)
                    {
                        type = GLOBUS_GASS_COPY_GLOB_ENTRY_DIR;
                    }
                    else if(strcmp(factval, "file") == 0)
                    {
                        type = GLOBUS_GASS_COPY_GLOB_ENTRY_FILE;
                    }
                    else
                    {
                        type = GLOBUS_GASS_COPY_GLOB_ENTRY_OTHER;
                    } 
                }                 
                if(strcmp(startfact, "unique") == 0)
                {
                    unique_id = factval;                        
                }                 
                startfact = endfact + 1;                                 
            } 
        }

        temp_p = strrchr(filename, '/');
        if (temp_p != GLOBUS_NULL)
        {
            filename = temp_p + 1;
        }
        
        *matched_url = '\0'; 
#ifndef TARGET_ARCH_WIN32
        switch(type)
        {
          case GLOBUS_GASS_COPY_GLOB_ENTRY_FILE:
          case GLOBUS_GASS_COPY_GLOB_ENTRY_UNKNOWN:
            if(fnmatch(
                   info->glob_pattern,
                   filename,
                   FNM_PERIOD) == 0)
            {
                sprintf(matched_url, "%s/%s", info->base_url, filename);
            }
            break;
          
          case GLOBUS_GASS_COPY_GLOB_ENTRY_DIR:
            if(fnmatch(
                   info->glob_pattern,
                   filename,
                   FNM_PERIOD) == 0)
            {
                sprintf(matched_url, "%s/%s/", info->base_url, filename);
            }
            break;
          
          case GLOBUS_GASS_COPY_GLOB_ENTRY_OTHER:
          default:
            break;
        }
#endif        
        if(*matched_url)
        {
            info_stat.type = type;
            info_stat.unique_id = unique_id;
            info_stat.symlink_target = GLOBUS_NULL;
            info_stat.mode = -1;
            info_stat.mdtm = -1;
            info_stat.size = -1;
            
            info->entry_cb(
                matched_url,
                &info_stat,
                info->entry_user_arg);
        }
                
        startline = endline + 1;
        while(startline < info->list_buffer + info->buffer_length && 
            (*startline == '\r' || *startline == '\n'))
        {
            startline++;           
        }

    }
    
    return GLOBUS_SUCCESS;
    
error_invalid_mlsd:

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

    if(err)
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
    if (err && !info->err)
    {
        info->err = globus_object_copy(err);
    }
    info->callbacks_left--;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);

    return;
}


globus_result_t
globus_gass_copy_mkdir(
    globus_gass_copy_handle_t *         handle,
    char *                              url,
    globus_gass_copy_attr_t *           attr)
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
    globus_result_t                     result;
    globus_l_gass_copy_glob_info_t      info;
    
    info.callbacks_left = 1;
    info.err = GLOBUS_NULL;
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
    globus_mutex_unlock(&info.mutex);

    if(info.err)
    {
        result = globus_error_put(info.err);
        info.err = GLOBUS_NULL;
    }
    
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

