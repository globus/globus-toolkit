#include "globus_gridftp_server.h"
#include "globus_common.h"
#include "srbClient.h"
#include "globus_srb_options.h"
#include "globus_srb_config.h"
#include "version.h"
#include <ctype.h>

static char *                           srb_l_default_hostname = NULL;
static char *                           srb_l_default_hostname_dn = NULL;
static char *                           srb_l_default_resource = NULL;

static unsigned int                     srb_l_default_dev_wrap = 0;
extern char inCondition[];

int
queryCollColl (srbConn *conn, int catType, char *collName, int flagval,
mdasC_sql_result_struct *collResult);

static
globus_result_t
srb_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    /* TODO: log an error */
    return GLOBUS_SUCCESS;
}

extern 
char *
getAttributeColumn(mdasC_sql_result_struct *result,
            int attrIndex);


int
srb_l_reduce_path(
    char *                              path)
{
    char *                              ptr;
    int                                 len;
    int                                 end;

    len = strlen(path);

    while(len > 1 && path[len-1] == '/')
    {
        len--;
        path[len] = '\0';
    }
    end = len-2;
    while(end >= 0)
    {
        ptr = &path[end];
        if(strncmp(ptr, "//", 2) == 0)
        {
            memmove(ptr, &ptr[1], len - end);
            len--;
        }
        end--;
    }
    return 0;
}

static
globus_result_t
srb_l_opts_default_hostname(
    char *                              cmd,
    char *                              parm,
    void *                              arg,
    int *                               out_parms_used)
{
    if(parm == NULL)
    {
        /* TODO: log a warning */
        return GLOBUS_SUCCESS;
    }

    *out_parms_used = 1;
    if(srb_l_default_hostname != NULL)
    {
        free(srb_l_default_hostname);
    }
    srb_l_default_hostname = strdup(parm);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
srb_l_opts_default_hostname_dn(
    char *                              cmd,
    char *                              parm,
    void *                              arg,
    int *                               out_parms_used)
{
    if(parm == NULL)
    {
        /* TODO: log a warning */
        return GLOBUS_SUCCESS;
    }

    *out_parms_used = 1;
    if(srb_l_default_hostname_dn != NULL)
    {
        free(srb_l_default_hostname_dn);
    }
    srb_l_default_hostname_dn = strdup(parm);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
srb_l_opts_default_resource(
    char *                              cmd,
    char *                              parm,
    void *                              arg,
    int *                               out_parms_used)
{
    if(parm == NULL)
    {
        /* TODO: log a warning */
        return GLOBUS_SUCCESS;
    }

    *out_parms_used = 1;
    if(srb_l_default_resource != NULL)
    {
        free(srb_l_default_resource);
    }
    srb_l_default_resource = strdup(parm);

    return GLOBUS_SUCCESS;
}

static globus_srb_options_entry_t           srb_l_opts_table[] =
{
    {"srb_hostname",
    NULL,
    "GLOBUS_SRB_HOSTNAME",
    "<srb host>:<srb port>",
    "The host and port of the backend SRB server",
    1,
    srb_l_opts_default_hostname},
    {"srb_hostname_dn",
    NULL,
    "GLOBUS_SRB_DN",
    "<srb security DN>",
    "The DN under which the srb server is running",
    1,
    srb_l_opts_default_hostname_dn},
    {"srb_default_resource",
    NULL,
    "GLOBUS_SRB_DEFAULT_RESOURCE",
    "<srb host>:<srb port>",
    "The default resource to use when writing data to the SRB backend.",
    1,
    srb_l_opts_default_resource}
};


int
aid_import_credential(gss_cred_id_t input_cred);

typedef struct globus_l_srb_read_ahead_s
{
    struct globus_l_gfs_srb_handle_s *  srb_handle;
    globus_off_t                        offset;
    globus_size_t                       length;
    globus_byte_t                       buffer[1];
} globus_l_srb_read_ahead_t;

/*
 *  the data structure representing the FTP session
 */
typedef struct globus_l_gfs_srb_handle_s
{
    srbConn *                           conn;
    int                                 stor_sys_type;
    int                                 fd;
    globus_mutex_t                      mutex;
    globus_gfs_operation_t              op;
    globus_bool_t                       done;
    globus_bool_t                       read_eof;
    int                                 outstanding;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_result_t                     cached_res;
    globus_off_t                        blk_length;
    globus_off_t                        blk_offset;

    globus_fifo_t                       rh_q;

    char *                              hostname;
    char *                              port;

    char *                              zone;
    char *                              user;
    char *                              domain;

    char *                              srb_dn;
} globus_l_gfs_srb_handle_t;

typedef struct globus_l_gfs_srb_trans_s
{
    srbConn *                           conn;
    globus_l_gfs_srb_handle_t *         handle;
} globus_l_gfs_srb_trans_t;

static
globus_bool_t
globus_l_gfs_srb_send_next_to_client(
    globus_l_gfs_srb_handle_t *         srb_handle);

static
globus_bool_t
globus_l_gfs_srb_read_from_net(
    globus_l_gfs_srb_handle_t *         srb_handle);

static
void
globus_l_gfs_srb_read_ahead_next(
    globus_l_gfs_srb_handle_t *         srb_handle);

/*
 *  utility function to make errors
 */
static
globus_result_t
globus_l_gfs_srb_make_error(
    const char *                        msg,
    srbConn *                           conn,
    int                                 status)
{
    char *                              err_str;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_srb_make_error);

    err_str = globus_common_create_string("SRB Error: %s: %s status: %d", 
            msg, clErrorMessage(conn), status);
    result = GlobusGFSErrorGeneric(err_str);
    free(err_str);

    return result;
}

#if 0
static void
tmp_to_disk_func(
    gss_cred_id_t                       del_cred)
{
    char *                  error_str;
    char *                  tmp_str;
    OM_uint32                   maj_stat;
    OM_uint32                   min_stat;
    gss_buffer_desc                             gss_buf;
char x[1024];

assert(del_cred != NULL);
    gss_buf.value = "/tmp/bresnaha_test";
    gss_buf.length = strlen(gss_buf.value);

    maj_stat = gss_export_cred(
            &min_stat,
            del_cred,
            NULL,
            1,
            &gss_buf);
    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    tmp_str = strchr((char *)gss_buf.value, '=') + 1;

sleep(1);
sprintf(x, "/bin/cp %s /tmp/bresnaha_test_proxy", (char *)tmp_str);
system(x);
/*
globus_libc_setenv("X509_USER_PROXY", tmp_str, 1);

printf("X509_USER_PROXY=%s\n", tmp_str);
*/
}
#endif

static
int
srb_l_filename_hash(
    char *                              string)
{
    unsigned long                       h = 0;
    unsigned long                       g;
    char *                              key;

    if(string == NULL)
    {
        return 0;
    }

    key = (char *) string;

    while(*key)
    {
        h = (h << 4) + *key++;
        if((g = (h & 0xF0UL)))
        {
            h ^= g >> 24;
            h ^= g;
        }
    }

    return h % 2147483647;
}

static
int
srb_l_stat_dir(
    srbConn *                           conn,
    globus_gfs_stat_t **                out_stat,
    int *                               out_count,
    char *                              start_dir)
{
    int                                 i;
    int                                 status;
    mdasC_sql_result_struct             myresult;
    char                                qval[MAX_DCS_NUM][MAX_TOKEN];
    int                                 selval[MAX_DCS_NUM];
    char *                              tmp_s;
    char *                              rsrcName;
    char *                              rsrcNameStart;
    char *                              sizeName;
    char *                              sizeNameStart;
    char *                              ownerName;
    char *                              ownerNameStart;
    char *                              pathName;
    char *                              pathNameStart;
    char *                              modTime;
    char *                              modTimeStart;
    int                                 maxRows = 128;
    globus_gfs_stat_t *                 stat_array = NULL;
    int                                 stat_count = 1;
    int                                 stat_ndx = 0;
    struct tm                           tm;
    int                                 sc;
    int                                 done = 0;


    /* add in a single '.' entry */
    stat_count = 1;
    stat_array = (globus_gfs_stat_t *) globus_calloc(
        stat_count, sizeof(globus_gfs_stat_t));
    stat_array[stat_ndx].ino = srb_l_filename_hash(start_dir);
    stat_array[stat_ndx].name = strdup(".");
    stat_array[stat_ndx].nlink = 0;
    stat_array[stat_ndx].uid = 1;
    stat_array[stat_ndx].gid = 1;
        stat_array[stat_ndx].size = 0;
    stat_array[stat_ndx].dev = 0;
    stat_array[stat_ndx].mode =
        S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    stat_ndx++;

    for (i = 0; i < MAX_DCS_NUM; i++)
    {
        selval[i] = 0;
        *qval[i] = '\0';
    }

    sprintf(qval[DATA_GRP_NAME]," = '%s'", start_dir);

    /* ones that i want */
    selval[DATA_NAME] = 1;
    selval[DATA_GRP_NAME] = 1;
    selval[SIZE] = 1;
    selval[DATA_OWNER] = 1;
    selval[REPL_TIMESTAMP] = 1;
    /* ones that i seem to need to not hang */
    selval[IS_DIRTY] = 1;  
    selval[DATA_TYP_NAME] = 1; 
    selval[DATA_REPL_ENUM] = 1; 
    selval[CONTAINER_SIZE] = 1; 
    selval[OFFSET] = 1;
    selval[PHY_RSRC_NAME] = 1; 
    selval[CONTAINER_NAME] = 1; 
    sprintf(qval[ORDERBY], "DATA_NAME");

    /* perform the MCAT query */
    status = srbGetDataDirInfo(conn, MDAS_CATALOG,
                qval, selval, &myresult, maxRows);
    if(status != 0 && status != -3005)
    {
        return status;
    }
    while(status == 0 && !done)
    {
        /* retrieve the values */
        pathName = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            DATA_GRP_NAME);
        pathNameStart = pathName;
        modTime = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            REPL_TIMESTAMP);
        modTimeStart = modTime;
        rsrcName = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            DATA_NAME);
        rsrcNameStart = rsrcName;
        sizeName = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            SIZE);
        sizeNameStart = sizeName;
        ownerName = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            DATA_OWNER);
        ownerNameStart = ownerName;

        stat_count = myresult.row_count + stat_count;
        stat_array = (globus_gfs_stat_t *) globus_realloc(stat_array,
            stat_count * sizeof(globus_gfs_stat_t));
        for (i = 0; i < myresult.row_count; i++)
        {
            memset(&stat_array[stat_ndx], '\0', sizeof(globus_gfs_stat_t));
            stat_array[stat_ndx].symlink_target = NULL;
            stat_array[stat_ndx].name = globus_libc_strdup(rsrcName);
            stat_array[stat_ndx].nlink = 0;
            stat_array[stat_ndx].uid = 1;
            stat_array[stat_ndx].gid = 1;
            sc = sscanf(sizeName, "%"GLOBUS_OFF_T_FORMAT,
                &stat_array[stat_ndx].size);
            if(sc != 1)
            {
                stat_array[stat_ndx].size = -1;
            }

            memset(&tm, '\0', sizeof(struct tm));
            sc = sscanf(modTime, "%d-%d-%d-%d.%d.%d",
                &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
            if(sc == 6)
            {
                tm.tm_wday = 0;
                tm.tm_yday = 0;
                tm.tm_isdst = 1;
                tm.tm_year -= 1900;
                tm.tm_mon -= 1;

                stat_array[stat_ndx].ctime = mktime(&tm);
                stat_array[stat_ndx].mtime = mktime(&tm);
                stat_array[stat_ndx].atime = mktime(&tm);
            }
            /* need to fake these next 2 better */
            stat_array[stat_ndx].dev = srb_l_default_dev_wrap++;
            stat_array[stat_ndx].ino = srb_l_filename_hash(pathName);

            stat_array[stat_ndx].mode =
                S_IFREG | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

            if(rsrcName) 
            {
                rsrcName += MAX_DATA_SIZE;
            }
            if(pathName)
            {
                pathName += MAX_DATA_SIZE;
            }
            if(sizeName)
            {
                sizeName += MAX_DATA_SIZE;
            }
            if(ownerName)
            {
                ownerName += MAX_DATA_SIZE;
            }
            stat_ndx++;
        }
        clearSqlResult(&myresult);
        if (myresult.continuation_index >= 0)
        {
            status = srbGetMoreRows(conn, MDAS_CATALOG,
                myresult.continuation_index, &myresult, maxRows);
        }
        else
        {
            done = 1;
        }
/*
        free(pathNameStart);
        free(modTimeStart);
        free(sizeNameStart);
        free(ownerNameStart);
*/
    }

    done = 0;
    /* now we need to do directories/collections */
    for (i = 0; i < MAX_DCS_NUM; i++)
    {
        selval[i] = 0;
        *qval[i] = '\0';
    }


    selval[DATA_GRP_NAME] = 1;
    sprintf(qval[PARENT_COLLECTION_NAME]," = '%s'", start_dir);
    status = srbGetDataDirInfo(conn, MDAS_CATALOG,
                qval, selval, &myresult, maxRows);
    if(status != 0 && status != -3005)
    {
        /* free some leaks here */
        return status;
    }
    while(status == 0 && !done)
    {
        rsrcName = (char *) getAttributeColumn(
            (mdasC_sql_result_struct *) &myresult,
            DATA_GRP_NAME);

        stat_count = myresult.row_count + stat_count;
        stat_array = (globus_gfs_stat_t *) globus_realloc(stat_array,
            stat_count * sizeof(globus_gfs_stat_t));
        for (i = 0; i < myresult.row_count; i++)
        {
            char * fname;

            memset(&stat_array[stat_ndx], '\0', sizeof(globus_gfs_stat_t));
            stat_array[stat_ndx].ino = srb_l_filename_hash(rsrcName);
            fname = rsrcName ? rsrcName : "(null)";
            tmp_s = strrchr(fname, '/');
            if(tmp_s != NULL) fname = tmp_s + 1;
            stat_array[stat_ndx].name = strdup(fname);
            stat_array[stat_ndx].nlink = 0;
            stat_array[stat_ndx].uid = 1;
            stat_array[stat_ndx].gid = 1;
                stat_array[stat_ndx].size = 0;;
            stat_array[stat_ndx].dev = 0;

            stat_array[stat_ndx].mode =
                S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

            if(rsrcName) rsrcName += MAX_DATA_SIZE;
            stat_ndx++;
        }
        clearSqlResult(&myresult);
        if (myresult.continuation_index >= 0)
        {
            status = srbGetMoreRows(conn, MDAS_CATALOG,
                myresult.continuation_index, &myresult, maxRows);
        }
        else
        {
            done = 1;
        }
    }

    *out_stat = stat_array;
    *out_count = stat_count;
    return 0;
}



/***********************************************************************
 *    logic for sending to the client
 *    -------------------------------
 **********************************************************************/
static
void
globus_l_gfs_net_write_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_l_gfs_srb_handle_t *         srb_handle;
    globus_l_srb_read_ahead_t *         rh;
    globus_l_srb_read_ahead_t *         tmp_rh;

    rh = (globus_l_srb_read_ahead_t *) user_arg;
    srb_handle = rh->srb_handle;
    globus_free(rh);

    globus_mutex_lock(&srb_handle->mutex);
    {
        srb_handle->outstanding--;
        if(result != GLOBUS_SUCCESS)
        {
            srb_handle->cached_res = result;
            srb_handle->read_eof = GLOBUS_TRUE;
            srbObjClose(srb_handle->conn, srb_handle->fd);
            while(!globus_fifo_empty(&srb_handle->rh_q))
            {
                tmp_rh = (globus_l_srb_read_ahead_t *)
                    globus_fifo_dequeue(&srb_handle->rh_q);
                globus_free(tmp_rh);
            }
        }
        else
        {
            globus_l_gfs_srb_send_next_to_client(srb_handle);
            globus_l_gfs_srb_read_ahead_next(srb_handle);
        }
        /* if done and there are no outstanding callbacks finish */
        if(srb_handle->outstanding == 0 &&
            globus_fifo_empty(&srb_handle->rh_q))
        {
            finish = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&srb_handle->mutex);

    if(finish)
    {
        globus_gridftp_server_finished_transfer(op, srb_handle->cached_res);
    }
}

static
void
globus_l_gfs_srb_read_ahead_next(
    globus_l_gfs_srb_handle_t *         srb_handle)
{
    int                                 read_length;
    globus_result_t                     result;
    globus_l_srb_read_ahead_t *         rh;
    globus_off_t                        start_offset;
    GlobusGFSName(globus_l_gfs_srb_read_ahead_next);

    if(srb_handle->read_eof)
    {
        goto error;
    }
    /* if we have done everything for this block, get the next block
       also this will happen the first time
       -1 length means unti lthe end of the file  */
    if(srb_handle->blk_length == 0)
    {
        /* check the next range to read */
        globus_gridftp_server_get_read_range(
            srb_handle->op,
            &srb_handle->blk_offset,
            &srb_handle->blk_length);
        if(srb_handle->blk_length == 0)
        {
            result = GLOBUS_SUCCESS;
            goto error;
        }
    }

    /* get the current length to read */
    if(srb_handle->blk_length == -1 || 
        srb_handle->blk_length > srb_handle->block_size)
    {
        read_length = (int)srb_handle->block_size;
    }
    else
    {
        read_length = (int)srb_handle->blk_length;
    }
    rh = (globus_l_srb_read_ahead_t *) calloc(1,
        sizeof(globus_l_srb_read_ahead_t)+read_length);
    rh->offset = srb_handle->blk_offset;
    rh->srb_handle = srb_handle;

#ifdef SRB_CAN_SEEK
    /* read it from srb */
    start_offset = srbObjSeek(
        srb_handle->conn, srb_handle->fd,
        (int)srb_handle->blk_offset, SEEK_SET);
    /* verify that it worked */
    if(start_offset != rh->offset)
    {
        result = globus_l_gfs_srb_make_error(
            "seek failed", srb_handle->conn, clStatus(srb_handle->conn));
        goto attempt_error;
    }
#endif

    rh->length = srbObjRead(
        srb_handle->conn, srb_handle->fd, rh->buffer, read_length);
    if(rh->length <= 0)
    {
        result = GLOBUS_SUCCESS; /* this may just be eof */
        goto attempt_error;
    }

    srb_handle->blk_offset += rh->length;
    if(srb_handle->blk_length != -1)
    {
        srb_handle->blk_length -= rh->length;
    }

    globus_fifo_enqueue(&srb_handle->rh_q, rh);

    return;

attempt_error:
    globus_free(rh);
    srbObjClose(srb_handle->conn, srb_handle->fd);
    srb_handle->cached_res = result;
error:
    srb_handle->read_eof = GLOBUS_TRUE;
}

static
globus_bool_t
globus_l_gfs_srb_send_next_to_client(
    globus_l_gfs_srb_handle_t *         srb_handle)
{
    globus_l_srb_read_ahead_t *         rh;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_srb_send_next_to_client);

    rh = (globus_l_srb_read_ahead_t *) globus_fifo_dequeue(&srb_handle->rh_q);
    if(rh == NULL)
    {
        goto error;
    }

    res = globus_gridftp_server_register_write(
        srb_handle->op, rh->buffer, rh->length, rh->offset, -1, 
        globus_l_gfs_net_write_cb, rh);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }
    srb_handle->outstanding++;

    return GLOBUS_FALSE;

alloc_error:
    globus_free(rh);

    srb_handle->cached_res = result;
    if(!srb_handle->read_eof)
    {
        srbObjClose(srb_handle->conn, srb_handle->fd);
        srb_handle->read_eof = GLOBUS_TRUE;
    }
    /* if we get an error here we need to flush the q */
    while(!globus_fifo_empty(&srb_handle->rh_q))
    {
        rh = (globus_l_srb_read_ahead_t *)
            globus_fifo_dequeue(&srb_handle->rh_q);
        globus_free(rh);
    }

error:
    return GLOBUS_TRUE;
}

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
static
void
globus_l_gfs_srb_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_bool_t                       finish = GLOBUS_FALSE;
    char *                              collection;
    char *                              tmp_ptr;
    char *                              object;
    globus_result_t                     result;
    globus_l_gfs_srb_handle_t *         srb_handle;
    GlobusGFSName(globus_l_gfs_srb_send);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;
    if(srb_handle == NULL)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("SRB DSI must be a default backend"
            " module.  It cannot be an eret alone");
        goto alloc_error;
    }

    collection = strdup(transfer_info->pathname);
    if(collection == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: strdup failed");
        goto alloc_error;
    }
    tmp_ptr = strrchr(collection, '/');
    if(tmp_ptr == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: bad collection name");
        goto error;
    }
    *tmp_ptr = '\0';
    object = tmp_ptr + 1;

    srb_handle->fd = srbObjOpen(
        srb_handle->conn,
        object,
        O_RDONLY,
        collection);
    if(srb_handle->fd <= 0)
    {
        result = globus_l_gfs_srb_make_error(
            "open failed", srb_handle->conn, srb_handle->fd);
        goto error;
    }

    /* reset all the needed variables in the handle */
    srb_handle->read_eof = GLOBUS_FALSE;
    srb_handle->cached_res = GLOBUS_SUCCESS;
    srb_handle->outstanding = 0;
    srb_handle->done = GLOBUS_FALSE;
    srb_handle->blk_length = 0;
    srb_handle->blk_offset = 0;
    srb_handle->op = op;
    globus_gridftp_server_get_optimal_concurrency(
        op, &srb_handle->optimal_count);
    globus_gridftp_server_get_block_size(
        op, &srb_handle->block_size);

    globus_gridftp_server_begin_transfer(op, 0, srb_handle);

    globus_mutex_lock(&srb_handle->mutex);
    {
        for(i = 0; i < srb_handle->optimal_count && !done; i++)
        {
            globus_l_gfs_srb_read_ahead_next(srb_handle);
            done = globus_l_gfs_srb_send_next_to_client(srb_handle);
        }
        for(i = 0; i < srb_handle->optimal_count && !done; i++)
        {
            globus_l_gfs_srb_read_ahead_next(srb_handle);
        }
        if(done && srb_handle->outstanding == 0 &&
            globus_fifo_empty(&srb_handle->rh_q))
        {
            finish = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&srb_handle->mutex);

    if(finish)
    {
        globus_gridftp_server_finished_transfer(op, srb_handle->cached_res);
    }

    globus_free(collection);
    return;

error:
    globus_free(collection);
alloc_error:
    globus_gridftp_server_finished_transfer(op, result);
}

/*************************************************************************
 *         logic to recieve from client
 *         ----------------------------
 ************************************************************************/

static
void
globus_l_gfs_srb_net_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg)
{
    globus_bool_t                       finished = GLOBUS_FALSE;
    globus_off_t                        start_offset;
    globus_l_gfs_srb_handle_t *         srb_handle;
    globus_size_t                       bytes_written;

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    globus_mutex_lock(&srb_handle->mutex);
    {
        if(eof)
        {
            srb_handle->done = GLOBUS_TRUE;
        }
        srb_handle->outstanding--;
        if(result != GLOBUS_SUCCESS)
        {
            srb_handle->cached_res = result;
            srb_handle->done = GLOBUS_TRUE;
        }
        /* if the read was successful write to disk */
        else if(nbytes > 0)
        {
            /* seek to the correct place */
            start_offset = srbObjSeek(
                srb_handle->conn,
                srb_handle->fd,
                offset,
                SEEK_SET);
            /* verify that it worked */
            if(start_offset != offset)
            {
                srb_handle->cached_res = globus_l_gfs_srb_make_error(
                    "seek failed", srb_handle->conn, start_offset);
                srb_handle->done = GLOBUS_TRUE;
            }
            else
            {
                bytes_written = srbObjWrite(
                    srb_handle->conn,
                    srb_handle->fd,
                    buffer,
                    nbytes);
                if(bytes_written < nbytes)
                {
                    srb_handle->cached_res = globus_l_gfs_srb_make_error(
                        "write failed", srb_handle->conn,
                        clStatus(srb_handle->conn));
                    srb_handle->done = GLOBUS_TRUE;
                }
            }
        }

        globus_free(buffer);
        /* if not done just register the next one */
        if(!srb_handle->done)
        {
            finished = globus_l_gfs_srb_read_from_net(srb_handle);
        }
        /* if done and there are no outstanding callbacks finish */
        else if(srb_handle->outstanding == 0)
        {
            srbObjClose(srb_handle->conn, srb_handle->fd);
            finished = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&srb_handle->mutex);

    if(finished)
    {
        globus_gridftp_server_finished_transfer(op, srb_handle->cached_res);
    }
}

static
globus_bool_t
globus_l_gfs_srb_read_from_net(
    globus_l_gfs_srb_handle_t *         srb_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_srb_read_from_net);

    /* in the read case tis number will vary */
    globus_gridftp_server_get_optimal_concurrency(
        srb_handle->op, &srb_handle->optimal_count);

    while(srb_handle->outstanding < srb_handle->optimal_count)
    {
        buffer = globus_malloc(srb_handle->block_size);
        if(buffer == NULL)
        {
            result = GlobusGFSErrorGeneric("malloc failed");
            goto error;
        }
        result = globus_gridftp_server_register_read(
            srb_handle->op,
            buffer,
            srb_handle->block_size,
            globus_l_gfs_srb_net_read_cb,
            srb_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto alloc_error;
        }
        srb_handle->outstanding++;
    }

    return GLOBUS_FALSE;

alloc_error:
    globus_free(buffer);
error:

    srb_handle->cached_res = result;
    srb_handle->done = GLOBUS_TRUE;
    if(srb_handle->outstanding == 0)
    {
        srbObjClose(srb_handle->conn, srb_handle->fd);
        return GLOBUS_TRUE;
    }
    return GLOBUS_FALSE;
}

/*************************************************************************
 *  recv
 *  ----
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 *  To receive a file the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_read();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
static
void
globus_l_gfs_srb_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_bool_t                       finish = GLOBUS_FALSE;
    int                                 status;
    char *                              collection = NULL;
    char *                              tmp_ptr;
    char *                              object;
    char *                              resource = "";
    globus_result_t                     result;
    struct stat                         statbuf;
    globus_l_gfs_srb_handle_t *         srb_handle;
    struct mdasEnvData *                tmpMdasEnvData;
    GlobusGFSName(globus_l_gfs_srb_recv);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    if(srb_handle == NULL)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("SRB DSI must be a default backend"
            " module.  It cannot be an eret alone");
        goto alloc_error;
    }

    if(transfer_info->pathname != NULL)
    {
        collection = strdup(transfer_info->pathname);
    }
    if(collection == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: strdup failed");
        goto alloc_error;
    }
    tmp_ptr = strrchr(collection, '/');
    if(tmp_ptr == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: bad collection name");
        goto error;
    }
    *tmp_ptr = '\0';
    object = tmp_ptr + 1;

    /* before opening we must check to see if it exists, if it does we
       use it where it is, if not we check the module parameters to see
       what resource to create it in, it NULL then shoose the default */

    /* try to open */ 
    status = srbObjStat(
        srb_handle->conn, MDAS_CATALOG, transfer_info->pathname, &statbuf);
    if(status == 0)
    {
        int                                       flags = O_WRONLY;

        if(transfer_info->truncate)
        {
            flags |= O_TRUNC;
        }
        srb_handle->fd = srbObjOpen(
            srb_handle->conn,
            object,
            flags,
            collection);

        globus_gfs_log_message(
            GLOBUS_GFS_LOG_INFO,
            "opening already existing file :%s: for write\n",
                transfer_info->pathname);
    }
    else
    {
         if(transfer_info->module_args == NULL)
         {
             resource = srb_l_default_resource;
             if(resource == NULL)
             {
                tmpMdasEnvData = readMdasParam();
                if(tmpMdasEnvData != NULL)
                {
                    resource = tmpMdasEnvData->defRes;
                }
             }
         }
         else
         {
             resource = transfer_info->module_args;
         }

         srb_handle->fd = srbObjCreate(
             srb_handle->conn,
             MDAS_CATALOG,
             object,
             "generic",
             resource,
             collection,
             "",
             -1);
    }
    if(srb_handle->fd <= 0)
    {
        result = globus_l_gfs_srb_make_error("post open/create",
            srb_handle->conn, srb_handle->fd);
        goto error;
    }
    free(collection);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    /* reset all the needed variables in the handle */
    srb_handle->cached_res = GLOBUS_SUCCESS;
    srb_handle->outstanding = 0;
    srb_handle->done = GLOBUS_FALSE;
    srb_handle->blk_length = 0;
    srb_handle->blk_offset = 0;
    srb_handle->op = op;
    globus_gridftp_server_get_block_size(
        op, &srb_handle->block_size);

    globus_gridftp_server_begin_transfer(op, 0, srb_handle);

    globus_mutex_lock(&srb_handle->mutex);
    {
        finish = globus_l_gfs_srb_read_from_net(srb_handle);
    }
    globus_mutex_unlock(&srb_handle->mutex);

    if(finish)
    {
        globus_gridftp_server_finished_transfer(
            srb_handle->op, srb_handle->cached_res);
    }
    return;

error:
    globus_free(collection);
alloc_error:
    globus_gridftp_server_finished_transfer(op, result);
}



/*************************************************************************
 *         logic for the remaining commands
 *         --------------------------------
 ************************************************************************/



/*************************************************************************
 *  start
 *  -----
 *  This function is called when a new session is initialized, ie a user 
 *  connectes to the server.  This hook gives the dsi an oppertunity to
 *  set internal state that will be threaded through to all other
 *  function calls associated with this session.  And an oppertunity to
 *  reject the user.
 *
 *  finished_info.info.session.session_arg should be set to an DSI
 *  defined data structure.  This pointer will be passed as the void *
 *  user_arg parameter to all other interface functions.
 * 
 *  NOTE: at nice wrapper function should exist that hides the details 
 *        of the finished_info structure, but it currently does not.  
 *        The DSI developer should jsut follow this template for now
 ************************************************************************/
static
void
globus_l_gfs_srb_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    globus_l_gfs_srb_handle_t *         srb_handle;
    globus_gfs_finished_info_t          finished_info;
    char *                              srbUserStr;
    char *                              user_name;
    char *                              domain_name = "";
    globus_result_t                           result;
    char *                              tmp_str;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_srb_start);

    if(session_info->del_cred == NULL)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("must be GSSAPI auth for SRB backend");
        goto error;
    }

    srb_handle = (globus_l_gfs_srb_handle_t *)
        globus_calloc(sizeof(globus_l_gfs_srb_handle_t), 1);
    if(srb_handle == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB start: malloc failed");
        goto error;
    }

    globus_mutex_init(&srb_handle->mutex, NULL);
    globus_fifo_init(&srb_handle->rh_q);

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = srb_handle;
    finished_info.info.session.username = session_info->username;

    aid_import_credential(session_info->del_cred);

    tmp_str = srb_l_default_hostname;
    if(tmp_str == NULL)
    {
        result = GlobusGFSErrorGeneric(
            "srbConnect failed.  setenv GLOBUS_SRB_HOSTNAME properly");
        goto hostname_error;
    }
    srb_handle->port = "";
    srb_handle->hostname = strdup(tmp_str);
    tmp_str = strchr(srb_handle->hostname, ':');
    if(tmp_str != NULL)
    {
        *tmp_str = '\0';
        srb_handle->port = tmp_str + 1;
    }
    srb_handle->srb_dn = srb_l_default_hostname_dn;
    if(srb_handle->srb_dn == NULL)
    {
        srb_handle->srb_dn = "";
    }

    user_name = strdup(session_info->username);
    tmp_str = strchr(user_name, '@');
    if(tmp_str != NULL)
    {
        *tmp_str = '\0';
        domain_name = tmp_str + 1;
    }

    srb_handle->conn = srbConnect(
           srb_handle->hostname,
           srb_handle->port,
           "",
           user_name,
           domain_name,
           "GSI_AUTH",
           srb_handle->srb_dn);
    if(clStatus(srb_handle->conn) != CLI_CONNECTION_OK)
    {
        char *                          aid_str = "";
#       if defined(WITH_PATCHED_SRB)
        {
            aid_str = aidi_get_last_message();
        }
#       endif
        tmp_str = globus_common_create_string(
            "srbConnect failed::\n  host '%s': port '%s': user '%s': domain '%s': srb DN '%s'\n%s",
            srb_handle->hostname, srb_handle->port, user_name, domain_name,
            srb_handle->srb_dn, aid_str);
        result = globus_l_gfs_srb_make_error(
            tmp_str, srb_handle->conn, clStatus(srb_handle->conn)); 
        goto handle_alloc_error;
    }
    free(user_name);

    rc = srbGetUserByDn(srb_handle->conn, 0, 0,
        session_info->subject, &srbUserStr);
    if(rc < 0)
    {
        tmp_str = globus_common_create_string(
            "getUserByDn() failed::  subject '%s' rc = %d\n",
            session_info->subject, rc);
        result = globus_l_gfs_srb_make_error(
            tmp_str, srb_handle->conn, clStatus(srb_handle->conn)); 
        goto handle_alloc_error;
    }

    /* allocate mem for the strings */
    srb_handle->zone = strdup(srbUserStr);
    free(srbUserStr);
    tmp_str = strchr(srb_handle->zone, ':');
    if(tmp_str == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB error, bad user dn");
        goto handle_alloc_error;
    }
    *tmp_str = '\0';
    srb_handle->user = tmp_str + 1;
    tmp_str = strchr(srb_handle->user, '@');
    if(tmp_str == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB error, bad user dn");
        goto zone_alloc_error;
    }
    *tmp_str = '\0';
    srb_handle->domain = tmp_str + 1;

    finished_info.info.session.home_dir = globus_common_create_string(
        "/%s/home/%s.%s",
        srb_handle->zone, srb_handle->user, srb_handle->domain);

    srb_handle->stor_sys_type = UNIX_FT;

    globus_gridftp_server_operation_finished(op, GLOBUS_SUCCESS, &finished_info);
    globus_free(finished_info.info.session.home_dir);

    return;

zone_alloc_error:
handle_alloc_error:
hostname_error:
error:
    globus_gridftp_server_operation_finished(op, result, &finished_info);

}

/*************************************************************************
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 *  The dsi should clean up all memory they associated wit the session
 *  here. 
 ************************************************************************/
static
void
globus_l_gfs_srb_destroy(
    void *                              user_arg)
{
    globus_l_gfs_srb_handle_t *       srb_handle;

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    globus_mutex_destroy(&srb_handle->mutex);
    globus_fifo_destroy(&srb_handle->rh_q);
    clFinish(srb_handle->conn);

    if(srb_handle->hostname != NULL)
    {
        free(srb_handle->hostname);
    }
    if(srb_handle->zone != NULL)
    {
        free(srb_handle->zone);
    }
    globus_free(srb_handle);
}

#ifdef SRBSTAT2
static
void
globus_l_gfs_srb_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count;
    int                                 rc;
    globus_result_t                     result;
    globus_l_gfs_srb_handle_t *         srb_handle;
    GlobusGFSName(globus_l_gfs_srb_stat);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    rc = srb_l_stat_dir(
        srb_handle->conn, &stat_array, &stat_count, stat_info->pathname);
    if(rc != 0)
    {
        result = globus_l_gfs_srb_make_error(
            "stat error", srb_handle->conn, rc);
        goto error;
    }
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);

    return;
error:

    globus_gridftp_server_finished_stat(op, result, NULL, 0);
}

#else

static
void
globus_l_gfs_srb_stat_cpy(
    char *                              name,
    globus_gfs_stat_t *                 stat_array,
    struct stat *                       statbuf)
{
    stat_array[0].name = strdup(name);
    stat_array[0].mode = statbuf->st_mode;
    stat_array[0].nlink = statbuf->st_nlink;
    stat_array[0].uid = statbuf->st_uid;
    stat_array[0].gid = statbuf->st_gid;
    stat_array[0].size = statbuf->st_size;

    stat_array[0].mtime = statbuf->st_mtime;
    stat_array[0].atime = statbuf->st_atime;
    stat_array[0].ctime = statbuf->st_ctime;

    stat_array[0].dev = statbuf->st_dev;
    stat_array[0].ino = statbuf->st_ino;
}

/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs 
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that 
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
static
void
globus_l_gfs_srb_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    int                                 status;
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count = 1;
    globus_l_gfs_srb_handle_t *         srb_handle;
    struct stat                         statbuf;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_srb_stat);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    /* first test for obvious directories */
    srb_l_reduce_path(stat_info->pathname);
    globus_gfs_log_message(
        GLOBUS_GFS_LOG_INFO,
        "globus_l_gfs_srb_stat() : %s\n", stat_info->pathname);

    status = srbObjStat(
        srb_handle->conn, MDAS_CATALOG, stat_info->pathname, &statbuf);
    if(status < 0)
    {
        result = globus_l_gfs_srb_make_error(
            "stat failed", srb_handle->conn, status);
        goto error;
    }
    globus_gfs_log_message(
        GLOBUS_GFS_LOG_INFO,
        "globus_l_gfs_srb_stat() : srbObjStat Success\n");
    /* srbFileStat */
    if(!S_ISDIR(statbuf.st_mode) || stat_info->file_only)
    {
        globus_gfs_log_message(
            GLOBUS_GFS_LOG_INFO,
            "globus_l_gfs_srb_stat() : single file\n");
        stat_array = (globus_gfs_stat_t *) globus_calloc(
            1, sizeof(globus_gfs_stat_t));
        globus_l_gfs_srb_stat_cpy(stat_info->pathname,stat_array,&statbuf);
    }
    else
    {
        int                             rc;

        rc = srb_l_stat_dir(
            srb_handle->conn, &stat_array, &stat_count, stat_info->pathname);
        if(rc != 0)
        {
            result = globus_l_gfs_srb_make_error(
                "stat error", srb_handle->conn, rc);
            goto error;
        }
    }

    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    /* gota free the names */
    for(i = 0; i < stat_count; i++)
    {
        globus_free(stat_array[i].name);
    }
    globus_free(stat_array);
    return;

error_free:
    for(i = 0; i < stat_count; i++)
    {
        globus_free(stat_array[i].name);
    }
    globus_free(stat_array);
error:
    globus_gfs_log_message(
        GLOBUS_GFS_LOG_INFO,
        "globus_l_gfs_srb_stat() : srbObjStat Failed\n");
    globus_gridftp_server_finished_stat(op, result, NULL, 0);
}

#endif

/*************************************************************************
 *  command
 *  -------
 *  This interface function is called when the client sends a 'command'.
 *  commands are such things as mkdir, remdir, delete.  The complete
 *  enumeration is below.
 *
 *  To determine which command is being requested look at:
 *      cmd_info->command
 *
 *      GLOBUS_GFS_CMD_MKD = 1,
 *      GLOBUS_GFS_CMD_RMD,
 *      GLOBUS_GFS_CMD_DELE,
 *      GLOBUS_GFS_CMD_RNTO,
 *      GLOBUS_GFS_CMD_CKSM,
 *      GLOBUS_GFS_CMD_SITE_CHMOD
 ************************************************************************/
static
void
globus_l_gfs_srb_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    int                                 status;
    int                                 len;
    globus_l_gfs_srb_handle_t *         srb_handle;
    char *                              frm_collection;
    char *                              frm_object;
    char *                              collection;
    char *                              object;
    char *                              tmp_ptr;
    globus_result_t                     result;
    char *                              error_str;
    GlobusGFSName(globus_l_gfs_srb_command);

    srb_handle = (globus_l_gfs_srb_handle_t *) user_arg;

    collection = strdup(cmd_info->pathname);
    if(collection == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: strdup failed");
        goto alloc_error;
    }
    len = strlen(collection);
    if(collection[len - 1] == '/')
    {
        len--;
        collection[len] = '\0';
    }
    tmp_ptr = strrchr(collection, '/');
    if(tmp_ptr == NULL)
    {
        result = GlobusGFSErrorGeneric("SRB: bad collection name");
        goto error;
    }
    *tmp_ptr = '\0';
    object = tmp_ptr + 1;

    switch(cmd_info->command)
    {
        case GLOBUS_GFS_CMD_MKD:
            status = srbCreateCollect(
                srb_handle->conn, MDAS_CATALOG, collection, object);
            globus_gfs_log_message(
                GLOBUS_GFS_LOG_INFO,
                "globus_l_gfs_srb_mkdir() : collection=%s object=%s\n",
                collection, object);
            break;

        case GLOBUS_GFS_CMD_RMD:
            status = srbModifyCollect(
                srb_handle->conn, MDAS_CATALOG,
                cmd_info->pathname, "", "", "", D_DELETE_COLL);
            break;

        case GLOBUS_GFS_CMD_DELE:
            status = srbObjUnlink(srb_handle->conn, object, collection);
            break;

        case GLOBUS_GFS_CMD_RNTO:
            frm_collection = strdup(cmd_info->rnfr_pathname);
            if(frm_collection == NULL)
            {
                result = GlobusGFSErrorGeneric("SRB: strdup failed");
                goto error;
            }
            tmp_ptr = strrchr(frm_collection, '/');
            if(tmp_ptr == NULL)
            {
                free(frm_collection);
                result = GlobusGFSErrorGeneric("SRB: bad collection name");
                goto error;
            }
            *tmp_ptr = '\0';
            frm_object = tmp_ptr + 1;

            status = srbModifyDataset(
                srb_handle->conn,
                MDAS_CATALOG,
                frm_object,
                frm_collection,
                "", "",
                object,
                collection,
                D_CHANGE_DNAME);
            free(frm_collection);
            break;

        case GLOBUS_GFS_CMD_CKSM:
            break;

        case GLOBUS_GFS_CMD_SITE_CHMOD:
            status = 0;
            break;

        default:
            break;
    }

    if(status != 0)
    {
        error_str = globus_common_create_string("SRB error: status = %d : %s",
            status, clErrorMessage(srb_handle->conn));
        result = GlobusGFSErrorGeneric(error_str);

        goto error;
    }

    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);

    free(collection);
    return;

error:
    free(collection);
alloc_error:
    globus_gridftp_server_finished_command(op, result, NULL);
}


static
int
globus_l_gfs_srb_activate(void);

static
int
globus_l_gfs_srb_deactivate(void);

/*
 *  no need to change this
 */
static globus_gfs_storage_iface_t       globus_l_gfs_srb_dsi_iface = 
{
    GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    globus_l_gfs_srb_start,
    globus_l_gfs_srb_destroy,
    NULL, /* list */
    globus_l_gfs_srb_send,
    globus_l_gfs_srb_recv,
    NULL, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    globus_l_gfs_srb_command, 
    globus_l_gfs_srb_stat,
    NULL,
    NULL
};

/*
 *  no need to change this
 */
GlobusExtensionDefineModule(globus_gridftp_server_srb) =
{
    "globus_gridftp_server_srb",
    globus_l_gfs_srb_activate,
    globus_l_gfs_srb_deactivate,
    NULL,
    NULL,
    &local_version
};

/*
 *  no need to change this
 */
static
int
globus_l_gfs_srb_activate(void)
{
    char *                              gl;
    char *                              srb_config_file;
    globus_srb_options_handle_t         opts_h;

    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "srb",
        GlobusExtensionMyModule(globus_gridftp_server_srb),
        &globus_l_gfs_srb_dsi_iface);

#   if defined(WITH_PATCHED_SRB)
    {
        fptr = fopen("/dev/null", "w");
        aidi_set_logptr(fptr);
    }
#   endif

    gl = globus_libc_getenv("GLOBUS_LOCATION");
    if(gl == NULL)
    {
        /* TODO, log an error */
        gl = "";
    }
    srb_config_file = globus_common_create_string("%s/etc/gridftp_srb.conf",
        globus_libc_getenv("GLOBUS_LOCATION"));

    globus_srb_options_init(
        &opts_h, srb_l_opts_unknown, NULL, srb_l_opts_table);
    globus_srb_options_file_process(opts_h, srb_config_file);
    globus_srb_options_env_process(opts_h);
    globus_srb_options_destroy(opts_h);
    globus_free(srb_config_file);

    return 0;
}

/*
 *  no need to change this
 */
static
int
globus_l_gfs_srb_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "srb");

    return 0;
}
