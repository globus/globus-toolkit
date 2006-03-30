/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_xio_netlogger.h"
#include "globus_xio_driver.h"
#include <stdarg.h>
#include "version.h"
#include "nl_log.h"

#define GlobusXIONetloggerError(_r)                                         \
    globus_error_put(GlobusXIONetloggerErrorObj(_r))

#define GlobusXIONetloggerErrorObj(_reason)                                 \
    globus_error_construct_error(                                           \
        GLOBUS_XIO_MODULE,                                                  \
        GLOBUS_NULL,                                                        \
        1,                                                                  \
        __FILE__,                                                           \
        _xio_name,                                                          \
        __LINE__,                                                           \
        _XIOSL(_reason))                                

GlobusDebugDefine(GLOBUS_XIO_NETLOGGER);
GlobusXIODeclareDriver(netlogger);

#define GlobusXIONetloggerDebugPrintf(level, message)                      \
    GlobusDebugPrintf(GLOBUS_XIO_NETLOGGER, level, message)

#define GlobusXIONetloggerDebugEnter()                                     \
    GlobusXIONetloggerDebugPrintf(                                         \
        GLOBUS_L_XIO_NETLOGGER_DEBUG_TRACE,                                \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIONetloggerDebugExit()                                      \
    GlobusXIONetloggerDebugPrintf(                                         \
        GLOBUS_L_XIO_NETLOGGER_DEBUG_TRACE,                                \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIONetloggerDebugExitWithError()                             \
    GlobusXIONetloggerDebugPrintf(                                         \
        GLOBUS_L_XIO_NETLOGGER_DEBUG_TRACE,                                \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_netlogger_error_levels
{
    GLOBUS_L_XIO_NETLOGGER_DEBUG_TRACE                = 1,
    GLOBUS_L_XIO_NETLOGGER_DEBUG_INTERNAL_TRACE       = 2,
    GLOBUS_L_XIO_NETLOGGER_DEBUG_CNTLS                = 4
};

#define NL_XIO_ID_FLD                   4
#define NL_XIO_TYPE_FLD                 5
#define NL_XIO_BUFLEN_FLD               6
#define NL_XIO_BYTES_FLD                7

#define NL_XIO_RECSZ                    7
#define NL_XIO_B_RECSZ                  8
#define NL_XIO_BB_RECSZ                 9

#define NL_MAXREC 1024
#define ID_FIELD_LEN 64
typedef struct xio_l_netlogger_handle_s
{
    int                                 log_flag;
    int                                 fd;
    char                                id[ID_FIELD_LEN];
    int                                 type;
    NL_rec_t *                          open_start_rec;
    NL_rec_t *                          open_stop_rec;
    NL_rec_t *                          close_start_rec;
    NL_rec_t *                          close_stop_rec;
    NL_rec_t *                          read_start_rec;
    NL_rec_t *                          read_stop_rec;
    NL_rec_t *                          write_start_rec;
    NL_rec_t *                          write_stop_rec;
    NL_rec_t *                          accept_start_rec;
    NL_rec_t *                          accept_stop_rec;

    globus_size_t                       read_buflen;
    globus_size_t                       write_buflen;
    NL_rfmt_t *                         rfp;
    unsigned int                        seq;
    char                                recbuf[NL_MAXREC];
} xio_l_netlogger_handle_t;

xio_l_netlogger_handle_t *     globus_l_xio_netlogger_default_handle = NULL;

static
int
globus_l_xio_nl_sprintf(
    char *buf, const char *event, int level, char *fmt, ...)
{
    NL_fstrm_t *fs_p;
    char *nlbuf;
    int len;
    va_list ap;

    va_start(ap,fmt);
    fs_p = NL_fstrm();
    nlbuf = NL_fstrm_fmt(fs_p, &len, event, level, fmt, ap);
    va_end(ap);

    if(len > 0)
    {
        memcpy(buf,nlbuf,len);
    }
    return len;
}

static
void
xio_l_netlogger_log_transfer(
    int                                 stripe_count,
    int                                 stream_count,
    struct timeval *                    start_t,
    struct timeval *                    end_t,
    char *                              dest_ip,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    const char *                        fname,
    globus_off_t                        nbytes,
    int                                 code,
    char *                              volume,
    char *                              type,
    char *                              username,
    int                                 fd)
{
    int                                 len;
    char                                out_buf[4096];
    long                                win_size;
    char *                              hostname;

    if(tcp_bs == 0)
    {
        win_size = 0;
    }
    else
    {
        win_size = tcp_bs;
    }
    hostname = ipaddr(); /* defined in nl_log.h */
    if(hostname == NULL)
    {
        hostname = strdup("0.0.0.0");
    }

    len = globus_l_xio_nl_sprintf(
        out_buf,
        "gridftp.FTP_INFO",
        NL_LVL_INFO,
        "HOST=s "
        "PROG=s "
        "START.TM=d "
        "END.TM=d "
        "USER=s "
        "FILE=s "
        "BUFFER=l "
        "BLOCK=l "
        "NBYTES=l "
        "VOLUME=s "
        "STREAMS=i "
        "STRIPES=i "
        "DEST=s "
        "TYPE=s "
        "CODE=i",
        /* end time */
        hostname,
        "globus-gridftp-server",
        /* start time */
        start_t->tv_sec + start_t->tv_usec/1e6,
        end_t->tv_sec + end_t->tv_usec/1e6,
        /* other args */
        username,
        fname,
        (long long)win_size,
        (long long) blksize,
        (long long)nbytes,
        volume,
        stream_count,
        stripe_count,
        dest_ip,
        type,
        code);

    write(fd, out_buf, len);
}



static
void
globus_l_xio_nl_addbuflen(
    NL_rec_t *                          recp)
{
    int ival = 0;
    NL_rec_add(recp, NL_fld("buflen", 6,  &ival, sizeof(ival), NL_int));
}

/** Add 'bytes' integer fields to record */
static
void
globus_l_xio_nl_addbytes(
    NL_rec_t *                          recp)
{
    int ival = 0;
    NL_rec_add(recp, NL_fld("bytes", 5,  &ival, sizeof(ival), NL_int));
}


static
NL_rec_t *
globus_l_xio_nl_makerec(
    const char *                        event,
    int                                 size)
{
    int                                 ival = 0;
    char                                sval[NL_MAX_STR];
    char *                              hostname;
    NL_rec_t *                          recp;

    recp = NL_rec(size);
    NL_rec_add(recp, NL_fld(NL_FLD_DATE, NL_FLD_DATE_LEN, sval,
                            sizeof(struct timeval),NL_time));
    NL_rec_add(recp, NL_fld(NL_FLD_LVL, NL_FLD_LVL_LEN, "DEBUG",
                            5, NL_string));
    NL_rec_add(recp, NL_fld(NL_FLD_EVENT, NL_FLD_EVENT_LEN, (char*)event,
                            strlen(event), NL_string));
    hostname = ipaddr(); /* defined in nl_log.h */
    if(NULL == hostname)
    {
        hostname = strdup("0.0.0.0");
    }
    NL_rec_add(recp, NL_fld(NL_FLD_HOST, NL_FLD_HOST_LEN, hostname,
                            strlen(hostname), NL_string));

    NL_rec_add(recp, NL_fld("uuid", 2,  sval, ID_FIELD_LEN, NL_string));
    NL_rec_add(recp, NL_fld("type", 4,  &ival, sizeof(ival), NL_int));

    return recp;
}

static
void
xio_l_netlogger_fmtrec(
    xio_l_netlogger_handle_t *          handle,
    NL_rec_t *                          recp)
{
    int len;
    struct timeval tv;

    if(handle->fd < 0) return;

    gettimeofday(&tv, 0);

    memcpy(recp->fields[NL_XIO_ID_FLD]->value, handle->id, ID_FIELD_LEN);
    memcpy(recp->fields[NL_XIO_TYPE_FLD]->value, &handle->type, sizeof(int));

    memcpy( recp->fields[NL_dtfld]->value, &tv, sizeof(struct timeval));
    len = NL_rfmt_format(handle->rfp, recp, handle->recbuf, NL_MAXREC);
    write(handle->fd, handle->recbuf, len);
}


static
void
xio_l_netlogger_fmtrec_b(
    xio_l_netlogger_handle_t *          handle,
    NL_rec_t *                          recp, 
    int                                 buflen)
{
    int len;
    struct timeval tv;

    if(handle->fd < 0) return;

    gettimeofday(&tv, 0);

    memcpy(recp->fields[NL_XIO_ID_FLD]->value, handle->id, ID_FIELD_LEN);
    memcpy(recp->fields[NL_XIO_TYPE_FLD]->value, &handle->type, sizeof(int));

    memcpy(recp->fields[NL_dtfld]->value, &tv, sizeof(struct timeval));
    memcpy(((recp->fields)[NL_XIO_BUFLEN_FLD])->value, &buflen, sizeof(int));

    memcpy( recp->fields[NL_dtfld]->value, &tv, sizeof(struct timeval));
    len = NL_rfmt_format(handle->rfp, recp, handle->recbuf, NL_MAXREC);
    write(handle->fd, handle->recbuf, len);
}

/** Format a record with a buflen and a bytes field */
static
void
xio_l_netlogger_fmtrec_bb(
    xio_l_netlogger_handle_t *          handle,
    NL_rec_t *                          recp, 
    int                                 buflen, 
    int                                 bytes)
{
    int len;
    struct timeval tv;

    if(handle->fd < 0) return;
    gettimeofday(&tv, 0);

    memcpy(recp->fields[NL_XIO_ID_FLD]->value, handle->id, ID_FIELD_LEN);
    memcpy(recp->fields[NL_XIO_TYPE_FLD]->value, &handle->type, sizeof(int));

    memcpy(((recp->fields)[NL_XIO_BUFLEN_FLD])->value, &buflen, sizeof(int));
    memcpy(((recp->fields)[NL_XIO_BYTES_FLD])->value, &bytes, sizeof(int));

    memcpy( recp->fields[NL_dtfld]->value, &tv, sizeof(struct timeval));
    len = NL_rfmt_format(handle->rfp, recp, handle->recbuf, NL_MAXREC);
    write(handle->fd, handle->recbuf, len);
}


static
xio_l_netlogger_handle_t *
xio_l_netlogger_create_handle()
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(xio_l_netlogger_create_handle);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *)
        globus_calloc(1, sizeof(xio_l_netlogger_handle_t));

    handle->accept_start_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.accept.start",NL_XIO_RECSZ);
    handle->accept_stop_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.accept.end",NL_XIO_RECSZ);

    handle->open_start_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.open.start",NL_XIO_RECSZ);
    handle->open_stop_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.open.end",NL_XIO_RECSZ);

    handle->close_start_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.close.start",NL_XIO_RECSZ);
    handle->close_stop_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.close.end",NL_XIO_RECSZ);

    handle->read_start_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.read.start",NL_XIO_B_RECSZ);
    globus_l_xio_nl_addbuflen(handle->read_start_rec);
    handle->read_stop_rec = 
        globus_l_xio_nl_makerec("xio.XioSocket.read.end",NL_XIO_BB_RECSZ);
    globus_l_xio_nl_addbuflen(handle->read_stop_rec);
    globus_l_xio_nl_addbytes(handle->read_stop_rec);

    handle->write_start_rec =
        globus_l_xio_nl_makerec("xio.XioSocket.write.start",NL_XIO_B_RECSZ);
    globus_l_xio_nl_addbuflen(handle->write_start_rec);
    handle->write_stop_rec =
        globus_l_xio_nl_makerec("xio.XioSocket.write.end",NL_XIO_BB_RECSZ);
    globus_l_xio_nl_addbuflen(handle->write_stop_rec);
    globus_l_xio_nl_addbytes(handle->write_stop_rec);

    handle->rfp = NL_rfmt();
    handle->seq = 0U;

    GlobusXIONetloggerDebugExit();
    return handle;
}

static
int
globus_l_xio_netlogger_activate(void);

static
int
globus_l_xio_netlogger_deactivate(void);

GlobusXIODefineModule(netlogger) =
{
    "globus_xio_netlogger",
    globus_l_xio_netlogger_activate,
    globus_l_xio_netlogger_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_l_xio_netlogger_activate(void)
{
    int rc;
    GlobusXIOName(globus_l_xio_netlogger_activate);

    GlobusDebugInit(GLOBUS_XIO_NETLOGGER, TRACE);
    GlobusXIONetloggerDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(netlogger);

    globus_l_xio_netlogger_default_handle = xio_l_netlogger_create_handle();

    GlobusXIONetloggerDebugExit();
    return GLOBUS_SUCCESS;

error_xio_system_activate:
    GlobusXIONetloggerDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_NETLOGGER);
    return rc;
}

static
int
globus_l_xio_netlogger_deactivate(void)
{   
    int rc;
    GlobusXIOName(globus_l_xio_netlogger_deactivate);
    
    GlobusXIONetloggerDebugEnter();
    GlobusXIOUnRegisterDriver(netlogger);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusXIONetloggerDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_NETLOGGER);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIONetloggerDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_NETLOGGER);
    return rc;
}

static
globus_result_t
globus_l_xio_netlogger_attr_init(
    void **                             out_attr)
{
    xio_l_netlogger_handle_t *          attr;

    /* intiialize everything to 0 */
    attr = xio_l_netlogger_create_handle();
    *out_attr = attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_netlogger_attr_copy(
    void **                             dst,
    void *                              src)
{
    xio_l_netlogger_handle_t *          dst_attr;
    xio_l_netlogger_handle_t *          src_attr;

    src_attr = (xio_l_netlogger_handle_t *) src;
    /* intiialize everything to 0 */
    globus_l_xio_netlogger_attr_init((void **)&dst_attr);

    dst_attr->log_flag = src_attr->log_flag;
    dst_attr->fd = src_attr->fd;
    dst_attr->type = src_attr->type;
    memcpy(dst_attr->id, src_attr->id, ID_FIELD_LEN);
    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_netlogger_parse_opts(
    char *                              in_opts,
    xio_l_netlogger_handle_t *          attr)
{
    int                                 fd;
    int                                 sc;
    int                                 int_val;
    char *                              opts;
    char *                              start_opts;
    char *                              tmp_str;
    char *                              key;
    char *                              val;
    GlobusXIOName(globus_l_xio_netlogger_parse_opts);

    GlobusXIONetloggerDebugEnter();
    if(in_opts == NULL)
    {
        return;
    }
    opts = strdup(in_opts);
    start_opts = opts;

    key = "filename=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = tmp_str + strlen(key);
        fd = open(val, O_WRONLY);
        if(fd > 0)
        {
            attr->fd = fd;
        }
    }

    key = "mask=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = tmp_str + strlen(key);
        sc = sscanf(val, "%d", &int_val);
        if(sc == 1)
        {
            attr->log_flag = int_val;
        }
    }

    key = "type=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = tmp_str + strlen(key);
        sc = sscanf(val, "%d", &int_val);
        if(sc == 1)
        {
            attr->type = int_val;
        }
    }

    key = "id=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = tmp_str + strlen(key);
        tmp_str = strchr(attr->id, '#');
        if(tmp_str != NULL)
        {
            *tmp_str = '\0';
        }
        strcpy(attr->id, val);
    }
    free(start_opts);
    GlobusXIONetloggerDebugExit();
}

static
globus_result_t
globus_l_xio_netlogger_cntl(
    void  *                             driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              str;
    char *                              tmp_str;
    globus_xio_netlogger_log_event_t    event;
    xio_l_netlogger_handle_t *          attr;
    GlobusXIOName(globus_l_xio_netlogger_cntl);

    GlobusXIONetloggerDebugEnter();

    attr = (xio_l_netlogger_handle_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_NETLOGGER_CNTL_EVENT_ON:
            event = va_arg(ap, globus_xio_netlogger_log_event_t);
            attr->log_flag |= event;
            break;

        case GLOBUS_XIO_NETLOGGER_CNTL_EVENT_OFF:
            event = va_arg(ap, globus_xio_netlogger_log_event_t);
            attr->log_flag ^= event;
            break;

        case GLOBUS_XIO_NETLOGGER_CNTL_SET_FD:
            attr->fd = va_arg(ap, int);
            GlobusXIONetloggerDebugPrintf(GLOBUS_L_XIO_NETLOGGER_DEBUG_CNTLS,
                ("GLOBUS_XIO_NETLOGGER_CNTL_SET_FD: %d\n", attr->fd));
            break;

        case GLOBUS_XIO_SET_STRING_OPTIONS:
            str = va_arg(ap, char *);
            GlobusXIONetloggerDebugPrintf(GLOBUS_L_XIO_NETLOGGER_DEBUG_CNTLS,
                ("GLOBUS_XIO_SET_STRING_OPTIONS: %s\n", str));
            globus_l_xio_netlogger_parse_opts(str, attr);
            break;

        case GLOBUS_XIO_NETLOGGER_CNTL_SET_TRANSFER_ID:
            tmp_str = va_arg(ap, char *);
            strcpy(attr->id, tmp_str);
            GlobusXIONetloggerDebugPrintf(GLOBUS_L_XIO_NETLOGGER_DEBUG_CNTLS,
                ("GLOBUS_XIO_NETLOGGER_CNTL_SET_TRANSFER_ID: %s\n", attr->id));
            break;

        case GLOBUS_XIO_NETLOGGER_CNTL_SET_TYPE:
            attr->type = va_arg(ap, int);
            GlobusXIONetloggerDebugPrintf(GLOBUS_L_XIO_NETLOGGER_DEBUG_CNTLS,
              ("GLOBUS_XIO_NETLOGGER_CNTL_SET_TRANSFER_TYPE: %d\n", attr->type));
            break;

        case GLOBUS_XIO_NETLOGGER_CNTL_CHEATER:
            {
                int                     stripe_count;
                int                     stream_count;
                struct timeval *        start_gtd_time;
                struct timeval *        end_gtd_time;
                char *                  dest_ip;
                globus_size_t           blksize;
                globus_size_t           tcp_bs;
                char *                  fname;
                globus_off_t            nbytes;
                int                     code;
                char *                  volume;
                char *                  type;
                char *                  username;
                int                     fd;

                stripe_count = va_arg(ap, int);
                stream_count = va_arg(ap, int);
                start_gtd_time = va_arg(ap, struct timeval *);
                end_gtd_time = va_arg(ap, struct timeval *);
                dest_ip = va_arg(ap, char *);
                blksize = va_arg(ap, globus_size_t);
                tcp_bs = va_arg(ap, globus_size_t);
                fname = va_arg(ap, char *);
                nbytes = va_arg(ap, globus_off_t);
                code = va_arg(ap, int);
                volume = va_arg(ap, char *);
                type = va_arg(ap, char *);
                username = va_arg(ap, char *);
                fd = va_arg(ap, int);

                xio_l_netlogger_log_transfer(
                    stripe_count,
                    stream_count,
                    start_gtd_time,
                    end_gtd_time,
                    dest_ip,
                    blksize,
                    tcp_bs,
                    fname,
                    nbytes,
                    code,
                    volume,
                    type,
                    username,
                    fd);
            }
            break;
    }

    GlobusXIONetloggerDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_netlogger_handle_destroy(
    void *                              driver_attr)
{
    xio_l_netlogger_handle_t *          attr;

    attr = (xio_l_netlogger_handle_t *) driver_attr;
    globus_free(attr);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_netlogger_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          handle;
    xio_l_netlogger_handle_t *          cpy_handle;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_server_init);

    GlobusXIONetloggerDebugEnter();

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
        cpy_handle = (xio_l_netlogger_handle_t *) driver_attr;
    }
    /* else copy the default attr */
    else
    {
        cpy_handle = globus_l_xio_netlogger_default_handle;
    }

    globus_l_xio_netlogger_attr_copy((void **)&handle, (void *)cpy_handle);
    res = globus_xio_driver_pass_server_init(op, contact_info, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }
    GlobusXIONetloggerDebugExit();

    return GLOBUS_SUCCESS;
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;
}

static
void
globus_l_xio_netlogger_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(globus_l_xio_netlogger_accept_cb);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *) user_arg;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_ACCEPT)
    {
        xio_l_netlogger_fmtrec(handle, handle->accept_stop_rec);
    }

    globus_xio_driver_finished_accept(op, user_arg, result);
    GlobusXIONetloggerDebugExit();
}

static
globus_result_t
globus_l_xio_netlogger_accept(
    void *                              driver_server,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          cpy_handle;
    xio_l_netlogger_handle_t *          handle;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_accept);

    GlobusXIONetloggerDebugEnter();

    cpy_handle = (xio_l_netlogger_handle_t *) driver_server;
    globus_l_xio_netlogger_attr_copy((void **)&handle, (void *)cpy_handle);
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_ACCEPT)
    {
        xio_l_netlogger_fmtrec(handle, handle->accept_start_rec);
    }
    res = globus_xio_driver_pass_accept(
        op, globus_l_xio_netlogger_accept_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIONetloggerDebugExit();
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_netlogger_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(globus_l_xio_netlogger_open_cb);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *) user_arg;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_OPEN)
    {
        xio_l_netlogger_fmtrec(handle, handle->open_stop_rec);
    }

    globus_xio_driver_finished_open(user_arg, op, result);
    GlobusXIONetloggerDebugExit();
}


static
globus_result_t
globus_l_xio_netlogger_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          cpy_handle;
    xio_l_netlogger_handle_t *          handle;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_open);

    GlobusXIONetloggerDebugEnter();

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
        cpy_handle = (xio_l_netlogger_handle_t *) driver_attr;
    }
    /* then go to link */
    else if(driver_link != NULL)
    {
        cpy_handle = (xio_l_netlogger_handle_t *) driver_link;
    }
    /* else copy the default attr */
    else
    {
        cpy_handle = globus_l_xio_netlogger_default_handle;
    }
    globus_l_xio_netlogger_attr_copy((void **)&handle, (void *)cpy_handle);

    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_OPEN)
    {
        xio_l_netlogger_fmtrec(handle, handle->open_start_rec);
    }
    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_netlogger_open_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIONetloggerDebugExit();

    return GLOBUS_SUCCESS;
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;
}

static
void
globus_l_xio_netlogger_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(globus_l_xio_netlogger_read_cb);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *) user_arg;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_READ)
    {
        xio_l_netlogger_fmtrec_bb(
            handle, handle->read_stop_rec, handle->read_buflen, nbytes);
    }

    globus_xio_driver_finished_read(op, result, nbytes);
    GlobusXIONetloggerDebugExit();
}


static
globus_result_t
globus_l_xio_netlogger_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          handle;
    globus_size_t                       wait_for;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_read);

    GlobusXIONetloggerDebugEnter();

    handle = (xio_l_netlogger_handle_t *) driver_specific_handle;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_READ)
    {
        GlobusXIOUtilIovTotalLength(handle->read_buflen, iovec, iovec_count);
        xio_l_netlogger_fmtrec_b(
            handle, handle->read_start_rec, handle->read_buflen);
    }
    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_read(op,
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_netlogger_read_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIONetloggerDebugExit();

    return GLOBUS_SUCCESS;
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;
}

static
void
globus_l_xio_netlogger_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(globus_l_xio_netlogger_write_cb);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *) user_arg;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_WRITE)
    {
        xio_l_netlogger_fmtrec_bb(
            handle, handle->write_stop_rec, handle->write_buflen, nbytes);
    }

    globus_xio_driver_finished_write(op, result, nbytes);
    GlobusXIONetloggerDebugExit();
}

static
globus_result_t
globus_l_xio_netlogger_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          handle;
    globus_size_t                       wait_for;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_write);

    GlobusXIONetloggerDebugEnter();

    handle = (xio_l_netlogger_handle_t *) driver_specific_handle;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_WRITE)
    {
        GlobusXIOUtilIovTotalLength(handle->write_buflen, iovec, iovec_count);
        xio_l_netlogger_fmtrec_b(
            handle, handle->write_start_rec, handle->write_buflen);
    }
    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_write(op,
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_netlogger_write_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIONetloggerDebugExit();

    return GLOBUS_SUCCESS;
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;
}

static
void
globus_l_xio_netlogger_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_netlogger_handle_t *          handle;
    GlobusXIOName(globus_l_xio_netlogger_close_cb);

    GlobusXIONetloggerDebugEnter();
    handle = (xio_l_netlogger_handle_t *) user_arg;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_CLOSE)
    {
        xio_l_netlogger_fmtrec(handle, handle->close_stop_rec);
    }

    globus_xio_driver_finished_close(op, result);
    GlobusXIONetloggerDebugExit();
}


static
globus_result_t
globus_l_xio_netlogger_close(
    void *                              driver_handle,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    xio_l_netlogger_handle_t *          handle;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_netlogger_close);

    GlobusXIONetloggerDebugEnter();

    handle = (xio_l_netlogger_handle_t *) driver_handle;
    if(handle->log_flag & GLOBUS_XIO_NETLOGGER_LOG_CLOSE)
    {
        xio_l_netlogger_fmtrec(handle, handle->close_start_rec);
    }
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_netlogger_close_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIONetloggerDebugExit();

    return GLOBUS_SUCCESS;
error_pass:
    GlobusXIONetloggerDebugExitWithError();
    return res;
}

static
globus_result_t
globus_l_xio_netlogger_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_netlogger_init);

    GlobusXIONetloggerDebugEnter();
    result = globus_xio_driver_init(&driver, "netlogger", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_netlogger_open,
        globus_l_xio_netlogger_close,
        globus_l_xio_netlogger_read,
        globus_l_xio_netlogger_write,
        globus_l_xio_netlogger_cntl,
        NULL);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_netlogger_server_init,
        globus_l_xio_netlogger_accept,
        globus_l_xio_netlogger_handle_destroy,
        /* all controls are the same */
        globus_l_xio_netlogger_cntl,
        globus_l_xio_netlogger_cntl,
        globus_l_xio_netlogger_handle_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_netlogger_attr_init,
        globus_l_xio_netlogger_attr_copy,
        /* attr and handle same struct, same controls */
        globus_l_xio_netlogger_cntl,
        globus_l_xio_netlogger_handle_destroy);
    *out_driver = driver;
    GlobusXIONetloggerDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIONetloggerDebugExitWithError();
    return result;
}

static
void
globus_l_xio_netlogger_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    netlogger,
    globus_l_xio_netlogger_init,
    globus_l_xio_netlogger_destroy);
