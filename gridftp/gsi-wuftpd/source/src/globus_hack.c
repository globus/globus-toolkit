#define OUTSTANDING_READ_COUNT                      4

#include <setjmp.h>
#include "config.h"
#include "proto.h"
#include "../support/ftp.h"

#if defined(USE_GLOBUS_DATA_CODE)


#if defined(USE_LONGJMP)
#define wu_longjmp(x, y)        longjmp((x), (y))
#define wu_setjmp(x)            setjmp(x)
#ifndef JMP_BUF
#define JMP_BUF                 jmp_buf
#endif
#else
#define wu_longjmp(x, y)        siglongjmp((x), (y))
#define wu_setjmp(x)            sigsetjmp((x), 1)
#ifndef JMP_BUF
#define JMP_BUF                 sigjmp_buf
#endif
#endif

typedef struct globus_i_wu_montor_s
{
    globus_mutex_t             mutex;
    globus_cond_t              cond;
    globus_bool_t              done;
    int                        count;
    int                        fd;
} globus_i_wu_montor_t;

/*
 *  global varials from ftpd.c
 */
extern int logged_in;
extern JMP_BUF urgcatch;
extern int transflag;
extern int retrieve_is_data;
extern int type;
extern unsigned int timeout_data;
extern int data_count_total;
extern int data_count_in;
extern int data_count_out;
extern int byte_count_total;
extern int byte_count_in;
extern int byte_count_out;
extern off_t file_size;
extern off_t byte_count;
extern int file_count_total;
extern int file_count_in;
extern int file_count_out;
extern int xfer_count_total;
extern int xfer_count_in;
extern int xfer_count_out;
extern FILE * bean_bag;

/**********************************************************n
 * local function prototypes
 ************************************************************/
void
connect_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error);

void
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof);

void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof);

void 
data_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error);

/*************************************************************
 *   global vairables 
 ************************************************************/
static globus_bool_t                            g_timeout_occured;
globus_ftp_control_handle_t                     g_data_handle;


void
wu_monitor_init(
    globus_i_wu_montor_t *                      mon)
{
    globus_mutex_init(&mon->mutex, GLOBUS_NULL);
    globus_cond_init(&mon->cond, GLOBUS_NULL);
    mon->done = GLOBUS_FALSE;
    mon->count = 0;
}

void
wu_monitor_destroy(
    globus_i_wu_montor_t *                      mon)
{
    globus_mutex_destroy(&mon->mutex);
    globus_cond_destroy(&mon->cond);
}

void
g_passive()
{
    globus_result_t                             res;
    globus_ftp_control_host_port_t              host_port;
    int                                         hi;
    int                                         low;

    if (!logged_in)   
    {
        reply(530, "Login with USER first.");
        return;
    }

    res = globus_ftp_control_local_pasv(
              &g_data_handle,
              &host_port);
    if(res != GLOBUS_SUCCESS)
    {
        perror_reply(425, "Can't open passive connection");
    }

    hi = host_port.port / 256;
    low = host_port.port % 256;

    reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", 
          host_port.host[0],
          host_port.host[1],
          host_port.host[2],
          host_port.host[3],
          hi,
          low);
}


/*
 *  what to do if it times out
 *
 *  send error message on control connection
 */
static SIGNAL_TYPE 
g_alarm_signal(
    int                                             sig)
{
    g_timeout_occured = GLOBUS_TRUE;
}


/*
 *  globusified send data routine
 */
int
#ifdef THROUGHPUT
g_send_data(
    char *                                          name,
    FILE *                                          instr,
    globus_ftp_control_handle_t *                   handle,
    off_t                                           blksize,
    off_t                                           length)
#else
g_send_data(
    FILE *                                          instr,
    globus_ftp_control_handle_t *                   handle,
    off_t                                           blksize,
    off_t                                           length)
#endif
{
    int                                             jb_count;
    int                                             jb_i;
    register int                                    c;
    register int                                    cnt = 0;
    globus_byte_t *                                 buf;
    int                                             filefd;
    globus_bool_t                                   eof = GLOBUS_FALSE;
    globus_i_wu_montor_t                            monitor;
    int                                             cb_count = 0;
    globus_result_t                                 res;
    int                                             buffer_ndx;
    int                                             file_ndx;
#ifdef THROUGHPUT
    int                                             bps;
    double                                          bpsmult;
    time_t                                          t1;
    time_t                                          t2;
#endif

#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
#endif

fprintf(bean_bag, "using globus send\n");
    wu_monitor_init(&monitor);

    res = globus_ftp_control_data_connect_write(
              handle,
              connect_callback,
              (void *)&monitor);
    if(res != GLOBUS_SUCCESS)
    {
    }

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    g_timeout_occured = GLOBUS_FALSE;
    /* 
     *  what the heck is this 
     *  ??????? 
     */
    if (wu_setjmp(urgcatch))
    {
        alarm(0);
        transflag = 0;
        retrieve_is_data = 1;

        goto clean_exit;
    }
    transflag++;
    switch (type) 
    {

    case TYPE_A:

        /*
         *  set a timeout
         */
        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

        if ((buf = (globus_byte_t *) globus_malloc(blksize)) == NULL)  
        {
            transflag = 0;
            perror_reply(451, "Local resource failure: malloc");
            retrieve_is_data = 1;

            goto clean_exit;
        }

        jb_count = 0;
        buffer_ndx = 0;
        while ((jb_count < length || length == -1) &&
               ((c = getc(instr)) != EOF) &&
               !eof)
        {

            /*
             *  reset timeout every 4096 bytes
             */
            if (++byte_count % 4096 == 0)
            {
                (void) signal(SIGALRM, g_alarm_signal);
                alarm(timeout_data);
            }
            if (c == '\n')
            {
                buf[buffer_ndx] = '\r';
                buffer_ndx++;
                jb_count++;
#               ifdef TRANSFER_COUNT
                {
                    if (retrieve_is_data)
                    {
                        data_count_total++;
                        data_count_out++;
                    }
                    byte_count_total++;
                    byte_count_out++;
                }
#               endif
            }
            if(jb_count++ == length)
            {
                eof = GLOBUS_TRUE;
            }
            file_ndx++;
            buf[buffer_ndx] = c;
            buffer_ndx++;
#           ifdef TRANSFER_COUNT
            {
                if (retrieve_is_data)
                {
                    data_count_total++;
                    data_count_out++;
                }
                byte_count_total++;
                byte_count_out++;
            }
#           endif

            /* 
             *  if the buffer is full send it
             */
            if(buffer_ndx == blksize)
            {
                (void) signal(SIGALRM, g_alarm_signal);
                alarm(timeout_data);

                res = globus_ftp_control_data_write(
                          handle,
                          buf,
                          buffer_ndx,
                          file_ndx,
                          eof,
                          data_write_callback,
                          &monitor);
                if(res != GLOBUS_SUCCESS)
                { 
                    goto data_err;
                }
                cb_count++;

                if ((buf = (globus_byte_t *) globus_malloc(blksize)) == NULL)  
                {
                    transflag = 0;
                    perror_reply(451, "Local resource failure: malloc");
                    retrieve_is_data = 1;
            
                    goto clean_exit;
                }

                buffer_ndx = 0;
            }
        }

        /*
         *  send eof
         */
        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

        res = globus_ftp_control_data_write(
                  handle,
                  buf,
                  buffer_ndx,
                  file_ndx,
                  GLOBUS_TRUE,
                  data_write_callback,
                  &monitor);
        if(res != GLOBUS_SUCCESS)
        { 
            goto data_err;
        } 
        cb_count++;
        buf = GLOBUS_NULL;

        if(g_timeout_occured)
        {
            goto data_err;
        }

        /*
         *  wait until the eof callback is received
         */
        globus_mutex_lock(&monitor.mutex);
        {   
            while(monitor.count < cb_count)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);

        transflag = 0;
 
        if (ferror(instr))
        {
            goto file_err;
        }

        /*
         *  unset no alarm
         */
        alarm(0);
        reply(226, "Transfer complete.");

#       ifdef TRANSFER_COUNT
        {
            if (retrieve_is_data) 
            {
                file_count_total++;
                file_count_out++;
            }
            xfer_count_total++;
            xfer_count_out++;
        }
#       endif

        retrieve_is_data = 1;

        /*
         * EXIT POINT
         */
        goto clean_exit;

    case TYPE_I:
    case TYPE_L:

#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                blksize = bps;
            }
        }
#       endif

        filefd = fileno(instr);

        /*
         *  set alarm
         */
        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                t1 = time(NULL);
            }
       }
#      endif

        jb_count = 0;
        while (jb_count < length || length == -1)
        {
            /*
             *  allocate a buffer for each send
             */
            if ((buf = (char *) globus_malloc(blksize)) == NULL)  
            {
                transflag = 0;
                perror_reply(451, "Local resource failure: malloc");
                retrieve_is_data = 1;
                return (0);
            }

            if(length == -1 || length - jb_count >= blksize)
            {
                jb_i = blksize;
            }
            else
            {
                jb_i = length - jb_count;
            }

            /* modified by JB */
            cnt = read(filefd, buf, jb_i);
            if(cnt <= 0)
            {
                break;
            }

            res = globus_ftp_control_data_write(
                      handle,
                      buf,
                      cnt,
                      jb_count,
                      GLOBUS_FALSE,
                      data_write_callback,
                      &monitor);
            if(res != GLOBUS_SUCCESS)
            {
                goto data_err;
            }
            cb_count++;

            jb_count += cnt;

            /*
             *  reset the alarm
             */
            (void) signal(SIGALRM, g_alarm_signal);
            alarm(timeout_data);

            byte_count += cnt;
#           ifdef TRANSFER_COUNT
            {
                if (retrieve_is_data)
                {
#                   ifdef RATIO
                    {
                        if(freefile)
                        {
                            total_free_dl += cnt;
                        }
                    }
#                   endif /* RATIO */

                    data_count_total += cnt;
                    data_count_out += cnt;
                }
                byte_count_total += cnt;
                byte_count_out += cnt;

            }    
#           endif

#           ifdef THROUGHPUT
            {
                if (bps != -1)
                {
                    t2 = time(NULL);
                    if (t2 == t1)
                    {
                        sleep(1);
                    }
                    t1 = time(NULL);
                }
            }
#           endif
        } /* end while */

        if(jb_count == length && length != -1)
        {
            cnt = 0;
        }
#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                throughput_adjust(name);
            }
        }
#       endif

        transflag = 0;

        res = globus_ftp_control_data_write(
                  handle,
                  buf,
                  cnt,
                  jb_count,
                  GLOBUS_TRUE,
                  data_write_callback,
                  &monitor);
        if(res != GLOBUS_SUCCESS)
        {
            goto data_err;
        }
        cb_count++;
        /*
         *  wait until the eof callback is received
         */
        globus_mutex_lock(&monitor.mutex);
        {   
            while(monitor.count < cb_count)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);

        if (cnt != 0) 
        {
            if (cnt < 0)
            {
                goto file_err;
            }
            goto data_err;
        }

        if(g_timeout_occured)
        {
            goto data_err;
        }

        /* 
         *  unset alarm 
         */
        alarm(0);
        reply(226, "Transfer complete.");

#       ifdef TRANSFER_COUNT
        {
            if (retrieve_is_data) 
            {
                file_count_total++;
                file_count_out++;
            }
            xfer_count_total++;
            xfer_count_out++;
        }
#       endif
 
        retrieve_is_data = 1;

        /*
         *  EXIT POINT 
         */
        goto clean_exit;


    default:
        transflag = 0;
        reply(550, "Unimplemented TYPE %d in send_data", type);
        retrieve_is_data = 1;

        goto clean_exit;
    }

  /* 
   *  DATA_ERR
   */
  data_err:
    alarm(0);
    transflag = 0;

    /*
     *  force close the data connection
     */
    monitor.done = GLOBUS_FALSE;
    res = globus_ftp_control_data_force_close(
              handle,
              data_close_callback,
              (void*)&monitor);

    /*
     *  wait for all the callbacks and the close callback 
     */
    globus_mutex_lock(&monitor.mutex);
    {   
        while(!monitor.done || monitor.count < cb_count)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    if(buf != GLOBUS_NULL)
    {
        globus_free(buf);
    }

    perror_reply(426, "Data connection");
    retrieve_is_data = 1;

    return (0);

  /*
   *  FILE_ERR
   */
  file_err:
    alarm(0);
    transflag = 0;
    perror_reply(551, "Error on input file");
    retrieve_is_data = 1;

  clean_exit:
    wu_monitor_destroy(&monitor);

    return (0);
}

void 
data_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error)
{
    globus_i_wu_montor_t *                      monitor;

    monitor = (globus_i_wu_montor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}


void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof)
{
    globus_i_wu_montor_t *                         monitor;

    monitor = (globus_i_wu_montor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->count++;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);

    globus_free(buffer);
}

/*
 *  globus hacked receive data
 *  --------------------------
 */
int 
g_receive_data(
    globus_ftp_control_handle_t *            handle,
    FILE *                                   outstr)
{
    register int                             c;
    int                                      cnt = 0;
    int                                      bare_lfs = 0;
    globus_byte_t *                          buf;
    int                                      netfd;
    int                                      filefd;
    globus_bool_t                            eof = GLOBUS_FALSE;
    globus_i_wu_montor_t                     monitor;
    globus_result_t                          res;
    int                                      ctr;
    int                                      cb_count = 0;
#ifdef BUFFER_SIZE
    size_t                                   buffer_size = BUFFER_SIZE;
#else
    size_t                                   buffer_size = BUFSIZ;
#endif

    wu_monitor_init(&monitor);

    res = globus_ftp_control_data_connect_read(
              handle,
              connect_callback,
              (void *)&monitor);
    if(res != GLOBUS_SUCCESS)
    {
    }

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    if (wu_setjmp(urgcatch))
    {
        alarm(0);
        transflag = 0;
        if (buf)
        {
            (void) free(buf);
        }
        return (-1);
    }
    transflag++;
    switch (type) 
    {

    case TYPE_I:
    case TYPE_L:
    case TYPE_A:

    /* the globus code should handle ascii mode */

        filefd = fileno(outstr);

        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

        monitor.count = 0;
        monitor.fd = filefd;
        /* TODO: serval outstanding reads at once */
        for(ctr = 0; ctr < OUTSTANDING_READ_COUNT; ctr++)
        {
            if ((buf = (globus_byte_t *) globus_malloc(buffer_size)) == NULL)
            {
                transflag = 0;
                perror_reply(451, "Local resource failure: malloc");
                return (-1);
            }
            res = globus_ftp_control_data_read(
                      handle,
                      buf,
                      buffer_size,
                      data_read_callback,
                      (void *)&monitor);
            if(res != GLOBUS_SUCCESS)
            {
                globus_free(buf);
                goto data_err;
            }
            cb_count++;
        }

        globus_mutex_lock(&monitor.mutex);
        {
            while(!monitor.done && monitor.count < cb_count)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);
        
   
        if(monitor.done || g_timeout_occured)
        {
            goto data_err;
        }

        transflag = 0;

        alarm(0);
#       ifdef TRANSFER_COUNT
        {
            file_count_total++;
            file_count_in++;
            xfer_count_total++;
            xfer_count_in++;
        }
#       endif

        return (0);

    case TYPE_E:
        reply(553, "TYPE E not implemented.");
        transflag = 0;
        return (-1);

    default:
        reply(550, "Unimplemented TYPE %d in receive_data", type);
        transflag = 0;
        return (-1);
    }

  data_err:
    /*
     *  force close the data connection
     */
    monitor.done = GLOBUS_FALSE;
    res = globus_ftp_control_data_force_close(
              handle,
              data_close_callback,
              (void*)&monitor);

    /*
     *  wait for all the callbacks and the close callback 
     */
    globus_mutex_lock(&monitor.mutex);
    {   
        while(!monitor.done || monitor.count < cb_count)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    alarm(0);
    transflag = 0;
    perror_reply(426, "Data Connection");
    return (-1);

  file_err:
    alarm(0);
    transflag = 0;
    perror_reply(452, "Error writing file");
    return (-1);
}

void
connect_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_object_t *                           error)
{
    globus_i_wu_montor_t *                      monitor;

    monitor = (globus_i_wu_montor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
         reply(150, "Opening %s mode data connection.",
               type == TYPE_A ? "ASCII" : "BINARY");

         monitor->done = GLOBUS_TRUE;
         globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_size_t                               offset,
    globus_bool_t                               eof)
{
    globus_i_wu_montor_t *                      monitor;
    globus_result_t                             res;
#ifdef BUFFER_SIZE
    size_t                                      buffer_size = BUFFER_SIZE;
#else
    size_t                                      buffer_size = BUFSIZ;
#endif

    monitor = (globus_i_wu_montor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
            monitor->done = GLOBUS_TRUE;
            globus_cond_signal(&monitor->cond);
            globus_mutex_unlock(&monitor->mutex);

            return;
        }

        if(length > 0)
        {
            lseek(monitor->fd, offset, SEEK_SET);
            write(monitor->fd, buffer, length);
            byte_count += length;
#           ifdef TRANSFER_COUNT
            {
                data_count_total += length;
                data_count_in += length;
                byte_count_total += length;
                byte_count_in += length;
            }
#           endif
        }

        if(eof)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
            globus_free(buffer);
        }
        else
        {
            res = globus_ftp_control_data_read(
                      handle,
                      buffer,
                      buffer_size,
                      data_read_callback,
                      (void *)&monitor);
            if(res != GLOBUS_SUCCESS)
            {
                globus_free(buffer);
                monitor->done = GLOBUS_TRUE;
                globus_cond_signal(&monitor->cond);
            
                globus_mutex_unlock(&monitor->mutex);

                return;
            }
        }

        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);
    }
    globus_mutex_unlock(&monitor->mutex);
}

#endif /* USE_GLOBUS_DATA_CODE */
