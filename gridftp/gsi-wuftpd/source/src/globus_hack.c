globus_ftp_control_handle_t                              g_data_handle;

void
passive()
{
}

static globus_bool_t                                   g_timeout_occured;

/*
 *  what to do if it times out
 *
 *  send error message on control connection
 */
static SIGNAL_TYPE 
g_alarm_signal(
    int                                                  sig)
{
    g_timeout_occured = GLOBUS_TRUE;
}


/*
 *  globusified send data routine
 */
int
g_send_data(
    char *                                                name,
    FILE *                                                instr,
    globus_ftp_control_handle_t *                         handle,
    off_t                                                 blksize,
    off_t                                                 length)
{
    int                             jb_count;
    int                             jb_i;
    register int                    c;
    register int                    cnt = 0;
    globus_byte_t *                 buf;
    int                             filefd;
    globus_bool_t                   eof = GLOBUS_FALSE;
    globus_i_wu_montor_t              monitor;
    int                             cb_count = 0;
#ifdef THROUGHPUT
    int                             bps;
    double                          bpsmult;
    time_t                          t1;
    time_t                          t2;
#endif

#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
#endif

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
        return (0);
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
            return (0);
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
                          bufer_ndx,
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
                    return (0);
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
                  bufer_ndx,
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
        return (1);

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
        return (1);


    default:
        transflag = 0;
        reply(550, "Unimplemented TYPE %d in send_data", type);
        retrieve_is_data = 1;
        return (0);
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
receive_data(
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
#ifdef BUFFER_SIZE
    size_t                                   buffer_size = BUFFER_SIZE;
#else
    size_t                                   buffer_size = BUFSIZ;
#endif

    buf = NULL;
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

    /* the globus code should handle ascii mode */
    case TYPE_I:
    case TYPE_L:
    case TYPE_A:


        filefd = fileno(outstr);

        (void) signal(SIGALRM, draconian_alarm_signal);
        alarm(timeout_data);

        monitor.cb_count = 0;
        monitor.outstr = outstr;
        monitor.fd = filefd;
        /* TODO: serval outstanding reads at once */
        for(ctr = 0; ctr < XXXX; ctr++)
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
                      read_data_callback,
                      (void *)&monitor);
            if(res != GLOBUS_SUCCESS)
            {
            }
            monitor.cb_count++;
        }

        globus_mutex_lock(&monitor.mutex);
        {
            while(!monitor.done || monitor.count < monitor.cb_count)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);
        

        transflag = 0;
        if (cnt != 0)
        {
            if (cnt < 0)
                goto data_err;
            goto file_err;
        }
        if (draconian_FILE == NULL)
        {
            goto data_err;
        }
        draconian_FILE = NULL;
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

    monitor = (globus_i_wu_montor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        if(error != GLOBUS_NULL)
        {
        }

        if(length > 0)
        {
            fseek(monitor->fd, offset, SEEK_SET);
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
            globus_cond_signal(&monitor->cond, &monitor->mutex);
            globus_free(buffer);
        }
        else
        {
            res = globus_ftp_control_data_read(
                      handle,
                      buffer,
                      buffer_size,
                      read_data_callback,
                      (void *)&monitor);
            if(res != GLOBUS_SUCCESS)
            {
            }
        }

        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);
    }
    globus_mutex_unlock(&monitor->mutex);
}

