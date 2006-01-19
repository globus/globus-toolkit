/*
 * Copyright 1999-2006 University of Chicago
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

#include "globus_i_xio_udt.h"

static
globus_bool_t
globus_l_xio_udt_find_read_data_pos(
    globus_l_xio_udt_read_buf_t*        read_buf,
    unsigned char**                     data,
    int                                 offset,
    int                                 len);

static
globus_result_t
globus_l_xio_udt_add_data_to_read_buf(
    globus_l_xio_udt_read_buf_t*        read_buf,
    char*                               data,
    int                                 offset,
    int                                 len);

static
void
globus_l_xio_udt_compact_read_buf(
    globus_l_xio_udt_read_buf_t*        read_buf,
    int                                 offset,
    int                                 len);

static
int
globus_l_xio_udt_copy_data_to_user_buf(
    globus_l_xio_udt_read_buf_t*                read_buf,
    const globus_xio_iovec_t*                   iovec,
    int                                         iovec_count,
    int                                         len);

static
int
globus_l_xio_udt_register_user_read_buf(
    globus_l_xio_udt_read_buf_t*                read_buf,
    const globus_xio_iovec_t*                   iovec,
    int                                         iovec_count,
    int                                         len);

static
void
globus_l_xio_udt_process_user_buf(
    globus_l_handle_t*                   handle);

static
void
globus_l_xio_udt_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
int
globus_l_xio_udt_reader_loss_list_remove_predicate(
    void*                                                datum,
    void*                                                user_arg);

static
void
globus_l_xio_udt_reader_loss_list_remove(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int                                         seqno);

static
int
globus_l_xio_udt_reader_loss_list_relation(
    void*                     			low_datum,
    void*                       		high_datum,
    void*                       		args);

static
int
globus_l_xio_udt_irregular_pkt_list_relation(
    void*                                          low_datum,
    void*                                          high_datum,
    void*                                          args);

static
int
globus_l_xio_udt_irregular_pkt_list_predicate(
    void*                                               datum,
    void*                                               user_arg);

static
void
globus_l_xio_udt_add_irregular_pkt(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno,
    int                                         error_size);

static
globus_result_t
globus_l_xio_udt_process_data(
    globus_l_handle_t*           handle);

      /*
       *  Functionality:
       *     Find a position in the buffer to receive next packet.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] data: pointer of pointer to the next data position.
       *     3) [in] offset: offset from last ACK point.
       *     4) [in] len: size of data to be written.
       *  Returned value:
       *     GLOBUS_TRUE if found, else GLOBUS_FALSE
       */

static
globus_bool_t
globus_l_xio_udt_find_read_data_pos(
    globus_l_xio_udt_read_buf_t*        read_buf,
    unsigned char**                     data,
    int                                 offset,
    int                                 len)
{

    int ack_ptr = 0;
    GlobusXIOName(globus_l_xio_udt_find_read_data_pos);

    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&read_buf->mutex);

    if (read_buf->user_buf_size != 0)
    {
        int iovec_offset, src_iovec_num;
        /*
         * Introduced a new variable iovec_offset in user_buf_ack to avoid
         * the for loops that i had here and other places like
         * add_data_to_read_buf, compact_buf etc
         */
        iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + offset + len <= read_buf->user_buf_size)
        {
            src_iovec_num = read_buf->user_buf_ack->iovec_num;
            while (ack_ptr + offset > iovec_offset +
                   read_buf->user_iovec[src_iovec_num].iov_len)
            {
                src_iovec_num++;
                iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;
            }
            if (ack_ptr + offset + len <= iovec_offset +
                read_buf->user_iovec[src_iovec_num].iov_len)
            {
                *data = (unsigned char *)
                    read_buf->user_iovec[src_iovec_num].iov_base +
                    ack_ptr + offset - iovec_offset;
            }
            else
            {
                goto error;
            }
        }
        else if (ack_ptr + offset < read_buf->user_buf_size)
        {
            goto error;
        }
    }
    /*
     * this if loop will be entered only if user_buf_size = 0 or (user_buf_size
     * !=0 and ack_ptr + offset >= user_buf_size) but there no condition to
     * check if user_buf_size == 0 coz ack_ptr is initialized to 0 and the
     * condition below would take care of user_buf_size == 0
     */
    if (ack_ptr + offset >= read_buf->user_buf_size)
    {
        int last_ack_pos = read_buf->last_ack_pos;
        /*
         * this has to be only if (user_buf_size !=0 and ack_ptr + offset >=
         * user_buf_size) but it does not harm to do for (user_buf_size==0)
         */
        offset -= read_buf->user_buf_size - ack_ptr;

        if (last_ack_pos >= read_buf->start_pos)
        {
            int udt_buf_size = read_buf->udt_buf_size;
            if (last_ack_pos + offset + len <= udt_buf_size)
            {
                *data = read_buf->udt_buf + last_ack_pos + offset;
            }
            else if ((last_ack_pos + offset > udt_buf_size)
                      && (offset - (udt_buf_size - last_ack_pos)
                      + len <= read_buf->start_pos))
            {
                *data = read_buf->udt_buf + offset -
                        (udt_buf_size - read_buf->last_ack_pos);
            }
        }
        else if (last_ack_pos + offset + len <= read_buf->start_pos)
        {
            *data = read_buf->udt_buf + last_ack_pos + offset;
        }
        else
        {
            goto error;
        }
        /* update furtherest dirty point */
        if (offset + len > read_buf->max_offset)
        {
            read_buf->max_offset = offset + len;
            read_buf->into_udt_buf = GLOBUS_TRUE;
        }

    }

    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return GLOBUS_TRUE;

error:
    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExitWithError();
    return GLOBUS_FALSE;

}


      /*
       *  Functionality:
       *     Write data into the buffer.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] data: pointer to data to be copied.
       *     3) [in] offset: offset from last ACK point.
       *     4) [in] len: size of data to be written.
       *  Returned value:
       *     GLOBUS_SUCCESS if a position that can hold the data is found,
       *     otherwise a result object with error
       */

static
globus_result_t
globus_l_xio_udt_add_data_to_read_buf(
    globus_l_xio_udt_read_buf_t*      read_buf,
    char*                               data,
    int                                 offset,
    int                                 len)
{
    int ack_ptr = 0, orig_len;
    int user_buf_size;
    GlobusXIOName(globus_l_xio_udt_add_data_to_read_buf);

    GlobusXIOUdtDebugEnter();

    orig_len = len;
    user_buf_size = read_buf->user_buf_size;
    if (user_buf_size != 0)
    {
        int iovec_offset, src_iovec_num, src_base_offset;
        int rem_iov_len, total, total_temp, data_size;

        iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + offset < user_buf_size)
        {
            if (ack_ptr + offset + len < user_buf_size)
            {
                total = len;
            }
            else
            {
                total = user_buf_size - (ack_ptr + offset);
            }
            src_iovec_num = read_buf->user_buf_ack->iovec_num;
            while (ack_ptr + offset > iovec_offset +
                   read_buf->user_iovec[src_iovec_num].iov_len)
            {
                src_iovec_num++;
                iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;
            }
            src_base_offset = ack_ptr + offset - iovec_offset;
            total_temp = total;
            while(total)
            {
                rem_iov_len = read_buf->user_iovec[src_iovec_num].iov_len -
                              src_base_offset;
                data_size = (rem_iov_len > total) ? total : rem_iov_len;
                memcpy((char *) read_buf->user_iovec[src_iovec_num].iov_base +
                       src_base_offset, data, data_size);
                src_base_offset = (src_base_offset + data_size) %
                                   read_buf->user_iovec[src_iovec_num].iov_len;
                if (src_base_offset == 0)
                {
                    src_iovec_num++;
                }
                /*
                 * even if this exceeds iovec_count no problem, coz in that
                 * case total will become zero in the next line and the loop
                 * will get terminated
                 */
                total -= data_size;
            }
            if (total_temp < len)
            {
                int temp = user_buf_size - (ack_ptr + offset);
                data += temp;
                len -= temp;
            }
        }
    }
    /*
     * this if loop will be entered only if user_buf_size = 0 or (user_buf_size
     * !=0 and ack_ptr + offset >= user_buf_size) but there no condition to
     * check if user_buf_size == 0 coz ack_ptr is initialized to 0 and the
     * condition below would take care of user_buf_size == 0
     */
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
         ("add data ack_ptr = %d  offset = %d len = %d start_pos = %d"
         " last_ack_pos = %d\n", ack_ptr, offset, len, read_buf->start_pos,
         read_buf->last_ack_pos));
    if (ack_ptr + offset + orig_len  >= user_buf_size)
    {
        int last_ack_pos = read_buf->last_ack_pos;
        /*
         * this has to be only if (user_buf_size !=0 and ack_ptr + offset >=
         * user_buf_size) but it does not harm to do for (user_buf_size==0)
         */
        if (ack_ptr + offset >= user_buf_size)
        {
            offset -= user_buf_size - ack_ptr;
        }
        else
        {
            offset = 0;
        }

        /*
         * size=10 implies that data can be present in locations 0..9,
         * last_ack_pos + offset indicates start position for the data
         * (to be written).. if that is equal to size, it means start position
         * exceeeds the buffer size (we can not write at location 10. Whereas
         * if last_ack_pos + offset + len == size (i.e, for eg. if last_ack_pos
         * + offset = 3 and len = 7 then the data is going to occupy the
         * locations 3,4,5,6,7,8,9) then data doesnot exceed the buffer size
         */

        if (last_ack_pos >= read_buf->start_pos)
        {
            int udt_buf_size = read_buf->udt_buf_size;
            if (last_ack_pos + offset + len <= udt_buf_size)
            {
                memcpy(read_buf->udt_buf + last_ack_pos + offset,
                       data, len);
            }
            else if ((last_ack_pos + offset <
                      udt_buf_size) && (len -
                      (udt_buf_size - last_ack_pos -
                      offset) <= read_buf->start_pos))
            {
                memcpy(read_buf->udt_buf + last_ack_pos + offset,
                       data, udt_buf_size -
                       (last_ack_pos + offset));
                memcpy(read_buf->udt_buf, data + udt_buf_size -
                       last_ack_pos - offset, len -
                       (udt_buf_size - (last_ack_pos +
                       offset)));
            }
            else if ((last_ack_pos + offset >=
                      udt_buf_size) && (offset -
                      (udt_buf_size - last_ack_pos) +
                      len <= read_buf->start_pos))
            {
                memcpy(read_buf->udt_buf + offset -
                       (udt_buf_size - last_ack_pos),
                       data, len);
            }
        }
        else if (last_ack_pos + offset + len <= read_buf->start_pos)
        {
            memcpy(read_buf->udt_buf + last_ack_pos + offset, data,
                   len);
        }
        else
        {
            goto error;
        }
        if (offset + len > read_buf->max_offset)
        {
            read_buf->max_offset = offset + len;
        }
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOUdtDebugExitWithError();
    return GlobusXIOUdtErrorReadBufferFull();

}


      /*
       * Functionality:
       *     Move part of the data in buffer to the direction of the ACK point
       *     by some length.
       * Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] offset: last_ack_pos + offset is the destination
       *     3) [in] len: last_ack_pos + offset + len is the source i.e,
       *        starting from this position till the end of buf has to be
       *        moved
       * Returned value:
       *     None.
       */

static
void
globus_l_xio_udt_compact_read_buf(
    globus_l_xio_udt_read_buf_t*        read_buf,
    int                                 offset,
    int                                 len)
{
    int user_buf_size = read_buf->user_buf_size;
    GlobusXIOName(globus_l_xio_udt_compact_read_buf);

    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&read_buf->mutex);
    if (user_buf_size != 0)
    {
        int iovec_offset, ack_ptr;

        iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + offset < user_buf_size)
        {
            int src_base_offset, dst_base_offset, temp_user_buf_size;
            int src_iovec_num, dst_iovec_num;
            int total, total2 = 0, total3 = 0;
            int len1, len2, data_size;
            int last_ack_pos = read_buf->last_ack_pos;
            int udt_buf_size = read_buf->udt_buf_size;
            int max_offset = read_buf->max_offset;
            unsigned char* dst_ptr;

            src_iovec_num = read_buf->user_buf_ack->iovec_num;
            while (ack_ptr + offset  > iovec_offset +
                   read_buf->user_iovec[src_iovec_num].iov_len)
            {
                src_iovec_num++;
                iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;
            }
            src_base_offset = ack_ptr + offset - iovec_offset;
            total = user_buf_size - (ack_ptr + offset);

            /*
             * this is the total amount of data that needs to be copied
             * from protocol buf to user buf if ack_ptr + offset + len >
             * user_buf_size i.e, staring from last_ack_pos + len - total
             * (this is same as ack_ptr + offset + len), total amount of
             * data needs to be copied to user buf. In case if max_offset
             * < len, then starting from last_ack_pos + len - total,
             * last_ack_pos + max_offset - (last_ack_pos + len - total)
             * alone needs to be copied. this amounts to max_offset - len
             * + total which is same as total - (len - max_offset). The total
             * is set to this amount in the following if loop
             */

            if (max_offset < len)
            {
                total -= len - max_offset;
            }

            /*
             * dst_ptr indicates the location from which the data needs to be
             * copied from protocol buffer (to user buffer)
             */
            dst_ptr = read_buf->udt_buf + last_ack_pos + len -
                      (user_buf_size - (ack_ptr + offset));
            if (last_ack_pos + len - (user_buf_size -
                (ack_ptr + offset)) + total > udt_buf_size)
            {
                total3 = total - (udt_buf_size -
                         (last_ack_pos + len -
                         (user_buf_size - (ack_ptr + offset))));
                total = udt_buf_size - (last_ack_pos +
                        len - (user_buf_size - (ack_ptr + offset)));
            }
            if (ack_ptr + offset + len < user_buf_size)
            {
                dst_iovec_num = src_iovec_num;
                while (ack_ptr + offset + len > iovec_offset +
                       read_buf->user_iovec[dst_iovec_num].iov_len)
                {
                    dst_iovec_num++;
                    iovec_offset += read_buf->user_iovec[dst_iovec_num].iov_len;
                }
                dst_base_offset = ack_ptr + offset + len - iovec_offset;
                total = user_buf_size - (ack_ptr + offset + len);
            }
            /*
             * total is the amount of data that needs to be copied from
             * protocol buffer to user buffer for the case "ack_ptr +
             * offset < user_buf_size && ack_ptr + offset + len >
             * user_buf_size". In case if the amount of data to be copied from
             * protocol buffer exceeds the protocol buffer boundary, then total
             * indicates only a part amount of data that needs to be copied and
             * the remaining part is indicated by total3. Also total is the
             * amount of data that needs to be copied from ack_ptr + offset +
             * len in protocol buf to ack_ptr + offset in protocol buf for the
             * case "ack_ptr + offset + len < user_buf_size"
             */
            while (total)
            {

                len1 = read_buf->user_iovec[src_iovec_num].iov_len -
                       src_base_offset;
                if (ack_ptr + offset + len < read_buf->user_buf_size)
                {
                    len2 = read_buf->user_iovec[dst_iovec_num].iov_len -
                           dst_base_offset;
                    data_size = globus_l_xio_udt_min3(len1, len2, total);
                    memmove((char *)
                        read_buf->user_iovec[src_iovec_num].iov_base +
                            src_base_offset,
                        (char *) read_buf->user_iovec[dst_iovec_num].iov_base +
                            dst_base_offset, data_size);
                    dst_base_offset = (dst_base_offset + data_size) %
                                   read_buf->user_iovec[dst_iovec_num].iov_len;
                    if (dst_base_offset == 0)
                    {
                        dst_iovec_num++;
                    }
                }
                else
                {
                    data_size = (len1 > total) ? total : len1;
                    memcpy((char *)
                        read_buf->user_iovec[src_iovec_num].iov_base +
                           src_base_offset, dst_ptr, data_size);
                    dst_ptr += data_size;
                }
                src_base_offset = (src_base_offset + data_size) %
                                  read_buf->user_iovec[src_iovec_num].iov_len;
                if (src_base_offset == 0)
                {
                    src_iovec_num++;
                }
                total -= data_size;
            }
            if (ack_ptr + offset + len < user_buf_size)
            {
                total2 = len > max_offset ? max_offset :
                         len;
                if (last_ack_pos + total2 > udt_buf_size)
                {
                    total3 = total2 - (udt_buf_size -
                             last_ack_pos);
                    total2 = udt_buf_size - last_ack_pos;
                }
                temp_user_buf_size = user_buf_size;
                src_iovec_num = read_buf->user_iovec_count - 1;
                while (user_buf_size - len < temp_user_buf_size -
                       read_buf->user_iovec[src_iovec_num].iov_len)
                {
                   temp_user_buf_size -=
                        read_buf->user_iovec[src_iovec_num].iov_len;
                   src_iovec_num--;
                }
                src_base_offset = user_buf_size - len -
                    (temp_user_buf_size -
                    read_buf->user_iovec[src_iovec_num].iov_len);
                dst_ptr = read_buf->udt_buf + last_ack_pos;
                /*
                 * total is the amount of data that needs to be copied from
                 * protocol buffer to user buffer for the case "ack_ptr +
                 * offset + len < user_buf_size. In case if the amount of data
                 * to be copied from protocol buffer exceeds the protocol
                 * buffer boundary, then total2 indicates only a part amount of
                 * data that needs to be copied and the remaining part is
                 * indicated by total3. total2 does not have anything do with
                 * the case "ack_ptr + offset < user_buf_size && ack_ptr +
                 * offset + len > user_buf_size".
                 */
                while (total2)
                {
                    len1 = read_buf->user_iovec[src_iovec_num].iov_len -
                           src_base_offset;
                    data_size = (len1 > total2) ? total2 : len1;
                    memcpy((char *)
                        read_buf->user_iovec[src_iovec_num].iov_base +
                           src_base_offset, dst_ptr, data_size);
                    src_base_offset = (src_base_offset + data_size) %
                                read_buf->user_iovec[src_iovec_num].iov_len;
                    if (src_base_offset == 0)
                    {
                        src_iovec_num++;
                    }
                    total2 -= data_size;
                    dst_ptr += data_size;
                }
            }
            dst_ptr = read_buf->udt_buf;
            while (total3)
            {
                len1 = read_buf->user_iovec[src_iovec_num].iov_len -
                       src_base_offset;
                data_size = (len1 > total3) ? total3 : len1;
                memcpy((char *) read_buf->user_iovec[src_iovec_num].iov_base +
                       src_base_offset, dst_ptr, data_size);
                src_base_offset = (src_base_offset + data_size) %
                                  read_buf->user_iovec[src_iovec_num].iov_len;
                if (src_base_offset == 0)
                {
                    src_iovec_num++;
                }
                total3 -= data_size;
                dst_ptr += data_size;
            }
            offset = 0;
        }
        else
        {
            /* offset is larger than size of user buffer */
            offset -= user_buf_size - ack_ptr;
        }
    }

    /* No data to move */
    if (read_buf->max_offset - offset < len)
    {
        read_buf->max_offset = offset;
        /*
         * if there was data to move then max_offset would be set to max_offset
         * - len here since there is not data to move you set max_offset =
         * offset
         */
    }
    else
    {
        int last_ack_pos = read_buf->last_ack_pos;
        int udt_buf_size = read_buf->udt_buf_size;
        int max_offset = read_buf->max_offset;

        /* Oops, memory move is too complicated. */
        if (last_ack_pos + max_offset <= udt_buf_size)
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset,
                    read_buf->udt_buf + last_ack_pos + offset +
                    len, max_offset - (offset + len));
        }
        else if (last_ack_pos + offset > udt_buf_size)
        {
            memmove(read_buf->udt_buf + (last_ack_pos + offset) %
              udt_buf_size, read_buf->udt_buf +
              (last_ack_pos + offset + len) %
              udt_buf_size, max_offset - (offset + len));
        }
        else if (last_ack_pos + offset + len <= udt_buf_size)
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset,
                    read_buf->udt_buf + last_ack_pos + offset +
                    len, udt_buf_size - (last_ack_pos +
                    offset + len));

            /*
             * Since we moved data starting from "read_buf->udt_buf +
             * read_buf->last_ack_pos + offset + len" till end of protocol
             * buffer 'len' positions ahead, we need to move 'len' amount
             * data from the start of buffer to the end
             */

            memmove(read_buf->udt_buf + (udt_buf_size - len),
                    read_buf->udt_buf, len);
            memmove(read_buf->udt_buf, read_buf->udt_buf + len,
                    last_ack_pos + max_offset -
                    udt_buf_size - len);
        }
        else
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset,
                    read_buf->udt_buf + (last_ack_pos + offset +
                    len - udt_buf_size), udt_buf_size
                    - (last_ack_pos + offset));
            /*
             * total shift position is 'len' i.e, the data at 'offset + len'
             * needs to be shifted to 'offset'. Till now the shift is done till
             * the end of protocol buffer. The data that needs to be copied to
             * the start of buffer is (should be) in 'start + len' and the
             * amount of data that needs to be copied is 'last_ack_pos +
             * max_offset - len' and the extra '-read_buf->udt_buf_size is
             * because last_ack_pos + max_offset exceeds the protocol buffer
             * boundary
             */
            memmove(read_buf->udt_buf, read_buf->udt_buf + len,
                    last_ack_pos + max_offset - len - udt_buf_size);
        }

        /* Update the offset pointer */
        read_buf->max_offset -= len;
    }
    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return;
}


      /*
       *  Functionality:
       *     Read data from the buffer into user buffer.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer.
       *     2) [in] data: pointer to the user buffer.
       *     3) [in] len: size of data to be read.
       *  Returned value:
       *     Number of bytes copied
       */

static
int
globus_l_xio_udt_copy_data_to_user_buf(
    globus_l_xio_udt_read_buf_t*                read_buf,
    const globus_xio_iovec_t*                   iovec,
    int                                         iovec_count,
    int                                         len)
{
    int bytes_copied = 0;
    int start_pos = read_buf->start_pos;
    int last_ack_pos = read_buf->last_ack_pos;
    GlobusXIOName(globus_l_xio_udt_copy_data_to_user_buf);

    GlobusXIOUdtDebugEnter();

    GlobusXIOUdtDebugPrintf(
        GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("inside copy data start_pos is %d\n", read_buf->start_pos));

    if (start_pos + read_buf->wait_for <= last_ack_pos)
    {
        int i = 0;
        int total, data_size;

        total = last_ack_pos - start_pos;
        if (total > len)
        {
            total = len;
        }
        bytes_copied = total;
        while(total)
        {
            data_size = (iovec[i].iov_len > total) ? total :
                        iovec[i].iov_len;
            memcpy(iovec[i].iov_base, read_buf->udt_buf +
                   read_buf->start_pos, data_size);
            read_buf->start_pos += data_size;
            total -= data_size;
            ++i;
        }
    }
    else if ((last_ack_pos < start_pos)&&
             (read_buf->wait_for <= (read_buf->udt_buf_size -
             start_pos) + last_ack_pos))
    {
        int i = 0;
        int total1, total2 = 0, base_ptr, data_size;

        total1 = read_buf->udt_buf_size - start_pos;
        if (len > total1)
        {
            total2 = len - total1;
            if (total2 > last_ack_pos)
            {
                total2 = last_ack_pos;
            }
        }
        else
        {
            total1 = len;
        }
        bytes_copied = total1 + total2;
        while(total1)
        {
            data_size = (iovec[i].iov_len > total1) ? total1 :
                        iovec[i].iov_len;
            memcpy(iovec[i].iov_base, read_buf->udt_buf +
                   read_buf->start_pos, data_size);
            read_buf->start_pos += data_size;
            total1 -= data_size;
            ++i;
        }
        read_buf->start_pos = read_buf->start_pos % read_buf->udt_buf_size;
        if (total2 && data_size < iovec[i-1].iov_len);
        {
            base_ptr = data_size;
            data_size = iovec[i-1].iov_len - base_ptr;
            if (total2 < data_size)
                data_size = total2;
            memcpy((char *) iovec[i-1].iov_base + base_ptr, read_buf->udt_buf,
                   data_size);
            read_buf->start_pos = data_size;
            total2 -= data_size;
        }
        while(total2)
        {
            data_size = (iovec[i].iov_len > total2) ? total2 : iovec[i].iov_len;
            memcpy(iovec[i].iov_base, read_buf->udt_buf +
                   read_buf->start_pos, data_size);
            read_buf->start_pos += data_size;
            total2 -= data_size;
            ++i;
        }
    }

    GlobusXIOUdtDebugExit();
    return bytes_copied;

}

      /*
       *  Functionality:
       *     Update the ACK point of the buffer.
       *  Parameters:
       *    1) [in] handle: udt handle
       *    i'm getting the handle here coz i need both read_buf and read_cntl
       *    2) [in] len: size of data to be acknowledged.
       *  Returned value:
       *     GLOBUS_TRUE if a user buffer is fulfilled, otherwise GLOBUS_FALSE
       */
globus_bool_t
globus_l_xio_udt_update_read_ack_point(
    globus_l_handle_t*                          handle,
    int                                         len)
{
    globus_bool_t user_read_done = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_udt_update_read_ack_point);

    GlobusXIOUdtDebugEnter();

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
      ("update read ack - len = %d, last_ack_pos = %d\n",
        len, handle->read_buf->last_ack_pos));

    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->user_buf_size == 0)
    {
        /* there is no user buffer */
        handle->read_buf->last_ack_pos += len;
        handle->read_buf->last_ack_pos %= handle->read_buf->udt_buf_size;
        handle->read_buf->max_offset -= len;
    }
    else
    {
        int ack_ptr;

        ack_ptr = handle->read_buf->user_buf_ack->iovec_offset +
            handle->read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + len < handle->read_buf->user_buf_size)
        {
            /* update user buffer ACK pointer */
            while (ack_ptr + len >
                handle->read_buf->user_buf_ack->iovec_offset +
                handle->read_buf->user_iovec[
                    handle->read_buf->user_buf_ack->iovec_num].iov_len)
            {
              handle->read_buf->user_buf_ack->iovec_offset +=
                handle->read_buf->user_iovec[
                    handle->read_buf->user_buf_ack->iovec_num].iov_len;
              handle->read_buf->user_buf_ack->iovec_num++;
            }
            handle->read_buf->user_buf_ack->base_ptr =
                ack_ptr + len - handle->read_buf->user_buf_ack->iovec_offset;
        }
        else
        {
            /* user buffer is fulfilled */
            /* update protocol ACK pointer */
            handle->read_buf->last_ack_pos +=
                (ack_ptr + len - handle->read_buf->user_buf_size);
            handle->read_buf->last_ack_pos %= handle->read_buf->udt_buf_size;
            handle->read_buf->max_offset -=
                (ack_ptr + len - handle->read_buf->user_buf_size);
            handle->read_buf->pending_finished_read = GLOBUS_TRUE;
            handle->read_buf->result = GLOBUS_SUCCESS;
            handle->read_buf->nbytes = handle->read_buf->user_buf_size;
            handle->read_buf->user_buf_size = 0;
            user_read_done = GLOBUS_TRUE;
        }
    }

    globus_mutex_unlock(&handle->read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return user_read_done;
}


      /*
       *  Functionality:
       *     Insert the user buffer into the protocol buffer.
       *  Parameters:
       *    1) [in] read_buf: udt read buffer.
       *    2) [in] iovec: user iovec.
       *    3) [in] iovec_count: user iovec count.
       *    4) [in] len: size of the user buffer.
       *  Returned value:
       *     Size of data that has been received by now.
       */

static
int
globus_l_xio_udt_register_user_read_buf(
    globus_l_xio_udt_read_buf_t*                read_buf,
    const globus_xio_iovec_t*                   iovec,
    int                                         iovec_count,
    int                                         len)
{
    /* find the furthest "dirty" data that need to be copied */
    int curr_write_pos;
    int temp = read_buf->start_pos;
    int start_pos = temp;
    int last_ack_pos = read_buf->last_ack_pos;
    int udt_buf_size = read_buf->udt_buf_size;
    int wait_for = read_buf->wait_for;
    int size;
    GlobusXIOName(globus_l_xio_udt_register_user_read_buf);

    GlobusXIOUdtDebugEnter();

    read_buf->user_buf_ack->iovec_num = 0;
    read_buf->user_buf_ack->iovec_offset = 0;
    read_buf->user_buf_ack->base_ptr = 0;
    curr_write_pos = (last_ack_pos + read_buf->max_offset) %
                         udt_buf_size;
    if (wait_for < len)
    {
        int temp_len;

        if (curr_write_pos < start_pos)
        {
            temp_len = udt_buf_size - (start_pos - curr_write_pos);
        }
        else
        {
            temp_len = curr_write_pos - start_pos;
        }
        if (wait_for > temp_len)
        {
            len = wait_for;
        }
        else if (len > temp_len)
        {
            len = temp_len;
        }
    }
    read_buf->user_buf_size = len;

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("register_user_buf curr_write_pos = %d\n", curr_write_pos));
    /*
     * copy data from protocol buffer into user buffer - if curr_write_pos ==
     * start_pos, then it is not considered as curr_write_pos has wrapped
     * around and difference between curr_write_pos and start_pos as
     * udt_buf_size, but considered as both are equal
     */
    if (start_pos <= curr_write_pos)
    {
        if (curr_write_pos - start_pos <= len)
        {
            /*
             * there wont be any dirty data after copy is done thats why
             * max_offset set to zero below
             */
            int i = 0;

            while (temp < curr_write_pos)
            {
                if (temp + iovec[i].iov_len  < curr_write_pos)
                {
                    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                           iovec[i].iov_len);
                    temp += iovec[i].iov_len;
                }
                else
                {
                    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                           curr_write_pos - temp);
                    temp += curr_write_pos - temp;
                }
                ++i;
            }
            read_buf->max_offset = 0;
        }
        else
        {
            int i;
            for (i = 0; i < iovec_count; i++)
            {
                memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                       iovec[i].iov_len);
                temp+= iovec[i].iov_len;
            }
            read_buf->max_offset -= len;
        }
    }
    else
    {
        /* start_pos > curr_pos */
        if (udt_buf_size - (start_pos - curr_write_pos) <= len)
        {
            /*
             * there wont be any dirty data after copy is done thats why
             * max_offset set to zero below
             */
            int i = 0, temp_len;
            while (temp + iovec[i].iov_len < udt_buf_size)
            {
                memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                       iovec[i].iov_len);
                temp += iovec[i].iov_len;
                ++i;
            }
            temp_len = udt_buf_size - temp;
            memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, temp_len);
            temp = 0;
            /*
             * the above part copies data from start_pos till the end of
             * protocol buf and the below part copies data from beginning
             * of buffer till curr_pos.
             */
            if (curr_write_pos >= iovec[i].iov_len - temp_len)
            {
                /*
                 * if curr_write_pos == iovec[i].iov_len - temp_len, then
                 * memcpy below would copy only from read_buf->udt_buf till
                 * read_buf->udt_buf + curr_write_pos - 1
                 */
                memcpy((char *) iovec[i].iov_base + temp_len, read_buf->udt_buf,
                       iovec[i].iov_len - temp_len);
                temp += iovec[i].iov_len - temp_len;
                ++i;
            }
            while (temp + iovec[i].iov_len < curr_write_pos)
            {
                /*
                 * temp + iovec[i].iov_len >= curr_write_pos is taken care
                 * below while
                 */
                memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                       iovec[i].iov_len);
                /* read_buf->udt_buf is the start of protocol buffer */
                temp += iovec[i].iov_len;
                ++i;
            }
            memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                   curr_write_pos - temp);
            read_buf->max_offset = 0;
        }
        else
        {
            int i, data_size;

            if (udt_buf_size - start_pos <= len)
            {
                for (i = 0; i < iovec_count; i++)
                {
                    if (temp + iovec[i].iov_len < udt_buf_size)
                    {
                        /*
                         * Data does not exceed the physical boundary of the
                         * buffer
                         */
                        memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                               iovec[i].iov_len);
                        temp += iovec[i].iov_len;
                    }
                    else
                    {
                        /*
                         * data length exceeds the physical boundary, read twice
                         */
                        data_size = udt_buf_size - temp;
                        memcpy((char *)
                            iovec[i].iov_base, read_buf->udt_buf + temp,
                            data_size);
                        memcpy((char *) iovec[i].iov_base + data_size,
                            read_buf->udt_buf, iovec[i].iov_len -
                            data_size);
                        temp = iovec[i].iov_len - data_size;
                    }
                }
            }
            else
            {
                for (i = 0; i < iovec_count; i++)
                {
                    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp,
                           iovec[i].iov_len);
                    temp += iovec[i].iov_len;
                }
            }
            read_buf->max_offset -= len;
        }
    }

    /*
     * Update the user buffer pointer - we are sure that start_pos + len >
     * last_ack_pos - otherwise this routine wouldn't have been called
     * (copy_data_to_user_buf would have been succeeded), so we need to update
     * the user_buf_ack i.e, last_ack_pos - start_pos amount of ack'd data has
     * been copied to user buf (total amount of data copied to user bufffer may
     * be more than this but this much data is ack'd
     */

    if (start_pos <= last_ack_pos)
    {
        size = last_ack_pos - start_pos;
    }
    else
    {
        size = udt_buf_size - (start_pos - last_ack_pos);
    }
    while (size > read_buf->user_buf_ack->iovec_offset +
           read_buf->user_iovec[read_buf->user_buf_ack->iovec_num].iov_len)
    {
          read_buf->user_buf_ack->iovec_offset +=
              read_buf->user_iovec[read_buf->user_buf_ack->iovec_num].iov_len;
          read_buf->user_buf_ack->iovec_num++;
    }
    read_buf->user_buf_ack->base_ptr =
        size - read_buf->user_buf_ack->iovec_offset;

    /*
     * data from start_pos till start_pos + len is now handed over user_buf,
     * any arriving data that falls between start_pos and start_pos + len will
     * now be placed directly on the user_buf - so now, the start_pos of
     * protocol buffer should be changed to start_pos + len. It is like
     * clearing the protocol buffer so last_ack_pos is also set to start_pos.
     */

    read_buf->start_pos = (start_pos + len) % udt_buf_size;
    read_buf->last_ack_pos = read_buf->start_pos;

    GlobusXIOUdtDebugExit();
    return size;
    /*
     * this return value is used in calculating the user_buf_border(the seqno
     * that will fulfill the user buf) size gives largest ack point in user buf,
     * read_cntl->last_ack+(user_buf_size-(ack_ptr + size))/payload_size gives
     * the user_buf_border
     */
}


static
void
globus_l_xio_udt_process_user_buf(
    globus_l_handle_t*                   handle)
{
    globus_result_t                      read_result = GLOBUS_SUCCESS;
    int                                  bytes_copied = -1;
    int                                  temp_len;

    GlobusXIOName(globus_l_xio_udt_process_user_buf);
    GlobusXIOUdtDebugEnter();

    temp_len = handle->read_buf->temp_len;
    if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
    {
        int last_ack_pos = handle->read_buf->last_ack_pos;
        int start_pos = handle->read_buf->start_pos;

        if (last_ack_pos >= start_pos)
        {
            handle->read_buf->wait_for = last_ack_pos - start_pos;
        }
        else
        {
            handle->read_buf->wait_for =
                handle->read_buf->udt_buf_size + last_ack_pos - start_pos;
        }
        if (handle->read_buf->wait_for <= temp_len)
        {
            read_result = GlobusXIOErrorEOF();
        }
        else
        {
            handle->read_buf->wait_for = temp_len;
        }
    }
    bytes_copied = globus_l_xio_udt_copy_data_to_user_buf(
        handle->read_buf,  handle->read_buf->user_iovec,
        handle->read_buf->user_iovec_count, temp_len);


    handle->read_buf->user_buf = GLOBUS_FALSE;

    GlobusXIOUdtDebugPrintf(
        GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("bytes_copied = %d\n", bytes_copied));

    /* Still no?! Register the application buffer. */
    if (bytes_copied < handle->read_buf->wait_for)
    {
        int offset;
        offset = globus_l_xio_udt_register_user_read_buf(
            handle->read_buf, handle->read_buf->user_iovec,
            handle->read_buf->user_iovec_count, temp_len);
        handle->read_cntl->user_buf_border =
            handle->read_cntl->last_ack +
            (int)ceil((double)(handle->read_buf->user_buf_size
             - offset) / handle->payload_size);
        GlobusXIOUdtDebugPrintf(
            GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("user_buf_size = %d\n",
            handle->read_buf->user_buf_size));
    }
    else
    {
        handle->read_buf->pending_finished_read = GLOBUS_TRUE;
        handle->read_buf->result = read_result;
        handle->read_buf->nbytes = bytes_copied;
        handle->read_buf->user_buf_size = 0;
    }

    GlobusXIOUdtDebugExit();
    return;

}

      /*
       *  Functionality:
       *     read callback - do pass_read and take appropriate action depending
       *     on the info read (info read may be control or data),
       *     it also checks various timers and take appropriate action
       *  Parameters: 
       *     1) [in] op: xio operation
       *     2) [in] result: indicates the result of read operation
       *     3) [in] nbytes: number of bytes read
       *     4) [in] user_arg: udt driver handle
       *  Returned value:
       *     None.
       */
        
static      
void    
globus_l_xio_udt_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{   
    globus_l_handle_t*                  handle;
    globus_abstime_t                    curr_time;
    GlobusXIOName(globus_l_xio_udt_read_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    GlobusTimeAbstimeGetCurrent(curr_time);
        
    /* Below is the packet receiving/processing part. */
    if ((handle->state != GLOBUS_L_XIO_UDT_PEER_DEAD) &&
        (handle->state != GLOBUS_L_XIO_UDT_CLOSED))
    {
        globus_mutex_lock(&handle->read_cntl->mutex);
        if ((result == GLOBUS_SUCCESS) || (nbytes >= 4))
        {   
            handle->read_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
            handle->read_iovec[1].iov_len = nbytes -
                GLOBUS_L_XIO_UDT_HEADER_SIZE;
            /* Just heard from the peer, reset the expiration count. */
            handle->read_cntl->exp_count = 0;
            if (((handle->write_cntl->curr_seqno + 1) %
                GLOBUS_L_XIO_UDT_MAX_SEQ_NO) 
                == handle->write_cntl->last_ack)
            {
                GlobusTimeAbstimeCopy(handle->read_cntl->time_last_heard,
                        curr_time);
            }
            /* But this is control packet, process it! */
            if ((*(int*)handle->read_iovec[0].iov_base) >> 31)
            {
                int pkt_type = ((*(int*)handle->read_iovec[0].iov_base) >> 28)
                                & 0x00000007;
                switch (pkt_type)
                {
                /*000 - Unused */
                case GLOBUS_L_XIO_UDT_UNUSED:
                    break;

                /*001 - Keep-alive */
                case GLOBUS_L_XIO_UDT_KEEPALIVE:
                    /*
                     * The only purpose of keep-alive packet is to tell the
                     * peer is still alive nothing need to be done.
                     */
                    break;
                /*
                 * pkt_type 2,3 and 4 alone can tell a writer that reader has
                 * received new data or not. Keepalive can be sent even
                 * there is no packet writing/receiving.
                 */

                /*010 - Acknowledgement */
                case GLOBUS_L_XIO_UDT_ACK:
                    GlobusTimeAbstimeCopy(
                        handle->read_cntl->time_last_heard, curr_time);
                    globus_l_xio_udt_process_ack(handle);
                    break;

                /*011 - Loss Report */
                case GLOBUS_L_XIO_UDT_NAK:
                    GlobusTimeAbstimeCopy(
                        handle->read_cntl->time_last_heard, curr_time);
                    globus_l_xio_udt_process_nak(handle);
                    break;

                /*100 - Delay Warning */
                case GLOBUS_L_XIO_UDT_CONGESTION_WARNING:
                    GlobusTimeAbstimeCopy(
                        handle->read_cntl->time_last_heard, curr_time);
                    globus_l_xio_udt_process_congestion_warning(handle);
                    break;

                /*101 - Unused */
                case GLOBUS_L_XIO_UDT_FIN:
                    globus_l_xio_udt_process_fin(handle);
                    break;

                /*110 - Acknowledgement of Acknowledgement */
                case GLOBUS_L_XIO_UDT_ACK_ACK:
                    globus_l_xio_udt_process_ack_ack(handle);
                    break;

                /*111 - Reserved for future use */
                case GLOBUS_L_XIO_UDT_FIN_ACK:
                    globus_l_xio_udt_process_fin_ack(handle);
                    break;

                default:
                    break;
                }
                if (handle->read_buf->into_udt_buf)
                {
                    handle->read_buf->max_offset -= handle->payload_size;
                }
            }
            else if ((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
                     (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT))
            {
                if (globus_l_xio_udt_process_data(handle)
                        != GLOBUS_SUCCESS)
                {
                    goto error;
                }
            }
        }
        else
        {
            if (handle->read_buf->into_udt_buf)
            {
                handle->read_buf->max_offset -= handle->payload_size;
            }
        }

        globus_mutex_lock(&handle->read_buf->mutex);
        if (((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
            (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)) &&
            (handle->read_buf->user_buf == GLOBUS_TRUE))
        {
            globus_l_xio_udt_process_user_buf(handle);

        }
        globus_mutex_unlock(&handle->read_buf->mutex);

        handle->read_buf->into_udt_buf = GLOBUS_FALSE;
        globus_callback_register_oneshot(NULL, NULL,
            globus_i_xio_udt_read, handle);
        globus_mutex_unlock(&handle->read_cntl->mutex);
    }
    if (handle->write_buf->pending_finished_write)
    {
        handle->write_buf->pending_finished_write = GLOBUS_FALSE;
        globus_callback_register_oneshot(NULL, NULL,
            globus_l_xio_udt_finish_write, handle);
    }
    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->pending_finished_read)
    {
       GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("read finished nbytes = %d\n",
        handle->read_buf->nbytes));
        handle->read_buf->pending_finished_read = GLOBUS_FALSE;
        globus_mutex_unlock(&handle->read_buf->mutex);
        globus_xio_driver_finished_read(handle->user_read_op,
            handle->read_buf->result, handle->read_buf->nbytes);
    }
    else
    {
        globus_mutex_unlock(&handle->read_buf->mutex);
    }

    GlobusXIOUdtDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExitWithError();
    return;
}

void
globus_i_xio_udt_read(
    void*                       user_arg)
{

    globus_l_handle_t* handle = (globus_l_handle_t*) user_arg;
    GlobusXIOName(globus_i_xio_udt_read);

    GlobusXIOUdtDebugEnter();

    if (handle->state != GLOBUS_L_XIO_UDT_CLOSED)
    {
        int offset;
        int last_ack = handle->read_cntl->last_ack;
        int payload_size = handle->payload_size;

        globus_mutex_lock(&handle->read_cntl->mutex);
        /* Look for a slot for the speculated data. */
        offset = handle->read_cntl->next_expect - last_ack;
        if (offset < -GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
        {
            offset += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
        }

        handle->read_cntl->next_slot_found =
            globus_l_xio_udt_find_read_data_pos(
                handle->read_buf,
                (unsigned char**)&handle->read_iovec[1].iov_base,
                offset * payload_size -
                globus_l_xio_udt_get_error_size(
                    handle->irregular_pkt_info, offset + last_ack),
                payload_size);
        if (handle->read_cntl->next_slot_found == GLOBUS_FALSE)
        {
            handle->read_iovec[1].iov_base = handle->payload;
        }
        handle->read_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
        handle->read_iovec[1].iov_len = payload_size;
        if (globus_xio_driver_pass_read(
                handle->driver_read_op,
                handle->read_iovec,
                2,
                GLOBUS_L_XIO_UDT_HEADER_SIZE,
                globus_l_xio_udt_read_cb,
                handle) != GLOBUS_SUCCESS)
        {
            GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                ("pass read failed\n"));
            goto error;
        }
    }

    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}


      /*
       *  Functionality:
       *     Insert a series of loss seq. no. between "seqno1" and "seqno2"
       *     into reader's loss list.
       *  Parameters:
       *     1) [in] reader_loss_info: reader loss information
       *     2) [in] seqno1: sequence number starts.
       *     3) [in] seqno2: seqeunce number ends.
       *  Returned value:
       *     None.
       */

void
globus_l_xio_udt_reader_loss_list_insert(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int                                         seqno1,
    int                                         seqno2)
{
    globus_l_xio_udt_reader_loss_seq_t* lost_seq;
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_insert);

    GlobusXIOUdtDebugEnter();
    /*
     * Any seq wont be reported more than once so no need to the check for
     * duplicates
     */

    lost_seq = (globus_l_xio_udt_reader_loss_seq_t*)
                globus_malloc(sizeof(globus_l_xio_udt_reader_loss_seq_t));
    lost_seq->start_seq = seqno1;
    lost_seq->end_seq = seqno2;
    GlobusTimeAbstimeGetCurrent(lost_seq->last_feedback_time);
    lost_seq->report_count = 2;
    globus_list_insert(&reader_loss_info->list, lost_seq);

    /*
     * length is inclusive of seqno1 and seqno2 and get_length calculates the
     * inclusive length
     */

    reader_loss_info->length += globus_l_xio_udt_get_length(seqno1, seqno2);

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("reader_loss_list_insert seqno1 = %d seqno2 = %d length = %d\n",
        seqno1, seqno2, reader_loss_info->length));

    /*
     * I'm not doing the coalescing with prior node, e.g., [2, 5], [6, 7]
     * becomes [2, 7]
     */

    GlobusXIOUdtDebugExit();
    return;
}


        /*
         *  Functionality:
         *    Predicate for globus_l_xio_udt_reader_loss_list_remove. i.e,
         *    globus_l_xio_udt_reader_loss_list_remove uses this routine to i
         *    check if there is anything to remove in the reader loss list
         *  Parameters:
         *    1) [in] datum: data present in the write loss list
         *    2) [in] user_arg: user provided argument (seqno)
         *  Returned value:
         *    1 if datum <= user_arg else 0
         */

static
int
globus_l_xio_udt_reader_loss_list_remove_predicate(
    void*      			                         datum,
    void*                       		         user_arg)
{

    globus_l_xio_udt_reader_loss_seq_t * data =
        (globus_l_xio_udt_reader_loss_seq_t *) datum;
    int* seqno = (int*) user_arg;
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_remove_predicate);

    if ((globus_l_xio_udt_not_less_than(*seqno, data->start_seq)) &&
        (globus_l_xio_udt_not_greater_than(*seqno, data->end_seq)))
    {
        return 1;
    }
    return 0;
}


     /*
      *   Functionality:
      *      Remove a loss seq. no. from the reader's loss list.
      *   Parameters:
      *     1) [in] reader_loss_info: reader loss information
      *     2) [in] seqno: sequence number.
      *   Returned value:
      *      None.
      */

static
void
globus_l_xio_udt_reader_loss_list_remove(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int                                         seqno)
{
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_remove);

    GlobusXIOUdtDebugEnter();

    if (reader_loss_info->length > 0)
    {
        globus_list_t* list = reader_loss_info->list;
        globus_list_t* temp_list;
        globus_l_xio_udt_reader_loss_seq_t* temp_seq;

        if ((temp_list = globus_list_search_pred(list,
             globus_l_xio_udt_reader_loss_list_remove_predicate, &seqno))
             != NULL)
        {
            temp_seq = globus_list_first(temp_list);
            if (temp_seq->start_seq == temp_seq->end_seq)
            {
                globus_list_remove(&reader_loss_info->list, temp_list);
                globus_free(temp_seq);
            }
            else if (temp_seq->start_seq == seqno)
            {
                temp_seq->start_seq = globus_l_xio_udt_inc_seqno(
                                        temp_seq->start_seq);
            }
            else if (temp_seq->end_seq == seqno)
            {
                temp_seq->end_seq = globus_l_xio_udt_dec_seqno(
                                        temp_seq->end_seq);
            }                           
            else /* split */
            {
                globus_l_xio_udt_reader_loss_seq_t* new_seq =
                    (globus_l_xio_udt_reader_loss_seq_t*)
                    globus_malloc(sizeof(globus_l_xio_udt_reader_loss_seq_t));
                new_seq->start_seq = globus_l_xio_udt_inc_seqno(seqno);
                new_seq->end_seq = temp_seq->end_seq;
                GlobusTimeAbstimeCopy(new_seq->last_feedback_time, 
                    temp_seq->last_feedback_time); 
                new_seq->report_count = temp_seq->report_count;
                temp_seq->end_seq = globus_l_xio_udt_dec_seqno(seqno);
                globus_list_insert(&reader_loss_info->list, new_seq);
            }
            reader_loss_info->length--;
         }
    }
     
    GlobusXIOUdtDebugExit();
    return;  
}     
      
      
      
/* better make use of priority queue here */
      
      /*
       *  Functionality:
       *     This is a relation function used to find the minimum element in a
       *     list. This used by the globus_list_min function (see the
       *     globus_l_xio_udt_get_first_reader_lost_seq(..) function below)
       *     and globus_list_sort_destructive(..) (see
       *     globus_l_xio_udt_get_reader_loss_array(..) below)
       *  Parameters:
       *     1) low_datum: a data in the list
       *     2) high_datum: another data in the list
       *     3) args: NULL
       *  Returned value:
       *     1 if low_datum is less than high_datum 0 otherwise
       */
        
static  
int
globus_l_xio_udt_reader_loss_list_relation(
    void*                       		low_datum,
    void*                       		high_datum,
    void*                       		args)
{           
            
    globus_l_xio_udt_reader_loss_seq_t * data1 =
        (globus_l_xio_udt_reader_loss_seq_t *) low_datum;
    globus_l_xio_udt_reader_loss_seq_t * data2 =
        (globus_l_xio_udt_reader_loss_seq_t *) high_datum;
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_relation);

    if (globus_l_xio_udt_less_than(data1->start_seq, data2->start_seq))
    {
        return 1;
    }
    return 0;

}


      /*
       *  Functionality:
       *     Read the first (smallest) seq. no. in the list.
       *  Parameters:
       *     None.
       *  Returned value:
       *     the sequence number or -1 if the list is empty.
       */

int
globus_l_xio_udt_get_first_reader_lost_seq(
    globus_l_xio_udt_reader_loss_info_t*         reader_loss_info)
{
    int first_lost_seq = -1;
    GlobusXIOName(globus_l_xio_udt_get_first_reader_lost_seq);

    GlobusXIOUdtDebugEnter();

    if (reader_loss_info->length > 0)
    {
        globus_list_t* temp_list;
        globus_l_xio_udt_reader_loss_seq_t* temp_seq;

        temp_list = globus_list_min(reader_loss_info->list,
                        globus_l_xio_udt_reader_loss_list_relation, NULL);
        temp_seq = (globus_l_xio_udt_reader_loss_seq_t*)
                        globus_list_first(temp_list);
        first_lost_seq = temp_seq->start_seq;
    }

    GlobusXIOUdtDebugExit();
    return first_lost_seq;

}


      /*
       *  Functionality:
       *     Get a encoded loss array for NAK report.
       *  Parameters:
       *     1) [in] reader_loss_info: reader loss information
       *     2) [in] array: pointer to the result array.
       *     3) [out] physical length of the result array.
       *     4) [in] limit: maximum length of the array.
       *     5) [in] interval: Time threshold from last NAK report.
       *  Returned value:
       *     None.
       */

void 
globus_l_xio_udt_get_reader_loss_array(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int*                                        array,
    int*                                        len,
    int                                         limit,
    int                                         interval_usec)
{
    globus_list_t* list;
    globus_abstime_t curr_time;
    globus_reltime_t interval;
    GlobusXIOName(globus_l_xio_udt_get_reader_loss_array);
       
    GlobusXIOUdtDebugEnter();
       
    list = globus_list_sort_destructive(reader_loss_info->list,
                globus_l_xio_udt_reader_loss_list_relation, NULL);
    reader_loss_info->list = list;
    /* represents number of lost packets */
    len[0] = 0;
    /* represents no. of seqno.s used to represent total no. of lost packets */
    len[1] = 0;
    GlobusTimeAbstimeGetCurrent(curr_time);
    GlobusTimeReltimeSet(interval, 0, interval_usec);
    while (list && (len[1] < limit - 1))
    {
        globus_l_xio_udt_reader_loss_seq_t* temp_seq;
        globus_reltime_t time_expired;
    
        temp_seq = globus_list_first(list);
        GlobusTimeAbstimeDiff(time_expired, temp_seq->last_feedback_time,
            curr_time);
        GlobusTimeReltimeDivide(time_expired, temp_seq->report_count);
        if (globus_reltime_cmp(&time_expired, &interval) > 0)
        {
            array[len[1]] = temp_seq->start_seq;
            if (temp_seq->end_seq != temp_seq->start_seq)
            {
                /* there are more than 1 loss in the sequence */
                array[len[1]] |= 0x80000000;
                len[1]++;
                array[len[1]] = temp_seq->end_seq;
                /* here get_length should return b-a+1 */
                len[0] += globus_l_xio_udt_get_length(temp_seq->start_seq,
                              temp_seq->end_seq);
            }
            else
                /* there is only 1 loss in the seqeunce */
                len[0]++;
       
            len[1]++;
            /* update the timestamp */
            GlobusTimeAbstimeCopy(temp_seq->last_feedback_time, curr_time);
            /* update report counter */
            temp_seq->report_count++; 
        }    
        list = globus_list_rest(list);
    }  
       
    GlobusXIOUdtDebugExit();
    return;
} 


      /*
       *  Functionality:
       *     This is a relation function used to find the minimum element in a
       *     list. This used by the globus_list_sort_destructive function (see
       *     the globus_l_xio_udt_get_error_size(..) function below)
       *  Parameters:
       *     1) low_datum: a data in the list
       *     2) high_datum: another data in the list
       *     3) args: not used
       *  Returned value:
       *     1 if low_datum is less than high_datum 0 otherwise
       */

static
int
globus_l_xio_udt_irregular_pkt_list_relation(
    void*                                          low_datum,
    void*                                          high_datum,
    void*                                          args)
{

    globus_l_xio_udt_irregular_seq_t * data1 =
        (globus_l_xio_udt_irregular_seq_t *) low_datum;
    globus_l_xio_udt_irregular_seq_t * data2 =
        (globus_l_xio_udt_irregular_seq_t *) high_datum;
    GlobusXIOName(globus_l_xio_udt_irregular_pkt_list_relation);

    if (globus_l_xio_udt_less_than(data1->seqno, data2->seqno))
    {
        return 1;
    }
    return 0;

}



      /*
       *  Functionality:
       *     Read the total size error of all the irregular packets prior to
       *     "seqno".
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.
       *  Returned value:
       *     the total size error of all the irregular packets prior to "seqno".       */

int
globus_l_xio_udt_get_error_size(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno)
{
    int error_size = 0;
    GlobusXIOName(globus_l_xio_udt_get_error_size);

    GlobusXIOUdtDebugEnter();

    if (irregular_pkt_info->length > 0)
    {
        globus_list_t* list;
        globus_l_xio_udt_irregular_seq_t* temp_seq;

        list = globus_list_sort_destructive(irregular_pkt_info->list,
            globus_l_xio_udt_irregular_pkt_list_relation, NULL);
        irregular_pkt_info->list = list;
        temp_seq = globus_list_first(list);
        while(list && globus_l_xio_udt_less_than(temp_seq->seqno,
            seqno))
        {
            error_size += temp_seq->error_size;
            list = globus_list_rest(list);
            if (list)
            {
                temp_seq = globus_list_first(list);
            }
        }
    }

    GlobusXIOUdtDebugExit();
    return error_size;
}



         /*
          *  Functionality:
          *    Predicate for globus_l_xio_udt_add_irregular_pkt. i.e,
          *    globus_l_xio_udt_add_irregular_pkt uses this routine to
          *    check if the packet is already in irregular pkt list
          *  Parameters:
          *    1) [in] datum: data present in the irregular pkt list
          *    2) [in] user_arg: user provided argument (seqno)
          *  Returned value:
          *    1 if datum == user_arg else 0
          */

static
int
globus_l_xio_udt_irregular_pkt_list_predicate(
    void*                                               datum,
    void*                                               user_arg)
{
    GlobusXIOName(globus_l_xio_udt_irregular_pkt_list_predicate);

    globus_l_xio_udt_irregular_seq_t* data  =
        (globus_l_xio_udt_irregular_seq_t*) datum;
    int* seqno = (int*)user_arg;
    if (data->seqno == *seqno)
    {
        return 1;
    }
    return 0;

}


      /*
       *  Functionality:
       *     Insert an irregular packet into the list.
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.
       *     3) [in] errsize: size error of the current packet.
       *  Returned value:
       *     None 
       */   
        
static  
void    
globus_l_xio_udt_add_irregular_pkt(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno,
    int                                         error_size)
{           
    globus_l_xio_udt_irregular_seq_t*   irregular_seq;
    GlobusXIOName(globus_l_xio_udt_add_irregular_pkt);
            
    GlobusXIOUdtDebugEnter();
    
    if (globus_list_search_pred(irregular_pkt_info->list,
        globus_l_xio_udt_irregular_pkt_list_predicate, &seqno) == NULL)
    {
        irregular_seq = (globus_l_xio_udt_irregular_seq_t*)
            globus_malloc(sizeof(globus_l_xio_udt_irregular_seq_t));
        irregular_seq->seqno = seqno;
        irregular_seq->error_size = error_size;
        globus_list_insert(&irregular_pkt_info->list, irregular_seq);
        irregular_pkt_info->length++;
    }     
          
    GlobusXIOUdtDebugExit();
    return;  
}         
          
          
          
      /*  
       *  Functionality:
       *     Remove ALL the packets prior to "seqno".
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.            
       *  Returned value:                               
       *     None
       */

void    
globus_l_xio_udt_remove_irregular_pkts(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno)
{       
    GlobusXIOName(globus_l_xio_udt_remove_irregular_pkts);
    
    GlobusXIOUdtDebugEnter();

    if (irregular_pkt_info->length > 0)
    {
        globus_l_xio_udt_irregular_seq_t* temp_seq;
        globus_list_t* list = irregular_pkt_info->list;
       
        temp_seq = globus_list_first(list);
        while(list && globus_l_xio_udt_less_than(temp_seq->seqno, 
            seqno))
        {    
            irregular_pkt_info->length--;
            list = globus_list_rest(list);
            globus_free(temp_seq);
            if (list)
            {
                temp_seq = globus_list_first(list);
            }
            globus_list_remove(&irregular_pkt_info->list,
                irregular_pkt_info->list);
        }
    }

    GlobusXIOUdtDebugExit();
    return;
}


static
globus_result_t
globus_l_xio_udt_process_data(
    globus_l_handle_t*           handle)
{
    int                          seqno;
    int                          offset;
    int                          payload_size;
    
    GlobusXIOName(globus_l_xio_udt_process_data);
    GlobusXIOUdtDebugEnter();

    /* update time/delay information */
    globus_l_xio_udt_record_pkt_arrival(handle->read_history);
    seqno = *(int*)handle->read_iovec[0].iov_base;
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("seqno received = %d\n", seqno));

    /* check if it is probing packet pair */
    if ((seqno % GLOBUS_L_XIO_UDT_PROBE_INTERVAL) < 2)
    {
        /* 
         * Should definitely need { } for the if below coz
         * GlobusTimeAbstimeCopy is #define with {..} and
         * presence of ; terminates if else 
         */
        if ((seqno % GLOBUS_L_XIO_UDT_PROBE_INTERVAL) == 0)
        {
            GlobusTimeAbstimeGetCurrent(handle->read_history->probe_time);
        }
        else
        { 
            globus_l_xio_udt_record_probe2_arrival(
                handle->read_history);
        }
    }
    /* actual offset of the received data */
    offset = seqno - handle->read_cntl->last_ack;
    if (offset < -GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
        offset += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
    }

    payload_size = handle->payload_size;
    if ((offset >= 0) && (offset < handle->handshake->max_flow_wnd_size))
    {
        int curr_seqno = handle->read_cntl->curr_seqno;
        /* Oops, the speculation is wrong */
        if ((seqno != handle->read_cntl->next_expect) ||
            (handle->read_cntl->next_slot_found == GLOBUS_FALSE))
        {
            /* 
             * Put the received data explicitly into the right slot.
             */
            if (globus_l_xio_udt_add_data_to_read_buf(
                    handle->read_buf,
                    handle->read_iovec[1].iov_base,
                    offset * payload_size - 
                    globus_l_xio_udt_get_error_size(
                    handle->irregular_pkt_info, seqno),
                    handle->read_iovec[1].iov_len)
                    != GLOBUS_SUCCESS)
            {
                goto error_no_space;
            }
            else
            {
                /* Loss detection. */
                if (((seqno > curr_seqno + 1) && (seqno - curr_seqno <
                    GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) ||
                    (seqno < curr_seqno - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
                {
                    globus_l_xio_udt_write_nak(handle,
                        curr_seqno + 1, seqno - 1);
                }
            }
        }
        else
        {
            if (handle->read_buf->into_udt_buf)
            {
                handle->read_buf->max_offset -=
                    (payload_size - handle->read_iovec[1].iov_len);
            }
        }
        /* This is not a regular fixed size packet */
        if (handle->read_iovec[1].iov_len != payload_size)
        {
             globus_l_xio_udt_add_irregular_pkt(
                 handle->irregular_pkt_info, seqno,
                 payload_size - handle->read_iovec[1].iov_len);
        }

        if (((seqno > curr_seqno) &&
            (seqno - curr_seqno < GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) ||
            (seqno < curr_seqno - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
        {
            /*
             * The packet that has been received now is new and is not a
             * retransmitted one. So update the current largest seqno
             */
            handle->read_cntl->curr_seqno = seqno;

            /* Speculate next packet. */
            handle->read_cntl->next_expect =
                (seqno + 1) % GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
        }
        else
        {
            /*
             * It is a retransmitted packet, remove it from reader
             * loss list.
             */
            globus_l_xio_udt_reader_loss_list_remove(
                handle->reader_loss_info, seqno);
            if (handle->read_iovec[1].iov_len < payload_size)
            {
                globus_l_xio_udt_compact_read_buf(
                    handle->read_buf, (offset + 1) * payload_size -
                    globus_l_xio_udt_get_error_size(
                        handle->irregular_pkt_info, seqno),
                    payload_size - handle->read_iovec[1].iov_len);
            }
        }
    }
    else
    {       
        /*  
         * Data is too old, discard it!
         */     
        if (handle->read_buf->into_udt_buf)
        {           
            handle->read_buf->max_offset -= payload_size;
        }       
                    
    }                   
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
        
error_no_space:
    GlobusXIOUdtDebugExitWithError();
    return GlobusXIOUdtErrorReadBufferFull();
            
}

      /*
       *  Functionality:
       *     This gets called when user calls globus_xio_read. if enough data
       *     is already read into the protocol buffer, it just copies that data
       *     to user buf, else it registers the user buffer so that the later
       *     arriving data could directly be placed into the user buf
       *  Parameters:
       *     1) [in] driver_handle: udt driver handle
       *     2) [in] iovec: user's vector
       *     3) [in] iovec_count: vector count
       *     4) [in] op: xio operation
       *  Returned value:
       *     GLOBUS_SUCCESS
       */

globus_result_t
globus_l_xio_udt_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t*           iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{   
    globus_l_handle_t *                 handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    
    GlobusXIOName(globus_l_xio_udt_read);
    
    GlobusXIOUdtDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    if ((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
        (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT))
    {   
        int len = 0;
        int i;
        globus_result_t read_result = GLOBUS_SUCCESS;
        int bytes_copied;
        
        /* Check if there is enough data now. */
        for (i = iovec_count - 1; i >= 0; --i)
        {   
            len += iovec[i].iov_len;
        }
        globus_mutex_lock(&handle->read_buf->mutex);
        handle->read_buf->user_iovec = (globus_xio_iovec_t*)iovec;
        handle->read_buf->temp_len = len;
        handle->read_buf->user_iovec_count = iovec_count;
        handle->user_read_op = op; 
        handle->read_buf->wait_for =
            globus_xio_operation_get_wait_for(handle->user_read_op);
        GlobusXIOUdtDebugPrintf(
            GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("inside read wait_for = %d len = %d\n",
            handle->read_buf->wait_for, len));
        if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
        {   
            int last_ack_pos = handle->read_buf->last_ack_pos;
            int start_pos = handle->read_buf->start_pos;
            int temp_len = handle->read_buf->temp_len;
            
            if (last_ack_pos >= start_pos)
            {
                handle->read_buf->wait_for = last_ack_pos - start_pos;
            }
            else
            {
                handle->read_buf->wait_for =
                    handle->read_buf->udt_buf_size + last_ack_pos - start_pos;
            }
            if (handle->read_buf->wait_for <= temp_len)
            {
                read_result = GlobusXIOErrorEOF();
            }
            else
            {
                handle->read_buf->wait_for = temp_len;
            }
        }
        bytes_copied = globus_l_xio_udt_copy_data_to_user_buf(
            handle->read_buf,  handle->read_buf->user_iovec,
            handle->read_buf->user_iovec_count,
            handle->read_buf->temp_len);

        if (bytes_copied >= handle->read_buf->wait_for)
        {
            globus_mutex_unlock(&handle->read_buf->mutex);
            globus_xio_driver_finished_read(op,
                read_result, bytes_copied);
        }
        else
        {
            handle->read_buf->user_buf = GLOBUS_TRUE;
            globus_mutex_unlock(&handle->read_buf->mutex);
        }
    }
    else
    {
        result = GlobusXIOUdtErrorBrokenConnection();
    }

    GlobusXIOUdtDebugExit();
    return result;
}               
