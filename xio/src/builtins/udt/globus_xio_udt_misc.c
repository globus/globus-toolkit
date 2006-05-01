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

/*
 * This function is to find the minimum among 3 numbers
 */

int
globus_l_xio_udt_min3(
    int                 a,
    int                 b,
    int                 c)
{
    int min;
    GlobusXIOName(globus_l_xio_udt_min3);
    if (a < b)
    {
        min = a;
    }
    else
    {
        min = b;
    }
    if (c < min)
    {
        min = c;
    }
    return min;
}


/*
 * the following are the functions used in 3 lists (writer_loss,
 * reader_loss, irregular_pkt)
 */

/* Definition of >, <, >=, and <= with sequence number wrap */

globus_bool_t
globus_l_xio_udt_greater_than(
    int                         seqno1,
    int                         seqno2)
{
    GlobusXIOName(globus_l_xio_udt_greater_than);
    if (((seqno1 > seqno2) && (seqno1 - seqno2 <
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || (seqno1 < seqno2 -
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
      return GLOBUS_TRUE;
    
    /* 
     * if (seqno1 < seqno2 - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH), it means
     * seqno1 crossed MAX_SEQNO but since the difference is less than
     * GLOBUS_L_XIO_UDT_SEQ_NO_THRESH seqno1 is greater than seqno2
     */         
    return GLOBUS_FALSE;
}

globus_bool_t 
globus_l_xio_udt_less_than(     
    int                         seqno1,
    int                         seqno2)
{   
    GlobusXIOName(globus_l_xio_udt_less_than);
    return globus_l_xio_udt_greater_than(seqno2, seqno1);
}

globus_bool_t 
globus_l_xio_udt_not_less_than(         
    int                                 seqno1,
    int                                 seqno2)
{  
   GlobusXIOName(globus_l_xio_udt_not_less_than);
   if (seqno1 == seqno2)
      return GLOBUS_TRUE;
   
   return globus_l_xio_udt_greater_than(seqno1, seqno2);
}

globus_bool_t 
globus_l_xio_udt_not_greater_than(      
    int                                 seqno1,
    int                                 seqno2)
{
    GlobusXIOName(globus_l_xio_udt_not_greater_than);
    if (seqno1 == seqno2)
      return GLOBUS_TRUE;

    return globus_l_xio_udt_less_than(seqno1, seqno2);
}

int
globus_l_xio_udt_min_seqno(
    int                         seqno1,
    int                         seqno2)
{
    GlobusXIOName(globus_l_xio_udt_min_seqno);
    if (globus_l_xio_udt_less_than(seqno1, seqno2))
        return seqno1;
    return seqno2;
}

int
globus_l_xio_udt_max_seqno(
    int                         seqno1,
    int                         seqno2)
{
    GlobusXIOName(globus_l_xio_udt_max_seqno);
    if (globus_l_xio_udt_greater_than(seqno1, seqno2))
        return seqno1;
    return seqno2;
}

int
globus_l_xio_udt_get_length(
    int                         seqno1,
    int                         seqno2)
{
    int length = 0;
    GlobusXIOName(globus_l_xio_udt_get_length);

    /*
     * I'm making sure that the difference between the 2 sequence numbers
     * should not be greater than GLOBUS_L_XIO_UDT_SEQ_NO_THRESH only for
     * the case seqno2 < seqno1 and not for seqno1 > seqno2 coz in fact such
     * call like getLength(1, 2^30) should never happen. The parameters of
     * seqno1 and seqno2 are checked(explicity or implicitly) before
     * getLength() is called. However, such call as getLength(3, 2) can
     * happen, which is not right. So the condition is checked. (Such call
     * should return 0)
     */

    if (seqno2 >= seqno1)
    {
        length = seqno2 - seqno1 + 1;
    }
    else if (seqno2 < seqno1 - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
        length = seqno2 - seqno1 + GLOBUS_L_XIO_UDT_MAX_SEQ_NO + 1;
    }
    return length;
}

/*Definition of ++, and -- with sequence number wrap */

int
globus_l_xio_udt_inc_seqno(
    int                         seqno)
{
    GlobusXIOName(globus_l_xio_udt_inc_seqno);
    return (seqno + 1) % GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
}
    
int
globus_l_xio_udt_dec_seqno(
    int                         seqno)
{       
    GlobusXIOName(globus_l_xio_udt_dec_seqno);
    return (seqno - 1 + GLOBUS_L_XIO_UDT_MAX_SEQ_NO) %
            GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
}

