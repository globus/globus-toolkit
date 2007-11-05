/*****************************************************************************
Copyright (c) 2001 - 2007, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 09/19/2007
*****************************************************************************/

#include <cstring>
#include <cmath>
#include "buffer.h"

using namespace std;

CSndBuffer::CSndBuffer(const int& mss):
m_pBlock(NULL),
m_pLastBlock(NULL),
m_pCurrSendBlk(NULL),
m_pCurrAckBlk(NULL),
m_iCurrBufSize(0),
m_iCurrSendPnt(0),
m_iCurrAckPnt(0),
m_iNextMsgNo(0),
m_iMSS(mss)
{
   #ifndef WIN32
      pthread_mutex_init(&m_BufLock, NULL);
   #else
      m_BufLock = CreateMutex(NULL, false, NULL);
   #endif
}

CSndBuffer::~CSndBuffer()
{
   Block* pb = m_pBlock;

   // Release allocated data structure if there is any
   while (NULL != m_pBlock)
   {
      pb = pb->m_next;

      // release sender buffer
      delete [] m_pBlock->m_pcData;

      delete m_pBlock;
      m_pBlock = pb;
   }

   #ifndef WIN32
      pthread_mutex_destroy(&m_BufLock);
   #else
      CloseHandle(m_BufLock);
   #endif
}

void CSndBuffer::addBuffer(const char* data, const int& len, const int& ttl, const int32_t& seqno, const bool& order)
{
   CGuard bufferguard(m_BufLock);

   if (NULL == m_pBlock)
   {
      // Insert a block to the empty list   
  
      m_pBlock = new Block;
      m_pBlock->m_pcData = const_cast<char*>(data);
      m_pBlock->m_iLength = len;
      m_pBlock->m_OriginTime = CTimer::getTime();
      m_pBlock->m_iTTL = ttl;
      m_pBlock->m_iMsgNo = m_iNextMsgNo;
      m_pBlock->m_iSeqNo = seqno;
      m_pBlock->m_iInOrder = order;
      m_pBlock->m_iInOrder <<= 29;
      m_pBlock->m_next = NULL;
      m_pLastBlock = m_pBlock;
      m_pCurrSendBlk = m_pBlock;
      m_iCurrSendPnt = 0;
      m_pCurrAckBlk = m_pBlock;
      m_iCurrAckPnt = 0;
   }
   else
   {
      // Insert a new block to the tail of the list

      int32_t lastseq = m_pLastBlock->m_iSeqNo;
      int offset = m_pLastBlock->m_iLength;

      m_pLastBlock->m_next = new Block;
      m_pLastBlock = m_pLastBlock->m_next;
      m_pLastBlock->m_pcData = const_cast<char*>(data);
      m_pLastBlock->m_iLength = len;
      m_pLastBlock->m_OriginTime = CTimer::getTime();
      m_pLastBlock->m_iTTL = ttl;
      m_pLastBlock->m_iMsgNo = m_iNextMsgNo;
      m_pLastBlock->m_iSeqNo = lastseq + (int32_t)ceil(double(offset) / m_iMSS);
      m_pLastBlock->m_iInOrder = order;
      m_pLastBlock->m_iInOrder <<= 29;
      m_pLastBlock->m_next = NULL;
      if (NULL == m_pCurrSendBlk)
         m_pCurrSendBlk = m_pLastBlock;
   }

   m_iNextMsgNo = CMsgNo::incmsg(m_iNextMsgNo);

   m_iCurrBufSize += len;
}

int CSndBuffer::readData(char** data, const int& len, int32_t& msgno)
{
   CGuard bufferguard(m_BufLock);

   // No data to read
   if (NULL == m_pCurrSendBlk)
      return 0;

   // read data in the current sending block
   if (m_iCurrSendPnt + len < m_pCurrSendBlk->m_iLength)
   {
      *data = m_pCurrSendBlk->m_pcData + m_iCurrSendPnt;

      msgno = m_pCurrSendBlk->m_iMsgNo | m_pCurrSendBlk->m_iInOrder;
      if (0 == m_iCurrSendPnt)
         msgno |= 0x80000000;
      if (m_pCurrSendBlk->m_iLength == m_iCurrSendPnt + len)
         msgno |= 0x40000000;

      m_iCurrSendPnt += len;

      return len;
   }

   // Not enough data to read. 
   // Read an irregular packet and move the current sending block pointer to the next block
   int readlen = m_pCurrSendBlk->m_iLength - m_iCurrSendPnt;
   *data = m_pCurrSendBlk->m_pcData + m_iCurrSendPnt;

   if (0 == m_iCurrSendPnt)
      msgno = m_pCurrSendBlk->m_iMsgNo | 0xC0000000 | m_pCurrSendBlk->m_iInOrder;
   else
      msgno = m_pCurrSendBlk->m_iMsgNo | 0x40000000 | m_pCurrSendBlk->m_iInOrder;

   m_pCurrSendBlk = m_pCurrSendBlk->m_next;
   m_iCurrSendPnt = 0;

   return readlen;
}

int CSndBuffer::readData(char** data, const int offset, const int& len, int32_t& msgno, int32_t& seqno, int& msglen)
{
   CGuard bufferguard(m_BufLock);

   Block* p = m_pCurrAckBlk;

   // No data to read
   if (NULL == p)
      return 0;

   // Locate to the data position by the offset
   int loffset = offset + m_iCurrAckPnt;
   while (p->m_iLength <= loffset)
   {
      loffset -= p->m_iLength;
      loffset -= len - ((0 == p->m_iLength % len) ? len : (p->m_iLength % len));
      p = p->m_next;
      if (NULL == p)
         return 0;
   }

   if (p->m_iTTL >= 0)
   {
      if ((CTimer::getTime() - p->m_OriginTime) / 1000 > (uint64_t)p->m_iTTL)
      {
         msgno = p->m_iMsgNo;
         seqno = p->m_iSeqNo;
         msglen = p->m_iLength;

         return -1;
      }
   }

   // Read a regular data
   if (loffset + len <= p->m_iLength)
   {
      *data = p->m_pcData + loffset;
      msgno = p->m_iMsgNo | p->m_iInOrder;

      if (0 == loffset)
         msgno |= 0x80000000;
      if (p->m_iLength == loffset + len)
         msgno |= 0x40000000;

      return len;
   }

   // Read an irrugular data at the end of a block
   *data = p->m_pcData + loffset;
   msgno = p->m_iMsgNo | p->m_iInOrder;

   if (0 == loffset)
      msgno |= 0xC0000000;
   else
      msgno |= 0x40000000;

   return p->m_iLength - loffset;
}

void CSndBuffer::ackData(const int& len, const int& payloadsize)
{
   CGuard bufferguard(m_BufLock);

   m_iCurrAckPnt += len;

   // Remove the block if it is acknowledged
   while (m_iCurrAckPnt >= m_pCurrAckBlk->m_iLength)
   {
      m_iCurrAckPnt -= m_pCurrAckBlk->m_iLength;

      // Update the size error between regular and irregular packets
      if (0 != m_pCurrAckBlk->m_iLength % payloadsize)
         m_iCurrAckPnt -= payloadsize - (m_pCurrAckBlk->m_iLength % payloadsize);

      m_iCurrBufSize -= m_pCurrAckBlk->m_iLength;
      m_pCurrAckBlk = m_pCurrAckBlk->m_next;

      // release the buffer
      delete [] m_pBlock->m_pcData;

      delete m_pBlock;
      m_pBlock = m_pCurrAckBlk;

      CTimer::triggerEvent();

      if (NULL == m_pBlock)
         break;
   }
}

int CSndBuffer::getCurrBufSize() const
{
   return m_iCurrBufSize - m_iCurrAckPnt;
}

////////////////////////////////////////////////////////////////////////////////

CRcvBuffer::CRcvBuffer(CUnitQueue* queue):
m_pUnit(NULL),
m_iSize(65536),
m_pUnitQueue(queue),
m_iStartPos(0),
m_iLastAckPos(0),
m_iMaxPos(-1),
m_iNotch(0)
{
   m_pUnit = new CUnit* [m_iSize];
}

CRcvBuffer::CRcvBuffer(const int& bufsize, CUnitQueue* queue):
m_pUnit(NULL),
m_iSize(bufsize),
m_pUnitQueue(queue),
m_iStartPos(0),
m_iLastAckPos(0),
m_iMaxPos(-1),
m_iNotch(0)
{
   m_pUnit = new CUnit* [m_iSize];
   for (int i = 0; i < m_iSize; ++ i)
      m_pUnit[i] = NULL;
}

CRcvBuffer::~CRcvBuffer()
{
   for (int i = 0; i < m_iSize; ++ i)
   {
      if (NULL != m_pUnit[i])
      {
         m_pUnit[i]->m_iFlag = 0;
         -- m_pUnitQueue->m_iCount;
      }
   }

   delete [] m_pUnit;
}

int CRcvBuffer::addData(CUnit* unit, int offset)
{
   int pos = (m_iLastAckPos + offset) % m_iSize;
   if (offset > m_iMaxPos)
      m_iMaxPos = offset;

   if (NULL != m_pUnit[pos])
      return -1;
   
   m_pUnit[pos] = unit;

   unit->m_iFlag = 1;
   ++ m_pUnitQueue->m_iCount;

   return 0;
}

int CRcvBuffer::readBuffer(char* data, const int& len)
{
   int p = m_iStartPos;
   int lastack = m_iLastAckPos;
   int rs = len;

   while ((p != lastack) && (rs > 0))
   {
      int unitsize = m_pUnit[p]->m_Packet.getLength() - m_iNotch;
      if (unitsize > rs)
         unitsize = rs;

      memcpy(data, m_pUnit[p]->m_Packet.m_pcData + m_iNotch, unitsize);
      data += unitsize;

      if ((rs > unitsize) || (rs == m_pUnit[p]->m_Packet.getLength() - m_iNotch))
      {
         CUnit* tmp = m_pUnit[p];
         m_pUnit[p] = NULL;
         tmp->m_iFlag = 0;
         -- m_pUnitQueue->m_iCount;

         if (++ p == m_iSize)
            p = 0;

         m_iNotch = 0;
      }
      else
         m_iNotch += rs;

      rs -= unitsize;
   }

   m_iStartPos = p;
   return len - rs;
}

int CRcvBuffer::readBufferToFile(ofstream& file, const int& len)
{
   int p = m_iStartPos;
   int lastack = m_iLastAckPos;
   int rs = len;

   while ((p != lastack) && (rs > 0))
   {
      int unitsize = m_pUnit[p]->m_Packet.getLength() - m_iNotch;
      if (unitsize > rs)
         unitsize = rs;

      file.write(m_pUnit[p]->m_Packet.m_pcData + m_iNotch, unitsize);

      if ((rs > unitsize) || (rs == m_pUnit[p]->m_Packet.getLength() - m_iNotch))
      {
         CUnit* tmp = m_pUnit[p];
         m_pUnit[p] = NULL;
         tmp->m_iFlag = 0;
         -- m_pUnitQueue->m_iCount;

         if (++ p == m_iSize)
            p = 0;

         m_iNotch = 0;
      }
      else
         m_iNotch += rs;

      rs -= unitsize;
   }

   m_iStartPos = p;
   return len - rs;
}

void CRcvBuffer::ackData(const int& len)
{
   m_iLastAckPos = (m_iLastAckPos + len) % m_iSize;
   m_iMaxPos -= len;

   CTimer::triggerEvent();
}

int CRcvBuffer::getAvailBufSize() const
{
   // One slot must be empty in order to tell the different between "empty buffer" and "full buffer"
   return m_iSize - getRcvDataSize() - 1;
}

int CRcvBuffer::getRcvDataSize() const
{
   if (m_iLastAckPos >= m_iStartPos)
      return m_iLastAckPos - m_iStartPos;

   return m_iSize + m_iLastAckPos - m_iStartPos;
}

void CRcvBuffer::dropMsg(const int32_t& msgno)
{
   for (int i = m_iStartPos, n = (m_iLastAckPos + m_iMaxPos) % m_iSize; i != n; i = (i + 1) % m_iSize)
      if ((NULL != m_pUnit[i]) && (msgno == m_pUnit[i]->m_Packet.m_iMsgNo))
         m_pUnit[i]->m_iFlag = 3;
}

int CRcvBuffer::readMsg(char* data, const int& len)
{
   int p, q;
   bool passack;
   if (!scanMsg(p, q, passack))
      return 0;

   int rs = len;
   while (p != (q + 1) % m_iSize)
   {
      int unitsize = m_pUnit[p]->m_Packet.getLength();
      if ((rs >= 0) && (unitsize > rs))
         unitsize = rs;

      if (unitsize > 0)
      {
         memcpy(data, m_pUnit[p]->m_Packet.m_pcData, unitsize);
         data += unitsize;
         rs -= unitsize;
      }

      if (!passack)
      {
         CUnit* tmp = m_pUnit[p];
         m_pUnit[p] = NULL;
         tmp->m_iFlag = 0;
         -- m_pUnitQueue->m_iCount;
      }
      else
         m_pUnit[p]->m_iFlag = 2;

      if (++ p == m_iSize)
         p = 0;
   }

   if (!passack)
      m_iStartPos = (q + 1) % m_iSize;

   return len - rs;
}

int CRcvBuffer::getRcvMsgNum()
{
   int p, q;
   bool passack;
   return scanMsg(p, q, passack) ? 1 : 0;
}

bool CRcvBuffer::scanMsg(int& p, int& q, bool& passack)
{
   // empty buffer
   if ((m_iStartPos == m_iLastAckPos) && (0 == m_iMaxPos))
      return false;

   //skip all bad msgs at the beginning
   while (m_iStartPos != m_iLastAckPos)
   {
      if ((1 == m_pUnit[m_iStartPos]->m_iFlag) && (m_pUnit[m_iStartPos]->m_Packet.getMsgBoundary() > 1))
         break;

      CUnit* tmp = m_pUnit[m_iStartPos];
      m_pUnit[m_iStartPos] = NULL;
      tmp->m_iFlag = 0;
      -- m_pUnitQueue->m_iCount;

      if (++ m_iStartPos == m_iSize)
         m_iStartPos = 0;
   }

   p = -1;                  // message head
   q = m_iStartPos;         // message tail
   passack = m_iStartPos == m_iLastAckPos;
   bool found = false;

   // looking for the first message
   for (int i = 0, n = m_iMaxPos + getRcvDataSize(); i <= n; ++ i)
   {
      if ((NULL != m_pUnit[q]) && (1 == m_pUnit[q]->m_iFlag))
      {
         switch (m_pUnit[q]->m_Packet.getMsgBoundary())
         {
         case 3: // 11
            p = q;
            found = true;
            break;

         case 2: // 10
            p = q;
            break;

         case 1: // 01
            if (p != -1)
               found = true;
         }
      }
      else
      {
         // a hole in this message, not valid, restart search
         p = -1;
      }

      if (found)
      {
         // the msg has to be ack'ed or it is allowed to read out of order, and was not read before
         if (!passack || !m_pUnit[q]->m_Packet.getMsgOrderFlag())
            break;

         found = false;
      }

      if (++ q == m_iSize)
         q = 0;

      if (q == m_iLastAckPos)
         passack = true;
   }

   // no msg found
   if (!found)
   {
      // if the message is larger than the receiver buffer, return part of the message
      if ((p != -1) && ((q + 1) % m_iSize == p))
         found = true;
   }

   return found;
}
