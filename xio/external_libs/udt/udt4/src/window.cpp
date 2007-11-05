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
   Yunhong Gu, last updated 08/22/2007
*****************************************************************************/

#include <cmath>
#include "common.h"
#include "window.h"


CACKWindow::CACKWindow():
m_piACKSeqNo(NULL),
m_piACK(NULL),
m_pTimeStamp(NULL),
m_iSize(1024),
m_iHead(0),
m_iTail(0)
{
   m_piACKSeqNo = new int32_t[m_iSize];
   m_piACK = new int32_t[m_iSize];
   m_pTimeStamp = new uint64_t[m_iSize];

   m_piACKSeqNo[0] = -1;
}

CACKWindow::CACKWindow(const int& size):
m_piACKSeqNo(NULL),
m_piACK(NULL),
m_pTimeStamp(NULL),
m_iSize(size),
m_iHead(0),
m_iTail(0)
{
   m_piACKSeqNo = new int32_t[m_iSize];
   m_piACK = new int32_t[m_iSize];
   m_pTimeStamp = new uint64_t[m_iSize];

   m_piACKSeqNo[0] = -1;
}

CACKWindow::~CACKWindow()
{
   delete [] m_piACKSeqNo;
   delete [] m_piACK;
   delete [] m_pTimeStamp;
}

void CACKWindow::store(const int32_t& seq, const int32_t& ack)
{
   m_piACKSeqNo[m_iHead] = seq;
   m_piACK[m_iHead] = ack;
   m_pTimeStamp[m_iHead] = CTimer::getTime();

   m_iHead = (m_iHead + 1) % m_iSize;

   // overwrite the oldest ACK since it is not likely to be acknowledged
   if (m_iHead == m_iTail)
      m_iTail = (m_iTail + 1) % m_iSize;
}

int CACKWindow::acknowledge(const int32_t& seq, int32_t& ack)
{
   if (m_iHead >= m_iTail)
   {
      // Head has not exceeded the physical boundary of the window

      for (int i = m_iTail, n = m_iHead; i < n; ++ i)
         // looking for indentical ACK Seq. No.
         if (seq == m_piACKSeqNo[i])
         {
            // return the Data ACK it carried
            ack = m_piACK[i];

            // calculate RTT
            int rtt = int(CTimer::getTime() - m_pTimeStamp[i]);
            if (i == m_iHead)
            {
               m_iTail = m_iHead = 0;
               m_piACKSeqNo[0] = -1;
            }
            else
               m_iTail = (i + 1) % m_iSize;

            return rtt;
         }

      // Bad input, the ACK node has been overwritten
      return -1;
   }

   // Head has exceeded the physical window boundary, so it is behind tail
   for (int j = m_iTail, n = m_iHead + m_iSize; j < n; ++ j)
      // looking for indentical ACK seq. no.
      if (seq == m_piACKSeqNo[j % m_iSize])
      {
         // return Data ACK
         j %= m_iSize;
         ack = m_piACK[j];

         // calculate RTT
         int rtt = int(CTimer::getTime() - m_pTimeStamp[j]);
         if (j == m_iHead)
         {
            m_iTail = m_iHead = 0;
            m_piACKSeqNo[0] = -1;
         }
         else
            m_iTail = (j + 1) % m_iSize;

         return rtt;
      }

   // bad input, the ACK node has been overwritten
   return -1;
}

////////////////////////////////////////////////////////////////////////////////

CPktTimeWindow::CPktTimeWindow():
m_iAWSize(16),
m_piPktWindow(NULL),
m_iPWSize(16),
m_piProbeWindow(NULL)
{
   m_piPktWindow = new int[m_iAWSize];
   m_piProbeWindow = new int[m_iPWSize];

   m_iPktWindowPtr = 0;
   m_iProbeWindowPtr = 0;

   m_LastArrTime = CTimer::getTime();

   m_iLastSentTime = 0;
   m_iMinPktSndInt = 1000000;

   for (int i = 0; i < m_iAWSize; ++ i)
      m_piPktWindow[i] = 1;

   for (int k = 0; k < m_iPWSize; ++ k)
      m_piProbeWindow[k] = 1000;
}

CPktTimeWindow::CPktTimeWindow(const int& asize, const int& psize):
m_iAWSize(asize),
m_piPktWindow(NULL),
m_iPWSize(psize),
m_piProbeWindow(NULL)
{
   m_piPktWindow = new int[m_iAWSize];
   m_piProbeWindow = new int[m_iPWSize];

   m_iPktWindowPtr = 0;
   m_iProbeWindowPtr = 0;

   m_LastArrTime = CTimer::getTime();

   m_iLastSentTime = 0;
   m_iMinPktSndInt = 1000000;

   for (int i = 0; i < m_iAWSize; ++ i)
      m_piPktWindow[i] = 1;

   for (int k = 0; k < m_iPWSize; ++ k)
      m_piProbeWindow[k] = 1000;
}

CPktTimeWindow::~CPktTimeWindow()
{
   delete [] m_piPktWindow;
   delete [] m_piProbeWindow;
}

int CPktTimeWindow::getMinPktSndInt() const
{
   return m_iMinPktSndInt;
}

int CPktTimeWindow::getPktRcvSpeed() const
{
   // sorting
   int temp;
   for (int i = 0, n = (m_iAWSize >> 1) + 1; i < n; ++ i)
      for (int j = i, m = m_iAWSize; j < m; ++ j)
         if (m_piPktWindow[i] > m_piPktWindow[j])
         {
            temp = m_piPktWindow[i];
            m_piPktWindow[i] = m_piPktWindow[j];
            m_piPktWindow[j] = temp;
         }

   // read the median value
   int median = (m_piPktWindow[(m_iAWSize >> 1) - 1] + m_piPktWindow[m_iAWSize >> 1]) >> 1;
   int count = 0;
   int sum = 0;
   int upper = median << 3;
   int lower = median >> 3;

   // median filtering
   for (int k = 0, l = m_iAWSize; k < l; ++ k)
      if ((m_piPktWindow[k] < upper) && (m_piPktWindow[k] > lower))
      {
         ++ count;
         sum += m_piPktWindow[k];
      }

   // claculate speed, or return 0 if not enough valid value
   if (count > (m_iAWSize >> 1))
      return (int)ceil(1000000.0 / (sum / count));
   else
      return 0;
}

int CPktTimeWindow::getBandwidth() const
{
   // sorting
   int temp;
   for (int i = 0, n = (m_iPWSize >> 1) + 1; i < n; ++ i)
      for (int j = i, m = m_iPWSize; j < m; ++ j)
         if (m_piProbeWindow[i] > m_piProbeWindow[j])
         {
            temp = m_piProbeWindow[i];
            m_piProbeWindow[i] = m_piProbeWindow[j];
            m_piProbeWindow[j] = temp;
         }

   // read the median value
   int median = (m_piProbeWindow[(m_iPWSize >> 1) - 1] + m_piProbeWindow[m_iPWSize >> 1]) >> 1;
   int count = 1;
   int sum = median;
   int upper = median << 3;
   int lower = median >> 3;

   // median filtering
   for (int k = 0, l = m_iPWSize; k < l; ++ k)
      if ((m_piProbeWindow[k] < upper) && (m_piProbeWindow[k] > lower))
      {
         ++ count;
         sum += m_piProbeWindow[k];
      }

   return (int)ceil(1000000.0 / (double(sum) / double(count)));
}

void CPktTimeWindow::onPktSent(const int& currtime)
{
   int interval = currtime - m_iLastSentTime;

   if ((interval < m_iMinPktSndInt) && (interval > 0))
      m_iMinPktSndInt = interval;

   m_iLastSentTime = currtime;
}

void CPktTimeWindow::onPktArrival()
{
   m_CurrArrTime = CTimer::getTime();

   // record the packet interval between the current and the last one
   m_piPktWindow[m_iPktWindowPtr] = int(m_CurrArrTime - m_LastArrTime);

   // the window is logically circular
   m_iPktWindowPtr = (m_iPktWindowPtr + 1) % m_iAWSize;

   // remember last packet arrival time
   m_LastArrTime = m_CurrArrTime;
}

void CPktTimeWindow::probe1Arrival()
{
   m_ProbeTime = CTimer::getTime();
}

void CPktTimeWindow::probe2Arrival()
{
   m_CurrArrTime = CTimer::getTime();

   // record the probing packets interval
   m_piProbeWindow[m_iProbeWindowPtr] = int(m_CurrArrTime - m_ProbeTime);
   // the window is logically circular
   m_iProbeWindowPtr = (m_iProbeWindowPtr + 1) % m_iPWSize;
}
