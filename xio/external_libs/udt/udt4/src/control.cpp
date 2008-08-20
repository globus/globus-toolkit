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
   Yunhong Gu, last updated 07/17/2007
*****************************************************************************/

#ifdef WIN32
   #include <winsock2.h>
   #include <ws2tcpip.h>
#endif

#include <string.h>
#include "control.h"
#include "core.h"

using namespace std;

bool CIPComp::operator()(const CHistoryBlock* hb1, const CHistoryBlock* hb2) const
{
   if (hb1->m_iIPversion != hb2->m_iIPversion)
      return (hb1->m_iIPversion < hb2->m_iIPversion);
   else if (hb1->m_iIPversion == AF_INET)
      return (hb1->m_IP[0] > hb2->m_IP[0]);
   else
   {
      for (int i = 0; i < 4; ++ i)
      {
         if (hb1->m_IP[i] != hb2->m_IP[i])
            return (hb1->m_IP[i] > hb2->m_IP[i]);
      }
      return false;
   }
}

bool CTSComp::operator()(const CHistoryBlock* hb1, const CHistoryBlock* hb2) const
{
   return (hb1->m_ullTimeStamp > hb2->m_ullTimeStamp);
}

CHistory::CHistory():
m_uiSize(1024)
{
   #ifndef WIN32
      pthread_mutex_init(&m_Lock, NULL);
   #else
      m_Lock = CreateMutex(NULL, false, NULL);
   #endif
}

CHistory::CHistory(const unsigned int& size):
m_uiSize(size)
{
   #ifndef WIN32
      pthread_mutex_init(&m_Lock, NULL);
   #else
      m_Lock = CreateMutex(NULL, false, NULL);
   #endif
}

CHistory::~CHistory()
{
   for (set<CHistoryBlock*, CTSComp>::iterator i = m_sTSIndex.begin(); i != m_sTSIndex.end(); ++ i)
      delete *i;

   #ifndef WIN32
      pthread_mutex_destroy(&m_Lock);
   #else
      CloseHandle(m_Lock);
   #endif
}

void CHistory::update(const sockaddr* addr, const int& ver, const int& rtt, const int& bw)
{
   CGuard hbguard(m_Lock);

   CHistoryBlock* hb = new CHistoryBlock;
   convert(addr, ver, hb->m_IP);
   hb->m_iIPversion = ver;

   set<CHistoryBlock*, CIPComp>::iterator i = m_sIPIndex.find(hb);

   if (i != m_sIPIndex.end())
   {
      m_sTSIndex.erase(*i);
      delete *i;
      m_sIPIndex.erase(i);
   }

   hb->m_iRTT = rtt;
   hb->m_iBandwidth = bw;
   hb->m_ullTimeStamp = CTimer::getTime();
   m_sIPIndex.insert(hb);
   m_sTSIndex.insert(hb);

   if (m_sTSIndex.size() > m_uiSize)
   {
      hb = *m_sTSIndex.begin();
      m_sIPIndex.erase(hb);
      m_sTSIndex.erase(m_sTSIndex.begin());
      delete hb;
   }
}

void CHistory::update(const CHistoryBlock* info)
{
   CGuard hbguard(m_Lock);

   CHistoryBlock* hb = new CHistoryBlock;
   memcpy((char*)hb, (char*)info, sizeof(CHistoryBlock));

   set<CHistoryBlock*, CIPComp>::iterator i = m_sIPIndex.find(hb);

   if (i != m_sIPIndex.end())
   {
      m_sTSIndex.erase(*i);
      delete *i;
      m_sIPIndex.erase(i);
   }

   hb->m_ullTimeStamp = CTimer::getTime();
   m_sIPIndex.insert(hb);
   m_sTSIndex.insert(hb);

   if (m_sTSIndex.size() > m_uiSize)
   {
      hb = *m_sTSIndex.begin();
      m_sIPIndex.erase(hb);
      m_sTSIndex.erase(m_sTSIndex.begin());
      delete hb;
   }
}

int CHistory::lookup(const sockaddr* addr, const int& ver, CHistoryBlock* hb)
{
   CGuard hbguard(m_Lock);

   convert(addr, ver, hb->m_IP);
   hb->m_iIPversion = ver;

   set<CHistoryBlock*, CIPComp>::iterator i = m_sIPIndex.find(hb);

   if (i == m_sIPIndex.end())
      return -1;

   hb->m_ullTimeStamp = (*i)->m_ullTimeStamp;
   hb->m_iRTT = (*i)->m_iRTT;
   hb->m_iBandwidth = (*i)->m_iBandwidth;

   return 1;
}

void CHistory::convert(const sockaddr* addr, const int& ver, uint32_t* ip)
{
   if (ver == AF_INET)
   {
      ip[0] = ((sockaddr_in*)addr)->sin_addr.s_addr;
      ip[1] = ip[2] = ip[3] = 0;
   }
   else
   {
      memcpy((char*)ip, (char*)((sockaddr_in6*)addr)->sin6_addr.s6_addr, 16);
   }
}


//
bool CUDTComp::operator()(const CUDT* u1, const CUDT* u2) const
{
   return (u1->m_SocketID > u2->m_SocketID);
}

CControl::CControl()
{
   #ifndef WIN32
      pthread_mutex_init(&m_Lock, NULL);
   #else
      m_Lock = CreateMutex(NULL, false, NULL);
   #endif

   m_pHistoryRecord = new CHistory;   
}

CControl::~CControl()
{
   #ifndef WIN32
      pthread_mutex_destroy(&m_Lock);
   #else
      CloseHandle(m_Lock);
   #endif

   delete m_pHistoryRecord;
}

int CControl::join(CUDT* udt, const sockaddr* addr, const int& ver, int& rtt, int& bw)
{
   CGuard ctrlguard(m_Lock);

   CHistoryBlock* hb = new CHistoryBlock;
   int found = m_pHistoryRecord->lookup(addr, ver, hb);

   if (found > 0)
   {
      rtt = hb->m_iRTT;
      bw = hb->m_iBandwidth;
   }

   map<CHistoryBlock*, set<CUDT*, CUDTComp>, CIPComp>::iterator i = m_mControlBlock.find(hb);

   if (i == m_mControlBlock.end())
   {
      set<CUDT*, CUDTComp> tmp;
      m_mControlBlock[hb] = tmp;
      m_mControlBlock[hb].insert(udt);
      m_mUDTIndex[udt] = hb;
   }
   else
   {
      i->second.insert(udt);
      m_mUDTIndex[udt] = i->first;
      delete hb;
   }

   if (found < 0)
      return -1;

   return 1;
}

void CControl::leave(CUDT* udt, const int& rtt, const int& bw)
{
   CGuard ctrlguard(m_Lock);

   CHistoryBlock* hb = m_mUDTIndex[udt];
   map<CHistoryBlock*, set<CUDT*, CUDTComp>, CIPComp>::iterator i = m_mControlBlock.find(hb);

   hb->m_iRTT = rtt;
   hb->m_iBandwidth = bw;
   m_pHistoryRecord->update(hb);

   i->second.erase(udt);
   if (i->second.empty())
   {
      m_mControlBlock.erase(i);
      delete hb;
   }
   m_mUDTIndex.erase(udt);
}
