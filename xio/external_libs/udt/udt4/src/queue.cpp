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
   Yunhong Gu, last updated 10/11/2007
*****************************************************************************/

#ifdef WIN32
   #include <winsock2.h>
   #include <ws2tcpip.h>
#endif

#include "common.h"
#include "queue.h"
#include "core.h"

using namespace std;

CUnitQueue::CUnitQueue():
m_pQEntry(NULL),
m_pCurrQueue(NULL),
m_pLastQueue(NULL),
m_iSize(0),
m_iCount(0)
{
}

CUnitQueue::~CUnitQueue()
{
   CQEntry* p = m_pQEntry;

   while (p != NULL)
   {
      delete [] p->m_pUnit;
      delete [] p->m_pBuffer;

      CQEntry* q = p;
      if (p == m_pLastQueue)
         p = NULL;
      else
         p = p->m_pNext;
      delete q;
   }
}

int CUnitQueue::init(const int& size, const int& mss, const int& version)
{
   CQEntry* tempq = NULL;
   CUnit* tempu = NULL;
   char* tempb = NULL;

   try
   {
      tempq = new CQEntry;
      tempu = new CUnit [size];
      tempb = new char [size * mss];
   }
   catch (...)
   {
      delete tempq;
      delete [] tempu;
      delete [] tempb;

      return -1;
   }

   for (int i = 0; i < size; ++ i)
   {
      tempu[i].m_iFlag = 0;
      tempu[i].m_Packet.m_pcData = tempb + i * mss;
   }
   tempq->m_pUnit = tempu;
   tempq->m_pBuffer = tempb;
   tempq->m_iSize = size;

   m_pQEntry = m_pCurrQueue = m_pLastQueue = tempq;
   m_pQEntry->m_pNext = m_pQEntry;

   m_pAvailUnit = m_pCurrQueue->m_pUnit;

   m_iSize = size;
   m_iMSS = mss;
   m_iIPversion = version;

   return 0;
}

int CUnitQueue::increase()
{
   // adjust/correct m_iCount
   int real_count = 0;
   CQEntry* p = m_pQEntry;
   while (p != NULL)
   {
      CUnit* u = p->m_pUnit;
      for (CUnit* end = u + p->m_iSize; u != end; ++ u)
         if (u->m_iFlag != 0)
            ++ real_count;

      if (p == m_pLastQueue)
         p = NULL;
      else
         p = p->m_pNext;
   }
   m_iCount = real_count;
   if (double(m_iCount) / m_iSize < 0.9)
      return -1;

   CQEntry* tempq = NULL;
   CUnit* tempu = NULL;
   char* tempb = NULL;

   // all queues have the same size
   int size = m_pQEntry->m_iSize;

   try
   {
      tempq = new CQEntry;
      tempu = new CUnit [size];
      tempb = new char [size * m_iMSS];
   }
   catch (...)
   {
      delete tempq;
      delete [] tempu;
      delete [] tempb;

      return -1;
   }

   for (int i = 0; i < size; ++ i)
   {
      tempu[i].m_iFlag = 0;
      tempu[i].m_Packet.m_pcData = tempb + i * m_iMSS;
   }
   tempq->m_pUnit = tempu;
   tempq->m_pBuffer = tempb;
   tempq->m_iSize = size;

   m_pLastQueue->m_pNext = tempq;
   m_pLastQueue = tempq;
   m_pLastQueue->m_pNext = m_pQEntry;

   m_iSize += size;

   return 0;
}

int CUnitQueue::shrink()
{
   // currently queue cannot be shrunk.
   return -1;
}

CUnit* CUnitQueue::getNextAvailUnit()
{
   if (double(m_iCount) / m_iSize > 0.9)
      increase();

   if (m_iCount >= m_iSize)
      return NULL;

   CQEntry* entrance = m_pCurrQueue;

   do
   {
      for (CUnit* sentinel = m_pCurrQueue->m_pUnit + m_pCurrQueue->m_iSize - 1; m_pAvailUnit != sentinel; ++ m_pAvailUnit)
         if (m_pAvailUnit->m_iFlag == 0)
            return m_pAvailUnit;

      if (m_pCurrQueue->m_pUnit->m_iFlag == 0)
      {
         m_pAvailUnit = m_pCurrQueue->m_pUnit;
         return m_pAvailUnit;
      }

      m_pCurrQueue = m_pCurrQueue->m_pNext;
      m_pAvailUnit = m_pCurrQueue->m_pUnit;
   } while (m_pCurrQueue != entrance);

   increase();

   return NULL;
}


CSndUList::CSndUList():
m_pUList(NULL),
m_pLast(NULL)
{
   #ifndef WIN32
      pthread_mutex_init(&m_ListLock, NULL);
   #else
      m_ListLock = CreateMutex(NULL, false, NULL);
   #endif
}

CSndUList::~CSndUList()
{
#ifndef WIN32
   pthread_mutex_destroy(&m_ListLock);
#else
   CloseHandle(m_ListLock);
#endif
}

void CSndUList::insert(const int64_t& ts, const int32_t& id, const CUDT* u)
{
   CGuard listguard(m_ListLock);

   CUDTList* n = u->m_pSNode;
   n->m_llTimeStamp = ts;

   if (NULL == m_pUList)
   {
      n->m_pPrev = n->m_pNext = NULL;
      m_pLast = m_pUList = n;

      // If UList was empty, signal the sending queue to restart
      #ifndef WIN32
         pthread_mutex_lock(m_pWindowLock);
         pthread_cond_signal(m_pWindowCond);
         pthread_mutex_unlock(m_pWindowLock);
      #else
         SetEvent(*m_pWindowCond);
      #endif

      return;
   }

   // SndUList is sorted by the next processing time

   if (n->m_llTimeStamp >= m_pLast->m_llTimeStamp)
   {
      // do not insert repeated node
      if (id == m_pLast->m_iID)
         return;

      // insert as the last node
      n->m_pPrev = m_pLast;
      n->m_pNext = NULL;
      m_pLast->m_pNext = n;
      m_pLast = n;

      return;
   }
   else if (n->m_llTimeStamp <= m_pUList->m_llTimeStamp)
   {
      // do not insert repeated node
      if (id == m_pUList->m_iID)
         return;

      // insert as the first node
      n->m_pPrev = NULL;
      n->m_pNext = m_pUList;
      m_pUList->m_pPrev = n;
      m_pUList = n;

      return;
   }

   // check somewhere in the middle
   CUDTList* p = m_pLast->m_pPrev;
   while (p->m_llTimeStamp > n->m_llTimeStamp)
      p = p->m_pPrev;

   // do not insert repeated node
   if ((id == p->m_iID) || (id == p->m_pNext->m_iID) || ((NULL != p->m_pPrev) && (id == p->m_pPrev->m_iID)))
      return;

   n->m_pPrev = p;
   n->m_pNext = p->m_pNext;
   p->m_pNext->m_pPrev = n;
   p->m_pNext = n;
}

void CSndUList::remove(const int32_t& id)
{
   CGuard listguard(m_ListLock);

   if (NULL == m_pUList)
      return;

   if (id == m_pUList->m_iID)
   {
      // check and remove the first node
      m_pUList = m_pUList->m_pNext;
      if (NULL == m_pUList)
         m_pLast = NULL;
      else
         m_pUList->m_pPrev = NULL;

      return;
   }

   // check further
   CUDTList* p = m_pUList->m_pNext;
   while (NULL != p)
   {
      if (id == p->m_iID)
      {
         p->m_pPrev->m_pNext = p->m_pNext;
         if (NULL != p->m_pNext)
            p->m_pNext->m_pPrev = p->m_pPrev;
         else
            m_pLast = p->m_pPrev;

         return;
      }

      p = p->m_pNext;
   }
}

void CSndUList::update(const int32_t& id, const CUDT* u, const bool& reschedule)
{
   CGuard listguard(m_ListLock);

   if (NULL == m_pUList)
   {
      // insert a new entry if the list was empty
      CUDTList* n = u->m_pSNode;
      n->m_llTimeStamp = 1;
      n->m_pPrev = n->m_pNext = NULL;
      m_pLast = m_pUList = n;

      #ifndef WIN32
         pthread_mutex_lock(m_pWindowLock);
         pthread_cond_signal(m_pWindowCond);
         pthread_mutex_unlock(m_pWindowLock);
      #else
         SetEvent(*m_pWindowCond);
      #endif

      return;
   }

   if (id == m_pUList->m_iID)
   {
      if (reschedule)
         m_pUList->m_llTimeStamp = 1;
      return;
   }

   // remove the old entry
   CUDTList* p = m_pUList->m_pNext;
   while (NULL != p)
   {
      if (id == p->m_iID)
      {
         if (!reschedule)
            return;

         p->m_pPrev->m_pNext = p->m_pNext;
         if (NULL != p->m_pNext)
            p->m_pNext->m_pPrev = p->m_pPrev;
         else
            m_pLast = p->m_pPrev;

         break;
      }

      p = p->m_pNext;
   }

   // insert at head
   CUDTList* n = u->m_pSNode;
   n->m_llTimeStamp = 1;
   n->m_pPrev = NULL;
   n->m_pNext = m_pUList;
   m_pUList->m_pPrev = n;
   m_pUList = n;
}

int CSndUList::pop(int32_t& id, CUDT*& u)
{
   CGuard listguard(m_ListLock);

   if (NULL == m_pUList)
      return -1;

   id = m_pUList->m_iID;
   u = m_pUList->m_pUDT;

   m_pUList = m_pUList->m_pNext;
   if (NULL == m_pUList)
      m_pLast = NULL;
   else
      m_pUList->m_pPrev = NULL;

   return id;
}


//
CSndQueue::CSndQueue():
m_pSndUList(NULL),
m_pChannel(NULL),
m_pTimer(NULL),
m_bClosing(false)
{
   #ifndef WIN32
      pthread_cond_init(&m_WindowCond, NULL);
      pthread_mutex_init(&m_WindowLock, NULL);
   #else
      m_WindowLock = CreateMutex(NULL, false, NULL);
      m_WindowCond = CreateEvent(NULL, false, false, NULL);
   #endif
}

CSndQueue::~CSndQueue()
{
   m_bClosing = true;

   #ifndef WIN32
      pthread_mutex_lock(&m_WindowLock);
      pthread_cond_signal(&m_WindowCond);
      pthread_mutex_unlock(&m_WindowLock);
      pthread_join(m_WorkerThread, NULL);
      pthread_cond_destroy(&m_WindowCond);
      pthread_mutex_destroy(&m_WindowLock);
   #else
      SetEvent(m_WindowCond);
      WaitForSingleObject(m_WorkerThread, INFINITE);
      CloseHandle(m_WorkerThread);
      CloseHandle(m_WindowLock);
      CloseHandle(m_WindowCond);
   #endif

   delete m_pSndUList;
}

void CSndQueue::init(const CChannel* c, const CTimer* t)
{
   m_pChannel = (CChannel*)c;
   m_pTimer = (CTimer*)t;
   m_pSndUList = new CSndUList;
   m_pSndUList->m_pWindowLock = &m_WindowLock;
   m_pSndUList->m_pWindowCond = &m_WindowCond;

   #ifndef WIN32
      pthread_create(&m_WorkerThread, NULL, CSndQueue::worker, this);
   #else
      DWORD threadID;
      m_WorkerThread = CreateThread(NULL, 0, CSndQueue::worker, this, 0, &threadID);
   #endif
}

#ifndef WIN32
   void* CSndQueue::worker(void* param)
#else
   DWORD WINAPI CSndQueue::worker(LPVOID param)
#endif
{
   CSndQueue* self = (CSndQueue*)param;

   CPacket pkt;

   while (!self->m_bClosing)
   {
      if (NULL != self->m_pSndUList->m_pUList)
      {
         // wait until next processing time of the first socket on the list
         uint64_t currtime;
         CTimer::rdtsc(currtime);
         if (currtime < self->m_pSndUList->m_pUList->m_llTimeStamp)
            self->m_pTimer->sleepto(self->m_pSndUList->m_pUList->m_llTimeStamp);

         // it is time to process it, pop it out/remove from the list
         int32_t id;
         CUDT* u;
         if (self->m_pSndUList->pop(id, u) < 0)
            continue;

         // pack a packet from the socket
         uint64_t ts;
         if (u->packData(pkt, ts) > 0)
            self->m_pChannel->sendto(u->m_pPeerAddr, pkt);

         // insert a new entry, ts is the next processing time
         if (ts > 0)
            self->m_pSndUList->insert(ts, id, u);
      }
      else
      {
         // wait here is there is no sockets with data to be sent
         #ifndef WIN32
            pthread_mutex_lock(&self->m_WindowLock);
            if (!self->m_bClosing && (NULL == self->m_pSndUList->m_pUList))
               pthread_cond_wait(&self->m_WindowCond, &self->m_WindowLock);
            pthread_mutex_unlock(&self->m_WindowLock);
         #else
            WaitForSingleObject(self->m_WindowCond, INFINITE);
         #endif
      }
   }

   return NULL;
}

int CSndQueue::sendto(const sockaddr* addr, CPacket& packet)
{
   // send out the packet immediately (high priority), this is a control packet
   m_pChannel->sendto(addr, packet);

   return packet.getLength();
}


//
CRcvUList::CRcvUList():
m_pUList(NULL),
m_pLast(NULL)
{
}

CRcvUList::~CRcvUList()
{
}

void CRcvUList::insert(const CUDT* u)
{
   CUDTList* n = u->m_pRNode;
   CTimer::rdtsc(n->m_llTimeStamp);

   if (NULL == m_pUList)
   {
      // empty list, insert as the single node
      n->m_pPrev = n->m_pNext = NULL;
      m_pLast = m_pUList = n;

      return;
   }

   // always insert at the end for RcvUList
   n->m_pPrev = m_pLast;
   n->m_pNext = NULL;
   m_pLast->m_pNext = n;
   m_pLast = n;
}

void CRcvUList::remove(const int32_t& id)
{
   if (NULL == m_pUList)
      return;

   if (id == m_pUList->m_iID)
   {
      // remove first node
      m_pUList = m_pUList->m_pNext;
      if (NULL == m_pUList)
         m_pLast = NULL;
      else
         m_pUList->m_pPrev = NULL;

      return;
   }

   // check further
   CUDTList* p = m_pUList;
   while (NULL != p->m_pNext)
   {
      if (id == p->m_pNext->m_iID)
      {
         p->m_pNext = p->m_pNext->m_pNext;
         if (NULL != p->m_pNext)
            p->m_pNext->m_pPrev = p;
         else
            m_pLast = p;

         return;
      }

      p = p->m_pNext;
   }
}

void CRcvUList::update(const int32_t& id)
{
   if (NULL == m_pUList)
      return;

   if (id == m_pUList->m_iID)
   {
      CTimer::rdtsc(m_pUList->m_llTimeStamp);

      // if there is only one node in the list, simply update it, otherwise move it to the end

      if (NULL != m_pUList->m_pNext)
      {
         CUDTList* n = m_pUList;

         m_pUList = m_pUList->m_pNext;
         m_pUList->m_pPrev = NULL;

         n->m_pNext = NULL;
         n->m_pPrev = m_pLast;
         m_pLast->m_pNext = n;
         m_pLast = n;
      }

      return;
   }

   // check further
   CUDTList* p = m_pUList;
   while (NULL != p->m_pNext)
   {
      if (id == p->m_pNext->m_iID)
      {
         CTimer::rdtsc(p->m_pNext->m_llTimeStamp);

         if (NULL != p->m_pNext->m_pNext)
         {
            CUDTList* n = p->m_pNext;

            p->m_pNext = p->m_pNext->m_pNext;
            p->m_pNext->m_pPrev = p;

            n->m_pNext = NULL;
            n->m_pPrev = m_pLast;
            m_pLast->m_pNext = n;
            m_pLast = n;
         }

         return;
      }

      p = p->m_pNext;
   }
}

//
CHash::CHash():
m_pBucket(NULL),
m_iHashSize(0)
{
}

CHash::~CHash()
{
   for (int i = 0; i < m_iHashSize; ++ i)
   {
      CBucket* b = m_pBucket[i];
      while (NULL != b)
      {
         CBucket* n = b->m_pNext;
         delete b;
         b = n;
      }
   }

   delete [] m_pBucket;
}

void CHash::init(const int& size)
{
   m_pBucket = new CBucket* [size];

   for (int i = 0; i < size; ++ i)
      m_pBucket[i] = NULL;

   m_iHashSize = size;
}

CUDT* CHash::lookup(const int32_t& id)
{
   // simple hash function (% hash table size); suitable for socket descriptors
   CBucket* b = m_pBucket[id % m_iHashSize];

   while (NULL != b)
   {
      if (id == b->m_iID)
         return b->m_pUDT;
      b = b->m_pNext;
   }

   return NULL;
}

void CHash::insert(const int32_t& id, const CUDT* u)
{
   CBucket* b = m_pBucket[id % m_iHashSize];

   CBucket* n = new CBucket;
   n->m_iID = id;
   n->m_pUDT = (CUDT*)u;
   n->m_pNext = b;

   m_pBucket[id % m_iHashSize] = n;
}

void CHash::remove(const int32_t& id)
{
   CBucket* b = m_pBucket[id % m_iHashSize];
   CBucket* p = NULL;

   while (NULL != b)
   {
      if (id == b->m_iID)
      {
         if (NULL == p)
            m_pBucket[id % m_iHashSize] = b->m_pNext;
         else
            p->m_pNext = b->m_pNext;

         delete b;

         return;
      }

      p = b;
      b = b->m_pNext;
   }
}


//
CRendezvousQueue::CRendezvousQueue()
{
   #ifndef WIN32
      pthread_mutex_init(&m_RIDVectorLock, NULL);
   #else
      m_RIDVectorLock = CreateMutex(NULL, false, NULL);
   #endif

   m_vRendezvousID.clear();
}

CRendezvousQueue::~CRendezvousQueue()
{
   #ifndef WIN32
      pthread_mutex_destroy(&m_RIDVectorLock);
   #else
      CloseHandle(m_RIDVectorLock);
   #endif

   for (vector<CRL>::iterator i = m_vRendezvousID.begin(); i != m_vRendezvousID.end(); ++ i)
   {
      if (AF_INET == i->m_iIPversion)
         delete (sockaddr_in*)i->m_pPeerAddr;
      else
         delete (sockaddr_in6*)i->m_pPeerAddr;
   }

   m_vRendezvousID.clear();
}

void CRendezvousQueue::insert(const UDTSOCKET& id, const int& ipv, const sockaddr* addr, CUDT* u)
{
   CGuard vg(m_RIDVectorLock);

   CRL r;
   r.m_iID = id;
   r.m_iPeerID = 0;
   r.m_iIPversion = ipv;
   r.m_pPeerAddr = (AF_INET == ipv) ? (sockaddr*)new sockaddr_in : (sockaddr*)new sockaddr_in6;
   memcpy(r.m_pPeerAddr, addr, (AF_INET == ipv) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
   r.m_pUDT = u;
   m_vRendezvousID.insert(m_vRendezvousID.end(), r);
}

void CRendezvousQueue::remove(const UDTSOCKET& id)
{
   CGuard vg(m_RIDVectorLock);

   for (vector<CRL>::iterator i = m_vRendezvousID.begin(); i != m_vRendezvousID.end(); ++ i)
      if (i->m_iID == id)
      {
         if (AF_INET == i->m_iIPversion)
            delete (sockaddr_in*)i->m_pPeerAddr;
         else
            delete (sockaddr_in6*)i->m_pPeerAddr;

         m_vRendezvousID.erase(i);

         return;
      }
}

bool CRendezvousQueue::retrieve(const sockaddr* addr, UDTSOCKET& id, const UDTSOCKET& peerid, CUDT*& u)
{
   CGuard vg(m_RIDVectorLock);

   for (vector<CRL>::iterator i = m_vRendezvousID.begin(); i != m_vRendezvousID.end(); ++ i)
      if (CIPAddress::ipcmp(addr, i->m_pPeerAddr, i->m_iIPversion) && ((0 == i->m_iPeerID) || (peerid == i->m_iPeerID)))
      {
         id = i->m_iID;
         i->m_iPeerID = peerid;
         u = i->m_pUDT;
         return true;
      }

   return false;
}


//
CRcvQueue::CRcvQueue():
m_pRcvUList(NULL),
m_pHash(NULL),
m_pChannel(NULL),
m_pTimer(NULL),
m_bClosing(false),
m_pListener(NULL),
m_pRendezvousQueue(NULL)
{
   #ifndef WIN32
      pthread_mutex_init(&m_PassLock, NULL);
      pthread_cond_init(&m_PassCond, NULL);
      pthread_mutex_init(&m_LSLock, NULL);
      pthread_mutex_init(&m_IDLock, NULL);
   #else
      m_PassLock = CreateMutex(NULL, false, NULL);
      m_PassCond = CreateEvent(NULL, false, false, NULL);
      m_LSLock = CreateMutex(NULL, false, NULL);
      m_IDLock = CreateMutex(NULL, false, NULL);
   #endif

   m_vNewEntry.clear();
   m_mBuffer.clear();
}

CRcvQueue::~CRcvQueue()
{
   m_bClosing = true;

   #ifndef WIN32
      pthread_join(m_WorkerThread, NULL);
      pthread_mutex_destroy(&m_PassLock);
      pthread_cond_destroy(&m_PassCond);
      pthread_mutex_destroy(&m_LSLock);
      pthread_mutex_destroy(&m_IDLock);
   #else
      WaitForSingleObject(m_WorkerThread, INFINITE);
      CloseHandle(m_WorkerThread);
      CloseHandle(m_PassLock);
      CloseHandle(m_PassCond);
      CloseHandle(m_LSLock);
      CloseHandle(m_IDLock);
   #endif

   delete m_pRcvUList;
   delete m_pHash;
   delete m_pRendezvousQueue;

   for (map<int32_t, CPacket*>::iterator i = m_mBuffer.begin(); i != m_mBuffer.end(); ++ i)
   {
      delete [] i->second->m_pcData;
      delete i->second;
   }
}

void CRcvQueue::init(const int& qsize, const int& payload, const int& version, const int& hsize, const CChannel* cc, const CTimer* t)
{
   m_iPayloadSize = payload;

   m_UnitQueue.init(qsize, payload, version);

   m_pHash = new CHash;
   m_pHash->init(hsize);

   m_pChannel = (CChannel*)cc;
   m_pTimer = (CTimer*)t;

   m_pRcvUList = new CRcvUList;
   m_pRendezvousQueue = new CRendezvousQueue;

   #ifndef WIN32
      pthread_create(&m_WorkerThread, NULL, CRcvQueue::worker, this);
   #else
      DWORD threadID;
      m_WorkerThread = CreateThread(NULL, 0, CRcvQueue::worker, this, 0, &threadID);
   #endif
}

#ifndef WIN32
   void* CRcvQueue::worker(void* param)
#else
   DWORD WINAPI CRcvQueue::worker(LPVOID param)
#endif
{
   CRcvQueue* self = (CRcvQueue*)param;

   CUnit temp;
   temp.m_Packet.m_pcData = new char[self->m_iPayloadSize];
   sockaddr* addr = (AF_INET == self->m_UnitQueue.m_iIPversion) ? (sockaddr*) new sockaddr_in : (sockaddr*) new sockaddr_in6;

   while (!self->m_bClosing)
   {
      #ifdef NO_BUSY_WAITING
         self->m_pTimer->tick();
      #endif

      // check waiting list, if new socket, insert it to the list
      if (self->ifNewEntry())
      {
         CUDT* ne = self->getNewEntry();
         if (NULL != ne)
         {
            self->m_pHash->insert(ne->m_SocketID, ne);
            self->m_pRcvUList->insert(ne);
         }
      }

      // find next available slot for incoming packet
      CUnit* unit = self->m_UnitQueue.getNextAvailUnit();
      if (NULL == unit)
         unit = &temp;

      unit->m_Packet.setLength(self->m_iPayloadSize);

      CUDT* u = NULL;
      int32_t id;

      // reading next incoming packet
      if (self->m_pChannel->recvfrom(addr, unit->m_Packet) <= 0)
         goto TIMER_CHECK;
      if (unit == &temp)
         goto TIMER_CHECK;

      id = unit->m_Packet.m_iID;

      // ID 0 is for connection request, which should be passed to the listening socket or rendezvous sockets
      if (0 == id)
      {
         if (NULL != self->m_pListener)
            ((CUDT*)self->m_pListener)->listen(addr, unit->m_Packet);
         else if (self->m_pRendezvousQueue->retrieve(addr, id, ((CHandShake*)unit->m_Packet.m_pcData)->m_iID, u))
         {
            if (u->m_bConnected && !u->m_bBroken)
               u->processCtrl(unit->m_Packet);
            else
               self->storePkt(id, unit->m_Packet.clone());
         }
      }
      else 
      {
         if (NULL != (u = self->m_pHash->lookup(id)))
         {
            if (u->m_bConnected && !u->m_bBroken)
            {
               if (0 == unit->m_Packet.getFlag())
                  u->processData(unit);
               else
                  u->processCtrl(unit->m_Packet);

               u->checkTimers();
               self->m_pRcvUList->update(id);
            }
         }
         else
            self->storePkt(id, unit->m_Packet.clone());
      }

TIMER_CHECK:
      // take care of the timing event for all UDT sockets

      CUDTList* ul = self->m_pRcvUList->m_pUList;
      uint64_t currtime;
      CTimer::rdtsc(currtime);

      while ((NULL != ul) && (ul->m_llTimeStamp < currtime - 10000 * CTimer::getCPUFrequency()))
      {
         CUDT* u = ul->m_pUDT;
         int32_t id = ul->m_iID;

         if (u->m_bConnected && !u->m_bBroken)
         {
            u->checkTimers();
            self->m_pRcvUList->update(id);
         }
         else
         {
            self->m_pRcvUList->remove(id);
            self->m_pHash->remove(id);
         }

         ul = self->m_pRcvUList->m_pUList;
      }
   }

   delete [] temp.m_Packet.m_pcData;
   if (AF_INET == self->m_UnitQueue.m_iIPversion)
      delete (sockaddr_in*)addr;
   else
      delete (sockaddr_in6*)addr;

   return NULL;
}

int CRcvQueue::recvfrom(const int32_t& id, CPacket& packet)
{
   CGuard bufferlock(m_PassLock);

   map<int32_t, CPacket*>::iterator i = m_mBuffer.find(id);

   if (i == m_mBuffer.end())
   {
      #ifndef WIN32
         uint64_t now = CTimer::getTime();
         timespec timeout;

         timeout.tv_sec = now / 1000000 + 1;
         timeout.tv_nsec = (now % 1000000) * 1000;

         pthread_cond_timedwait(&m_PassCond, &m_PassLock, &timeout);
      #else
         ReleaseMutex(m_PassLock);
         WaitForSingleObject(m_PassCond, 1);
         WaitForSingleObject(m_PassLock, INFINITE);
      #endif

      i = m_mBuffer.find(id);
      if (i == m_mBuffer.end())
      {
         packet.setLength(-1);
         return -1;
      }
   }

   if (packet.getLength() < i->second->getLength())
   {
      packet.setLength(-1);
      return -1;
   }

   memcpy(packet.m_nHeader, i->second->m_nHeader, CPacket::m_iPktHdrSize);
   memcpy(packet.m_pcData, i->second->m_pcData, i->second->getLength());
   packet.setLength(i->second->getLength());

   delete [] i->second->m_pcData;
   delete i->second;
   m_mBuffer.erase(i);

   return packet.getLength();
}

int CRcvQueue::setListener(const CUDT* u)
{
   CGuard lslock(m_LSLock);

   if (NULL != m_pListener)
      return -1;

   m_pListener = (CUDT*)u;
   return 1;
}

void CRcvQueue::removeListener(const CUDT* u)
{
   CGuard lslock(m_LSLock);

   if (u == m_pListener)
      m_pListener = NULL;
}

void CRcvQueue::setNewEntry(CUDT* u)
{
   CGuard listguard(m_IDLock);
   m_vNewEntry.insert(m_vNewEntry.end(), u);
}

bool CRcvQueue::ifNewEntry()
{
   return !(m_vNewEntry.empty());
}

CUDT* CRcvQueue::getNewEntry()
{
   CGuard listguard(m_IDLock);

   if (m_vNewEntry.empty())
      return NULL;

   CUDT* u = (CUDT*)*(m_vNewEntry.begin());
   m_vNewEntry.erase(m_vNewEntry.begin());

   return u;
}

void CRcvQueue::storePkt(const int32_t& id, CPacket* pkt)
{
   #ifndef WIN32
      pthread_mutex_lock(&m_PassLock);
   #else
      WaitForSingleObject(m_PassLock, INFINITE);
   #endif

   map<int32_t, CPacket*>::iterator i = m_mBuffer.find(id);

   if (i == m_mBuffer.end())
      m_mBuffer[id] = pkt;
   else
   {
      delete [] i->second->m_pcData;
      delete i->second;
      i->second = pkt;
   }

   #ifndef WIN32
      pthread_mutex_unlock(&m_PassLock);
      pthread_cond_signal(&m_PassCond);
   #else
      ReleaseMutex(m_PassLock);
      SetEvent(m_PassCond);
   #endif
}
