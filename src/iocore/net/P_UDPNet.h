/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

/****************************************************************************
  P_UDPNet.h
  Private header for UDPNetProcessor


 ****************************************************************************/

#pragma once

#include "P_UnixUDPConnection.h"
#include "iocore/net/UDPNet.h"
#include "iocore/net/PollCont.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

// added by YTS Team, yamsat
static inline PollCont *get_UDPPollCont(EThread *);

class UDPNetHandler;

class UDPNetProcessorInternal : public UDPNetProcessor
{
public:
  EventType register_event_type() override;
  int       start(int n_udp_threads, size_t stacksize) override;
  void      udp_read_from_net(UDPNetHandler *nh, UDPConnection *uc);
  int       udp_callback(UDPNetHandler *nh, UDPConnection *uc, EThread *thread);

  off_t pollCont_offset;
  off_t udpNetHandler_offset;

private:
  void read_single_message_from_net(UDPNetHandler *nh, UDPConnection *uc);
  void read_multiple_messages_from_net(UDPNetHandler *nh, UDPConnection *xuc);
};

extern UDPNetProcessorInternal udpNetInternal;

// 20 ms slots; 2048 slots  => 40 sec. into the future
#define SLOT_TIME_MSEC 20
#define SLOT_TIME      HRTIME_MSECONDS(SLOT_TIME_MSEC)
#define N_SLOTS        2048

constexpr int UDP_PERIOD    = 9;
constexpr int UDP_NH_PERIOD = UDP_PERIOD + 1;

class PacketQueue
{
public:
  PacketQueue() { init(); }

  virtual ~PacketQueue() {}
  int              nPackets          = 0;
  ink_hrtime       lastPullLongTermQ = 0;
  Queue<UDPPacket> longTermQ;
  Queue<UDPPacket> bucket[N_SLOTS];
  ink_hrtime       delivery_time[N_SLOTS];
  int              now_slot = 0;

  void
  init()
  {
    now_slot       = 0;
    ink_hrtime now = ink_get_hrtime();
    int        i   = now_slot;
    int        j   = 0;
    while (j < N_SLOTS) {
      delivery_time[i] = now + j * SLOT_TIME;
      i                = (i + 1) % N_SLOTS;
      j++;
    }
  }

  void
  addPacket(UDPPacket *e, ink_hrtime now = 0)
  {
    int before = 0;
    int slot;

    if (IsCancelledPacket(e)) {
      e->free();
      return;
    }

    nPackets++;

    ink_assert(delivery_time[now_slot]);

    if (e->p.delivery_time < now) {
      e->p.delivery_time = now;
    }

    ink_hrtime s = e->p.delivery_time - delivery_time[now_slot];

    if (s < 0) {
      before = 1;
      s      = 0;
    }
    s = s / SLOT_TIME;
    // if s >= N_SLOTS, either we are *REALLY* behind or someone is trying
    // queue packets *WAY* too far into the future.
    // need a thingy to hold packets in a "long-term" slot; then, pull packets
    // from long-term slot whenever you advance.
    if (s >= N_SLOTS - 1) {
      longTermQ.enqueue(e);
      e->p.in_heap               = 0;
      e->p.in_the_priority_queue = 1;
      return;
    }
    slot = (s + now_slot) % N_SLOTS;

    // so that slot+1 is still "in future".
    ink_assert((before || delivery_time[slot] <= e->p.delivery_time) &&
               (delivery_time[(slot + 1) % N_SLOTS] >= e->p.delivery_time));
    e->p.in_the_priority_queue = 1;
    e->p.in_heap               = slot;
    bucket[slot].enqueue(e);
  }

  UDPPacket *
  firstPacket(ink_hrtime t)
  {
    if (t > delivery_time[now_slot]) {
      return bucket[now_slot].head;
    } else {
      return nullptr;
    }
  }

  UDPPacket *
  getFirstPacket()
  {
    nPackets--;
    return dequeue_ready(0);
  }

  int
  size()
  {
    ink_assert(nPackets >= 0);
    return nPackets;
  }

  bool
  IsCancelledPacket(UDPPacket *p)
  {
    // discard packets that'll never get sent...
    return ((p->p.conn->shouldDestroy()) || (p->p.conn->GetSendGenerationNumber() != p->p.reqGenerationNum));
  }

  void
  FreeCancelledPackets(int numSlots)
  {
    Queue<UDPPacket> tempQ;
    int              i;

    for (i = 0; i < numSlots; i++) {
      int        s = (now_slot + i) % N_SLOTS;
      UDPPacket *p;
      while (nullptr != (p = bucket[s].dequeue())) {
        if (IsCancelledPacket(p)) {
          p->free();
          continue;
        }
        tempQ.enqueue(p);
      }
      // remove and flip it over
      while (nullptr != (p = tempQ.dequeue())) {
        bucket[s].enqueue(p);
      }
    }
  }

  void
  advanceNow(ink_hrtime t)
  {
    int s = now_slot;

    if (ink_hrtime_to_msec(t - lastPullLongTermQ) >= SLOT_TIME_MSEC * ((N_SLOTS - 1) / 2)) {
      Queue<UDPPacket> tempQ;
      UDPPacket       *p;
      // pull in all the stuff from long-term slot
      lastPullLongTermQ = t;
      // this is to handle weirdness where someone is trying to queue a
      // packet to be sent in SLOT_TIME_MSEC * N_SLOTS * (2+)---the packet
      // will get back to longTermQ and we'll have an infinite loop.
      while ((p = longTermQ.dequeue()) != nullptr) {
        tempQ.enqueue(p);
      }
      while ((p = tempQ.dequeue()) != nullptr) {
        addPacket(p);
      }
    }

    while (!bucket[s].head && (t > delivery_time[s] + SLOT_TIME)) {
      int prev;

      prev             = (s + N_SLOTS - 1) % N_SLOTS;
      delivery_time[s] = delivery_time[prev] + SLOT_TIME;
      s                = (s + 1) % N_SLOTS;
      prev             = (s + N_SLOTS - 1) % N_SLOTS;
      ink_assert(delivery_time[prev] > delivery_time[s]);

      if (s == now_slot) {
        init();
        s = 0;
        break;
      }
    }

    if (s != now_slot) {
      static DbgCtl dbg_ctl{"v_udpnet-service"};
      Dbg(dbg_ctl, "Advancing by (%d slots): behind by %" PRId64 " ms", s - now_slot,
          ink_hrtime_to_msec(t - delivery_time[now_slot]));
    }

    now_slot = s;
  }

private:
  void
  remove(UDPPacket *e)
  {
    nPackets--;
    ink_assert(e->p.in_the_priority_queue);
    e->p.in_the_priority_queue = 0;
    bucket[e->p.in_heap].remove(e);
  }

public:
  UDPPacket *
  dequeue_ready(ink_hrtime t)
  {
    (void)t;
    UDPPacket *e = bucket[now_slot].dequeue();
    if (e) {
      ink_assert(e->p.in_the_priority_queue);
      e->p.in_the_priority_queue = 0;
    }
    advanceNow(t);
    return e;
  }

  void
  check_ready(ink_hrtime now)
  {
    (void)now;
  }

  ink_hrtime
  earliest_timeout()
  {
    int s = now_slot;
    for (int i = 0; i < N_SLOTS; i++) {
      if (bucket[s].head) {
        return delivery_time[s];
      }
      s = (s + 1) % N_SLOTS;
    }
    return HRTIME_FOREVER;
  }
};

class UDPQueue
{
  PacketQueue pipeInfo{};
  ink_hrtime  last_report  = 0;
  ink_hrtime  last_service = 0;
  int         packets      = 0;
  int         added        = 0;
#ifdef SOL_UDP
  bool use_udp_gso = false;
#endif

public:
  // Outgoing UDP Packet Queue
  ASLL(UDPPacket, alink) outQueue;

  void service(UDPNetHandler *);

  void SendPackets();
  void SendUDPPacket(UDPPacket *p);
  int  SendMultipleUDPPackets(UDPPacket **p, uint16_t n);

  // Interface exported to the outside world
  void send(UDPPacket *p);

  UDPQueue(bool enable_gso);
  ~UDPQueue();
};

void initialize_thread_for_udp_net(EThread *thread);

class UDPNetHandler : public Continuation, public EThread::LoopTailHandler
{
public:
  struct Cfg {
    // Segmentation offload.
    bool enable_gso{true};
    bool enable_gro{true};
  };
  // engine for outgoing packets
  UDPQueue udpOutQueue;

  // New UDPConnections
  // to hold the newly created descriptors before scheduling them on the servicing buckets.
  // atomically added to by a thread creating a new connection with UDPBind
  ASLL(UnixUDPConnection, newconn_alink) newconn_list;
  // All opened UDPConnections
  Que(UnixUDPConnection, link) open_list;
  // to be called back with data
  Que(UnixUDPConnection, callback_link) udp_callbacks;

  Event     *trigger_event = nullptr;
  EThread   *thread        = nullptr;
  ink_hrtime nextCheck;
  ink_hrtime lastCheck;

  int startNetEvent(int event, Event *data);
  int mainNetEvent(int event, Event *data);

  int  waitForActivity(ink_hrtime timeout) override;
  void signalActivity() override;

  UDPNetHandler(Cfg &&cfg);

  // GRO
  bool is_gro_enabled() const;

private:
  Cfg _cfg; // Note: may not be the best place to put this, but for now is ok.
};

static inline PollCont *
get_UDPPollCont(EThread *t)
{
  return static_cast<PollCont *>(ETHREAD_GET_PTR(t, udpNetInternal.pollCont_offset));
}

static inline UDPNetHandler *
get_UDPNetHandler(EThread *t)
{
  return static_cast<UDPNetHandler *>(ETHREAD_GET_PTR(t, udpNetInternal.udpNetHandler_offset));
}
