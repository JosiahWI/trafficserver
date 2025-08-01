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
  P_HostDBProcessor.h
 ****************************************************************************/

#pragma once

#include <tsutil/TsSharedMutex.h>

#include "iocore/hostdb/HostDBProcessor.h"
#include "P_RefCountCache.h"
#include "tscore/PendingAction.h"
#include "tsutil/Metrics.h"

#include <utility>

using ts::Metrics;

//
// Data
//

extern int hostdb_enable;
extern int hostdb_migrate_on_demand;
extern int hostdb_lookup_timeout;
extern int hostdb_re_dns_on_reload;

// 0 = obey, 1 = ignore, 2 = min(X,ttl), 3 = max(X,ttl)
enum {
  TTL_OBEY,
  TTL_IGNORE,
  TTL_MIN,
  TTL_MAX,
};

extern int hostdb_ttl_mode;
extern int hostdb_srv_enabled;
extern int hostdb_disable_reverse_lookup;

// Static configuration information
extern HostDBCache hostDB;

/** Host DB record mark.

    The records in the host DB are de facto segregated by roughly the
    DNS query type. We use an intermediate type to provide a little flexibility
    although the type is presumed to be a single byte.
 */
enum HostDBMark {
  HOSTDB_MARK_GENERIC, ///< Anything that's not one of the other types.
  HOSTDB_MARK_IPV4,    ///< IPv4 / T_A
  HOSTDB_MARK_IPV6,    ///< IPv6 / T_AAAA
  HOSTDB_MARK_SRV,     ///< Service / T_SRV
};

//
// Constants
//

#define HOST_DB_HITS_BITS 3
#define HOST_DB_TAG_BITS  56

#define CONFIGURATION_HISTORY_PROBE_DEPTH 1

// Bump this any time hostdb format is changed
#define HOST_DB_CACHE_MAJOR_VERSION 3
#define HOST_DB_CACHE_MINOR_VERSION 0
// 2.2: IP family split 2.1 : IPv6

#define DEFAULT_HOST_DB_SIZE (1 << 14)
// Timeout DNS every 24 hours by default if ttl_mode is enabled
#define HOST_DB_IP_TIMEOUT (24 * 60 * 60)
// DNS entries should be revalidated every 12 hours
#define HOST_DB_IP_STALE (12 * 60 * 60)
// DNS entries which failed lookup, should be revalidated every hour
#define HOST_DB_IP_FAIL_TIMEOUT (60 * 60)

// #define HOST_DB_MAX_INTERVAL                 (0x7FFFFFFF)
const unsigned int HOST_DB_MAX_TTL = (0x1FFFFF); // 24 days

//
// Constants
//

// period to wait for a remote probe...
#define HOST_DB_RETRY_PERIOD   HRTIME_MSECONDS(20)
#define HOST_DB_ITERATE_PERIOD HRTIME_MSECONDS(5)

// #define TEST(_x) _x
#define TEST(_x)

struct HostEnt;

// Stats
struct HostDBStatsBlock {
  Metrics::Counter::AtomicType *total_lookups;
  Metrics::Counter::AtomicType *total_hits;
  Metrics::Counter::AtomicType *total_serve_stale;
  Metrics::Counter::AtomicType *ttl;
  Metrics::Counter::AtomicType *ttl_expires;
  Metrics::Counter::AtomicType *re_dns_on_reload;
  Metrics::Counter::AtomicType *insert_duplicate_to_pending_dns;
};

extern HostDBStatsBlock hostdb_rsb;

struct HostFile;

//
// HostDBCache (Private)
//
struct HostDBCache {
  int start(int flags = 0);
  // Map to contain all of the host file overrides, initialize it to empty
  std::shared_ptr<HostFile> host_file;
  ts::shared_mutex          host_file_mutex;

  // TODO: make ATS call a close() method or something on shutdown (it does nothing of the sort today)
  RefCountCache<HostDBRecord> *refcountcache = nullptr;

  // TODO configurable number of items in the cache
  Queue<HostDBContinuation, Continuation::Link_link> *pending_dns = nullptr;
  Queue<HostDBContinuation, Continuation::Link_link> &pending_dns_for_hash(const CryptoHash &hash);
  Queue<HostDBContinuation, Continuation::Link_link> *remoteHostDBQueue = nullptr;
  HostDBCache();
  bool is_pending_dns_for_hash(const CryptoHash &hash);

  std::shared_ptr<HostFile> acquire_host_file();
  bool                      remove_from_pending_dns_for_hash(const CryptoHash &hash, HostDBContinuation *c);
};

//
// Types
//

struct DNSServer;
struct SplitDNS;

/** Container for a hash and its dependent data.
    This handles both the host name and raw address cases.
*/
struct HostDBHash {
  using self = HostDBHash; ///< Self reference type.

  CryptoHash hash; ///< The hash value.

  swoc::TextView host_name; ///< Name of the host for the query.
  IpAddr         ip;        ///< IP address.
  in_port_t      port = 0;  ///< IP port (host order).
  /// DNS server. Not strictly part of the hash data but
  /// it's both used by @c HostDBContinuation and provides access to
  /// hash data. It's just handier to store it here for both uses.
  DNSServer *dns_server = nullptr;
  SplitDNS  *pSD        = nullptr;             ///< Hold the container for @a dns_server.
  HostDBMark db_mark    = HOSTDB_MARK_GENERIC; ///< Mark / type of record.

  /// Default constructor.
  HostDBHash() = default;
  /// Destructor.
  ~HostDBHash();
  /// Recompute and update the hash.
  void refresh();
  /** Assign a hostname.
      This updates the split DNS data as well.
  */
  self &set_host(swoc::TextView name);
  self &
  set_host(char const *name)
  {
    return this->set_host(swoc::TextView{name, strlen(name)});
  }

  bool
  is_byname() const
  {
    return db_mark == HOSTDB_MARK_IPV4 || db_mark == HOSTDB_MARK_IPV6;
  }

  bool
  is_srv() const
  {
    return db_mark == HOSTDB_MARK_SRV;
  }

  bool
  is_reverse() const
  {
    return !is_byname() && !is_srv();
  }
};

//
// Handles a HostDB lookup request
//
using HostDBContHandler = int (HostDBContinuation::*)(int, void *);

struct HostDBContinuation : public Continuation {
  Action     action;
  HostDBHash hash;
  ts_seconds ttl{0};
  //  HostDBMark db_mark; ///< Target type.
  /// Original IP address family style. Note this will disagree with
  /// @a hash.db_mark when doing a retry on an alternate family. The retry
  /// logic depends on it to avoid looping.
  HostResStyle host_res_style     = DEFAULT_OPTIONS.host_res_style; ///< Address family priority.
  int          dns_lookup_timeout = DEFAULT_OPTIONS.timeout;
  Event       *timeout            = nullptr;

  char hash_host_name_store[MAXDNAME + 1]; // used as backing store for @a hash

  PendingAction pending_action;

  unsigned int force_dns : 1;

  int probeEvent(int event, Event *e);
  int dnsEvent(int event, HostEnt *e);
  int dnsPendingEvent(int event, Event *e);
  int backgroundEvent(int event, Event *e);

  /// Recompute the hash and update ancillary values.
  void refresh_hash();
  void do_dns();

  Ptr<HostDBRecord> lookup_done(swoc::TextView query_name, ts_seconds answer_ttl, SRVHosts *s = nullptr,
                                Ptr<HostDBRecord> record = Ptr<HostDBRecord>{});

  void remove_and_trigger_pending_dns();
  int  set_check_pending_dns();

  /** Optional values for @c init.
   */
  struct Options {
    int           timeout        = 0;             ///< Timeout value. Default 0
    HostResStyle  host_res_style = HOST_RES_NONE; ///< IP address family fallback. Default @c HOST_RES_NONE
    bool          force_dns      = false;         ///< Force DNS lookup. Default @c false
    Continuation *cont           = nullptr;       ///< Continuation / action. Default @c nullptr (none)

    Options() {}
  };
  static const Options DEFAULT_OPTIONS; ///< Default defaults.
  void                 init(HostDBHash const &hash, Options const &opt = DEFAULT_OPTIONS);

  HostDBContinuation() : force_dns(DEFAULT_OPTIONS.force_dns)
  {
    ink_zero(hash_host_name_store);
    ink_zero(hash.hash);
    SET_HANDLER(&HostDBContinuation::probeEvent);
  }
};

inline Queue<HostDBContinuation> &
HostDBCache::pending_dns_for_hash(const CryptoHash &hash)
{
  return pending_dns[this->refcountcache->partition_for_key(hash.fold())];
}
