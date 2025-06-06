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

#include "P_DNSProcessor.h"
#include "iocore/dns/SplitDNSProcessor.h"
#include "iocore/eventsystem/Event.h"
#include "iocore/eventsystem/EventProcessor.h"
#include "iocore/eventsystem/UnixSocket.h"
#include "iocore/hostdb/HostDB.h"
#include "iocore/hostdb/HostDBProcessor.h"
#include "records/RecCore.h"
#include "tscore/ink_inet.h"
// TODO: make these go away
#include "../net/P_UnixNetProcessor.h"
#include "../net/P_UnixNet.h"

#if TS_HAS_TESTS
#include "tscore/Regression.h"
#endif

#define SRV_COST    (RRFIXEDSZ + 0)
#define SRV_WEIGHT  (RRFIXEDSZ + 2)
#define SRV_PORT    (RRFIXEDSZ + 4)
#define SRV_SERVER  (RRFIXEDSZ + 6)
#define SRV_FIXEDSZ (RRFIXEDSZ + 6)

EventType ET_DNS = ET_CALL;

//
// Config
//
int           dns_timeout                     = DEFAULT_DNS_TIMEOUT;
int           dns_retries                     = DEFAULT_DNS_RETRIES;
int           dns_search                      = DEFAULT_DNS_SEARCH;
int           dns_failover_number             = DEFAULT_FAILOVER_NUMBER;
int           dns_failover_period             = DEFAULT_FAILOVER_PERIOD;
int           dns_failover_try_period         = DEFAULT_FAILOVER_TRY_PERIOD;
int           dns_max_dns_in_flight           = MAX_DNS_IN_FLIGHT;
int           dns_max_tcp_continuous_failures = MAX_DNS_TCP_CONTINUOUS_FAILURES;
int           dns_validate_qname              = 0;
unsigned int  dns_handler_initialized         = 0;
int           dns_ns_rr                       = 0;
int           dns_ns_rr_init_down             = 1;
char         *dns_ns_list                     = nullptr;
char         *dns_resolv_conf                 = nullptr;
char         *dns_local_ipv6                  = nullptr;
char         *dns_local_ipv4                  = nullptr;
int           dns_thread                      = 0;
int           dns_prefer_ipv6                 = 0;
DNS_CONN_MODE dns_conn_mode                   = DNS_CONN_MODE::UDP_ONLY;

namespace
{
DbgCtl dbg_ctl_dns{"dns"};
DbgCtl dbg_ctl_dns_pas{"dns_pas"};
DbgCtl dbg_ctl_dns_srv{"dns_srv"};

const int tcp_data_length_offset = 2;

// Currently only used for A and AAAA.
inline const char *
QtypeName(int qtype)
{
  return T_AAAA == qtype ? "AAAA" : T_A == qtype ? "A" : "*";
}
inline bool
is_addr_query(int qtype)
{
  return qtype == T_A || qtype == T_AAAA;
}
} // namespace

DNSProcessor             dnsProcessor;
ClassAllocator<DNSEntry> dnsEntryAllocator("dnsEntryAllocator");
// Users are expected to free these entries in short order!
// We could page align this buffer to enable page flipping for recv...
ClassAllocator<HostEnt> dnsBufAllocator("dnsBufAllocator", 2);

//
// Function Prototypes
//
static bool      dns_process(DNSHandler *h, HostEnt *ent, int len);
static DNSEntry *get_dns(DNSHandler *h, uint16_t id);
// returns true when e is done
static void dns_result(DNSHandler *h, DNSEntry *e, HostEnt *ent, bool retry, bool tcp_retry = false);
static void write_dns(DNSHandler *h, bool tcp_retry = false);
static bool write_dns_event(DNSHandler *h, DNSEntry *e, bool over_tcp = false);
// "reliable" name to try. need to build up first.
static int try_servers         = 0;
static int local_num_entries   = 1;
static int attempt_num_entries = 1;
char       try_server_names[DEFAULT_NUM_TRY_SERVER][MAXDNAME];

static inline char *
strnchr(char *s, char c, int len)
{
  while (*s && *s != c && len) {
    ++s, --len;
  }
  return *s == c ? s : nullptr;
}

static inline uint16_t
ink_get16(const uint8_t *src)
{
  uint16_t dst;

  NS_GET16(dst, src);
  return dst;
}

static inline unsigned int
get_rcode(char *buff)
{
  // 'buff' is always a HostEnt::buf which is a char array and therefore cannot
  // be a nullptr. This assertion satisfies a mistaken clang-analyzer warning
  // saying this can be a nullptr dereference.
  ink_assert(buff != nullptr);
  return reinterpret_cast<HEADER *>(buff)->rcode;
}

static inline unsigned int
get_rcode(HostEnt *ent)
{
  return get_rcode(reinterpret_cast<char *>(ent->buf));
}

bool
HostEnt::isNameError()
{
  return get_rcode(this) == NXDOMAIN;
}

void
HostEnt::free()
{
  dnsBufAllocator.free(this);
}

size_t
make_ipv4_ptr(in_addr_t addr, char *buffer)
{
  char          *p = buffer;
  uint8_t const *u = reinterpret_cast<uint8_t *>(&addr);

  if (u[3] > 99) {
    *p++ = (u[3] / 100) + '0';
  }
  if (u[3] > 9) {
    *p++ = ((u[3] / 10) % 10) + '0';
  }
  *p++ = u[3] % 10 + '0';
  *p++ = '.';
  if (u[2] > 99) {
    *p++ = (u[2] / 100) + '0';
  }
  if (u[2] > 9) {
    *p++ = ((u[2] / 10) % 10) + '0';
  }
  *p++ = u[2] % 10 + '0';
  *p++ = '.';
  if (u[1] > 99) {
    *p++ = (u[1] / 100) + '0';
  }
  if (u[1] > 9) {
    *p++ = ((u[1] / 10) % 10) + '0';
  }
  *p++ = u[1] % 10 + '0';
  *p++ = '.';
  if (u[0] > 99) {
    *p++ = (u[0] / 100) + '0';
  }
  if (u[0] > 9) {
    *p++ = ((u[0] / 10) % 10) + '0';
  }
  *p++ = u[0] % 10 + '0';
  *p++ = '.';
  return ink_strlcpy(p, "in-addr.arpa", MAXDNAME - (p - buffer + 1));
}

size_t
make_ipv6_ptr(in6_addr const *addr, char *buffer)
{
  const char     hex_digit[] = "0123456789abcdef";
  char          *p           = buffer;
  uint8_t const *src         = addr->s6_addr;
  int            i;

  for (i = TS_IP6_SIZE - 1; i >= 0; --i) {
    *p++ = hex_digit[src[i] & 0x0f];
    *p++ = '.';
    *p++ = hex_digit[src[i] >> 4];
    *p++ = '.';
  }

  return ink_strlcpy(p, "ip6.arpa", MAXDNAME - (p - buffer + 1));
}

//  Public functions
//
//  See documentation is header files and Memos
//
int
DNSProcessor::start(int, size_t stacksize)
{
  //
  // Read configuration
  //
  RecEstablishStaticConfigInt32(dns_retries, "proxy.config.dns.retries");
  RecEstablishStaticConfigInt32(dns_timeout, "proxy.config.dns.lookup_timeout");
  RecEstablishStaticConfigInt32(dns_search, "proxy.config.dns.search_default_domains");
  RecEstablishStaticConfigInt32(dns_failover_number, "proxy.config.dns.failover_number");
  RecEstablishStaticConfigInt32(dns_failover_period, "proxy.config.dns.failover_period");
  RecEstablishStaticConfigInt32(dns_max_dns_in_flight, "proxy.config.dns.max_dns_in_flight");
  RecEstablishStaticConfigInt32(dns_validate_qname, "proxy.config.dns.validate_query_name");
  RecEstablishStaticConfigInt32(dns_ns_rr, "proxy.config.dns.round_robin_nameservers");
  RecEstablishStaticConfigInt32(dns_max_tcp_continuous_failures, "proxy.config.dns.max_tcp_continuous_failures");
  if (auto rec_str{RecGetRecordStringAlloc("proxy.config.dns.nameservers")}; rec_str) {
    dns_ns_list = ats_stringdup(rec_str);
  }
  if (auto rec_str{RecGetRecordStringAlloc("proxy.config.dns.local_ipv4")}; rec_str) {
    dns_local_ipv4 = ats_stringdup(rec_str);
  }
  if (auto rec_str{RecGetRecordStringAlloc("proxy.config.dns.local_ipv6")}; rec_str) {
    dns_local_ipv6 = ats_stringdup(rec_str);
  }
  if (auto rec_str{RecGetRecordStringAlloc("proxy.config.dns.resolv_conf")}; rec_str) {
    dns_resolv_conf = ats_stringdup(rec_str);
  }
  RecEstablishStaticConfigInt32(dns_thread, "proxy.config.dns.dedicated_thread");
  int dns_conn_mode_i = 0;
  RecEstablishStaticConfigInt32(dns_conn_mode_i, "proxy.config.dns.connection_mode");
  dns_conn_mode = static_cast<DNS_CONN_MODE>(dns_conn_mode_i);

  if (dns_thread > 0) {
    // TODO: Hmmm, should we just get a single thread some other way?
    ET_DNS = eventProcessor.register_event_type("ET_DNS");
    eventProcessor.schedule_spawn(&initialize_thread_for_net, ET_DNS);
    eventProcessor.spawn_event_threads(ET_DNS, 1, stacksize);
  } else {
    // Initialize the first event thread for DNS.
    ET_DNS = ET_CALL;
  }
  thread = eventProcessor.thread_group[ET_DNS]._thread[0];

  dns_failover_try_period = dns_timeout + 1; // Modify the "default" accordingly

  if (SplitDNSConfig::gsplit_dns_enabled) {
    SplitDNSConfig::dnsHandler_mutex = thread->mutex;
    // reconfigure after threads start
    SplitDNSConfig::reconfigure();
  }

  // Setup the default DNSHandler, it's used both by normal DNS, and SplitDNS (for PTR lookups etc.)
  dns_init();
  open();

  return 0;
}

void
DNSProcessor::open(sockaddr const *target)
{
  DNSHandler *h = new DNSHandler;

  h->mutex = thread->mutex;
  h->m_res = &l_res;
  ats_ip_copy(&h->local_ipv4.sa, &local_ipv4.sa);
  ats_ip_copy(&h->local_ipv6.sa, &local_ipv6.sa);

  if (target) {
    ats_ip_copy(&h->ip, target);
  } else {
    ats_ip_invalidate(&h->ip); // marked to use default.
  }

  if (!dns_handler_initialized) {
    handler = h;
  }

  SET_CONTINUATION_HANDLER(h, &DNSHandler::startEvent);
  thread->schedule_imm(h);
}

//
// Initialization
//
void
DNSProcessor::dns_init()
{
  gethostname(try_server_names[0], 255);
  Dbg(dbg_ctl_dns, "localhost=%s", try_server_names[0]);
  Dbg(dbg_ctl_dns, "Round-robin nameservers = %d", dns_ns_rr);

  IpEndpoint nameserver[MAX_NAMED];
  size_t     nserv = 0;

  if (dns_ns_list) {
    Dbg(dbg_ctl_dns, "Nameserver list specified \"%s\"", dns_ns_list);
    int   i;
    char *last;
    char *ns_list = ats_strdup(dns_ns_list);
    char *ns      = strtok_r(ns_list, " ,;\t\r", &last);

    for (i = 0, nserv = 0; (i < MAX_NAMED) && ns; ++i) {
      Dbg(dbg_ctl_dns, "Nameserver list - parsing \"%s\"", ns);
      bool  err   = false;
      int   prt   = DOMAIN_SERVICE_PORT;
      char *colon = nullptr; // where the port colon is.
      // Check for IPv6 notation.
      if ('[' == *ns) {
        char *ndx = strchr(ns + 1, ']');
        if (ndx) {
          if (':' == ndx[1]) {
            colon = ndx + 1;
          }
        } else {
          err = true;
          Warning("Unmatched '[' in address for nameserver '%s', discarding.", ns);
        }
      } else {
        colon = strchr(ns, ':');
      }

      if (!err && colon) {
        *colon = '\0';
        // coverity[secure_coding]
        if (sscanf(colon + 1, "%d%*s", &prt) != 1) {
          Dbg(dbg_ctl_dns, "Unable to parse port number '%s' for nameserver '%s', discardin.", colon + 1, ns);
          Warning("Unable to parse port number '%s' for nameserver '%s', discarding.", colon + 1, ns);
          err = true;
        }
      }

      if (!err && 0 != ats_ip_pton(ns, &nameserver[nserv].sa)) {
        Dbg(dbg_ctl_dns, "Invalid IP address given for nameserver '%s', discarding", ns);
        Warning("Invalid IP address given for nameserver '%s', discarding", ns);
        err = true;
      }

      if (!err) {
        ip_port_text_buffer buff;

        ats_ip_port_cast(&nameserver[nserv].sa) = htons(prt);

        Dbg(dbg_ctl_dns, "Adding nameserver %s to nameserver list", ats_ip_nptop(&nameserver[nserv].sa, buff, sizeof(buff)));
        ++nserv;
      }

      ns = strtok_r(nullptr, " ,;\t\r", &last);
    }
    ats_free(ns_list);
  }
  // The default domain (5th param) and search list (6th param) will
  // come from /etc/resolv.conf.
  if (ink_res_init(&l_res, nameserver, nserv, dns_search, nullptr, nullptr, dns_resolv_conf) < 0) {
    Warning("Failed to build DNS res records for the servers (%s).  Using resolv.conf.", dns_ns_list);
  }

  // Check for local forced bindings.

  if (dns_local_ipv6) {
    if (0 != ats_ip_pton(dns_local_ipv6, &local_ipv6)) {
      ats_ip_invalidate(&local_ipv6);
      Warning("Invalid IP address '%s' for dns.local_ipv6 value, discarding.", dns_local_ipv6);
    } else if (!ats_is_ip6(&local_ipv6.sa)) {
      ats_ip_invalidate(&local_ipv6);
      Warning("IP address '%s' for dns.local_ipv6 value was not IPv6, discarding.", dns_local_ipv6);
    }
  }

  if (dns_local_ipv4) {
    if (0 != ats_ip_pton(dns_local_ipv4, &local_ipv4)) {
      ats_ip_invalidate(&local_ipv4);
      Warning("Invalid IP address '%s' for dns.local_ipv4 value, discarding.", dns_local_ipv4);
    } else if (!ats_is_ip4(&local_ipv4.sa)) {
      ats_ip_invalidate(&local_ipv4);
      Warning("IP address '%s' for dns.local_ipv4 value was not IPv4, discarding.", dns_local_ipv4);
    }
  }
}

/**
  Inter-OS portability for dn_expand.  dn_expand() expands the compressed
  domain name comp_dn to a full domain name. Expanded names are converted
  to upper case. msg is a pointer to the beginning of the message,
  exp_dn is a pointer to a buffer of size length for the result. The
  size of compressed name is returned or -1 if there was an error.

*/
inline int
ink_dn_expand(const u_char *msg, const u_char *eom, const u_char *comp_dn, u_char *exp_dn, int length)
{
  return ::dn_expand(const_cast<unsigned char *>(msg), const_cast<unsigned char *>(eom), const_cast<unsigned char *>(comp_dn),
                     reinterpret_cast<char *>(exp_dn), length);
}

DNSProcessor::DNSProcessor()
{
  ink_zero(l_res);
  ink_zero(local_ipv6);
  ink_zero(local_ipv4);
}

void
DNSEntry::init(DNSQueryData target, int qtype_arg, Continuation *acont, DNSProcessor::Options const &opt)
{
  qtype          = qtype_arg;
  host_res_style = opt.host_res_style;
  if (is_addr_query(qtype)) {
    // adjust things based on family preference.
    if (HOST_RES_IPV4 == host_res_style || HOST_RES_IPV4_ONLY == host_res_style) {
      qtype = T_A;
    } else if (HOST_RES_IPV6 == host_res_style || HOST_RES_IPV6_ONLY == host_res_style) {
      qtype = T_AAAA;
    }
  }
  submit_time   = ink_get_hrtime();
  action        = acont;
  submit_thread = acont->mutex->thread_holding;

  if (SplitDNSConfig::gsplit_dns_enabled) {
    dnsH = opt.handler ? opt.handler : dnsProcessor.handler;
  } else {
    dnsH = dnsProcessor.handler;
  }

  dnsH->txn_lookup_timeout = opt.timeout;

  mutex = dnsH->mutex;

  if (is_addr_query(qtype) || qtype == T_SRV) {
    auto name = target.name.substr(0, MAXDNAME); // be sure of safe copy into @a qname
    memcpy(qname, name);
    qname[name.size()] = '\0';
    orig_qname_len = qname_len = name.size();
  } else { // T_PTR
    auto addr = target.addr;
    if (addr->isIp6()) {
      orig_qname_len = qname_len = make_ipv6_ptr(&addr->_addr._ip6, qname);
    } else if (addr->isIp4()) {
      orig_qname_len = qname_len = make_ipv4_ptr(addr->_addr._ip4, qname);
    } else {
      ink_assert(!"T_PTR query to DNS must be IP address.");
    }
  }

  SET_HANDLER(&DNSEntry::mainEvent);
}

/**
 Open UDP and/or TCP connections based on dns_conn_mode
 */

void
DNSHandler::open_cons(sockaddr const *target, bool failed, int icon)
{
  if (dns_conn_mode != DNS_CONN_MODE::TCP_ONLY) {
    open_con(target, failed, icon, false);
  }
  if (dns_conn_mode != DNS_CONN_MODE::UDP_ONLY) {
    open_con(target, failed, icon, true);
  }
}

/**
 Close the old TCP connection and open a new one
 */
bool
DNSHandler::reset_tcp_conn(int ndx)
{
  Metrics::Counter::increment(dns_rsb.tcp_reset);
  tcpcon[ndx].close();
  return open_con(&m_res->nsaddr_list[ndx].sa, true, ndx, true);
}

/**
  Open (and close) connections as necessary and also assures that the
  epoll fd struct is properly updated.

  target == nullptr :
      open connection to DNSHandler::ip.
      generally, the icon should be 0 if target == nullptr.

  target != nullptr and icon == 0 :
      open connection to target, and the target is assigned to DNSHandler::ip.

  target != nullptr and icon > 0 :
      open connection to target.
*/
bool
DNSHandler::open_con(sockaddr const *target, bool failed, int icon, bool over_tcp)
{
  ip_port_text_buffer ip_text;
  PollDescriptor     *pd  = get_PollDescriptor(dnsProcessor.thread);
  bool                ret = false;

  ink_assert(target != &ip.sa);

  if (!icon && target) {
    ats_ip_copy(&ip, target);
  } else if (!target) {
    target = &ip.sa;
  }
  DNSConnection &cur_con = over_tcp ? tcpcon[icon] : udpcon[icon];

  Dbg(dbg_ctl_dns, "open_con: opening connection %s", ats_ip_nptop(target, ip_text, sizeof ip_text));

  if (!cur_con.sock.is_ok()) { // Remove old FD from epoll fd
    cur_con.close();
  }

  if (cur_con.connect(target, DNSConnection::Options()
                                .setNonBlockingConnect(true)
                                .setNonBlockingIo(true)
                                .setUseTcp(over_tcp)
                                .setBindRandomPort(true)
                                .setLocalIpv6(&local_ipv6.sa)
                                .setLocalIpv4(&local_ipv4.sa)) < 0) {
    Dbg(dbg_ctl_dns, "opening connection %s FAILED for %d", ip_text, icon);
    if (!failed) {
      if (dns_ns_rr) {
        rr_failure(icon);
      } else {
        failover();
      }
    }
    return false;
  } else {
    if (cur_con.eio.start(pd, cur_con.sock.get_fd(), EVENTIO_READ) < 0) {
      Error("[iocore_dns] open_con: Failed to add %d server to epoll list\n", icon);
    } else {
      cur_con.num   = icon;
      ns_down[icon] = 0;
      Dbg(dbg_ctl_dns, "opening connection %s on fd %d SUCCEEDED for %d", ip_text, cur_con.sock.get_fd(), icon);
    }
    ret = true;
  }

  return ret;
}

void
DNSHandler::validate_ip()
{
  if (!ip.isValid()) {
    // Invalid, switch to default.
    // seems that res_init always sets m_res.nscount to at least 1!
    if (!m_res->nscount || !ats_ip_copy(&ip.sa, &m_res->nsaddr_list[0].sa)) {
      Warning("bad nameserver config, fallback to loopback");
      ip.setToLoopback(AF_INET);
    }
  }
}
/**
  Initial state of the DNSHandler. Can reinitialize the running DNS
  handler to a new nameserver.

*/
int
DNSHandler::startEvent(int /* event ATS_UNUSED */, Event *e)
{
  //
  // If this is for the default server, get it
  Dbg(dbg_ctl_dns, "DNSHandler::startEvent: on thread %d", e->ethread->id);

  this->validate_ip();

  if (!dns_handler_initialized) {
    //
    // If we are THE handler, open connection and configure for
    // periodic execution.
    //
    dns_handler_initialized = 1;
    SET_HANDLER(&DNSHandler::mainEvent);
    if (dns_ns_rr) {
      /* Round Robin mode:
       *   Establish a connection to each DNS server to make it a connection pool.
       *   For each DNS Request, a connection is picked up from the pool by round robin method.
       *
       *   The first DNS server is assigned to DNSHandler::ip within open_con() function.
       */
      int max_nscount = m_res->nscount;
      if (max_nscount > MAX_NAMED) {
        max_nscount = MAX_NAMED;
      }
      n_con = 0;
      for (int i = 0; i < max_nscount; i++) {
        ip_port_text_buffer buff;
        sockaddr           *sa = &m_res->nsaddr_list[i].sa;
        if (ats_is_ip(sa)) {
          open_cons(sa, false, n_con);
          ++n_con;
          Dbg(dbg_ctl_dns_pas, "opened connection to %s, n_con = %d", ats_ip_nptop(sa, buff, sizeof(buff)), n_con);
        }
      }
      dns_ns_rr_init_down = 0;
    } else {
      /* Primary - Secondary mode:
       *   Establish a connection to the Primary DNS server.
       *   It always send DNS requests to the Primary DNS server.
       *   If the Primary DNS server dies,
       *     - it will attempt to send DNS requests to the secondary DNS server until the Primary DNS server is back.
       *     - and keep to detect the health of the Primary DNS server.
       *   If DNSHandler::recv_dns() got a valid DNS response from the Primary DNS server,
       *     - it means that the Primary DNS server returns.
       *     - it send all DNS requests to the Primary DNS server.
       *
       *   The first DNS server is the Primary DNS server, and it is assigned to DNSHandler::ip within validate_ip() function.
       */
      open_cons(nullptr); // use current target address.
      n_con = 1;
    }

    // Retrying the name servers is something done periodically over the
    // lifetime of the handler. This ensures that we don't miss retrying if it
    // is necessary.
    this->_dns_retry_event = this_ethread()->schedule_every(this, DNS_PRIMARY_RETRY_PERIOD);

    return EVENT_CONT;
  } else {
    ink_assert(false); // I.e. this should never really happen
    return EVENT_DONE;
  }
}

/**
  Initial state of the DSNHandler. Can reinitialize the running DNS
  handler to a new nameserver.
*/
int
DNSHandler::startEvent_sdns(int /* event ATS_UNUSED */, Event *e)
{
  Dbg(dbg_ctl_dns, "DNSHandler::startEvent_sdns: on thread %d", e->ethread->id);
  this->validate_ip();

  SET_HANDLER(&DNSHandler::mainEvent);
  open_cons(nullptr, false, 0);
  n_con = 1;

  return EVENT_CONT;
}

static inline int
_ink_res_mkquery(ink_res_state res, char *qname, int qtype, unsigned char *buffer, bool over_tcp = false)
{
  int offset = over_tcp ? tcp_data_length_offset : 0;
  int r      = ink_res_mkquery(res, QUERY, qname, C_IN, qtype, nullptr, 0, nullptr, buffer + offset, MAX_DNS_REQUEST_LEN - offset);
  if (over_tcp) {
    NS_PUT16(r, buffer);
  }
  return r + offset;
}

void
DNSHandler::recover()
{
  ip_text_buffer buff;
  Warning("connection to DNS server %s restored", ats_ip_ntop(&ip.sa, buff, sizeof(buff)));
  name_server = 0;
  switch_named(name_server);
}

void
DNSHandler::retry_named(int ndx, ink_hrtime t, bool reopen)
{
  if (reopen && ((t - last_primary_reopen) > DNS_PRIMARY_REOPEN_PERIOD)) {
    Dbg(dbg_ctl_dns, "retry_named: reopening DNS connection for index %d", ndx);
    last_primary_reopen = t;
    if (dns_conn_mode != DNS_CONN_MODE::TCP_ONLY) {
      udpcon[ndx].close();
    }
    if (dns_conn_mode != DNS_CONN_MODE::UDP_ONLY) {
      tcpcon[ndx].close();
    }
    open_cons(&m_res->nsaddr_list[ndx].sa, true, ndx);
  }
  bool          over_tcp = dns_conn_mode == DNS_CONN_MODE::TCP_ONLY;
  UnixSocket    con_sock = over_tcp ? tcpcon[ndx].sock : udpcon[ndx].sock;
  unsigned char buffer[MAX_DNS_REQUEST_LEN];
  Dbg(dbg_ctl_dns, "trying to resolve '%s' from DNS connection, ndx %d", try_server_names[try_servers], ndx);
  int r       = _ink_res_mkquery(m_res, try_server_names[try_servers], T_A, buffer, over_tcp);
  try_servers = (try_servers + 1) % countof(try_server_names);
  ink_assert(r >= 0);
  if (r >= 0) { // looking for a bounce
    int res = con_sock.send(buffer, r, 0);
    Dbg(dbg_ctl_dns, "ping result = %d", res);
  }
}

void
DNSHandler::try_primary_named(bool reopen)
{
  ink_hrtime t = ink_get_hrtime();
  if (reopen && ((t - last_primary_reopen) > DNS_PRIMARY_REOPEN_PERIOD)) {
    Dbg(dbg_ctl_dns, "try_primary_named: reopening primary DNS connection");
    last_primary_reopen = t;
    open_cons(nullptr, true, 0);
  }
  if ((t - last_primary_retry) > DNS_PRIMARY_RETRY_PERIOD) {
    unsigned char buffer[MAX_DNS_REQUEST_LEN];
    bool          over_tcp = dns_conn_mode == DNS_CONN_MODE::TCP_ONLY;
    UnixSocket    con_sock = over_tcp ? tcpcon[0].sock : udpcon[0].sock;
    last_primary_retry     = t;
    Dbg(dbg_ctl_dns, "trying to resolve '%s' from primary DNS connection", try_server_names[try_servers]);
    int r = _ink_res_mkquery(m_res, try_server_names[try_servers], T_A, buffer, over_tcp);
    // if try_server_names[] is not full, round-robin within the
    // filled entries.
    if (local_num_entries < DEFAULT_NUM_TRY_SERVER) {
      try_servers = (try_servers + 1) % local_num_entries;
    } else {
      try_servers = (try_servers + 1) % countof(try_server_names);
    }
    ink_assert(r >= 0);
    if (r >= 0) { // looking for a bounce
      int res = con_sock.send(buffer, r, 0);
      Dbg(dbg_ctl_dns, "ping result = %d", res);
    }
  }
}

void
DNSHandler::switch_named(int ndx)
{
  for (DNSEntry *e = entries.head; e; e = static_cast<DNSEntry *>(e->link.next)) {
    e->written_flag = false;
    if (e->retries < dns_retries) {
      ++(e->retries); // give them another chance
    }
  }
  in_flight = 0;
  received_one(ndx); // reset failover counters
}

/** Fail over to another name server. */
void
DNSHandler::failover()
{
  Dbg(dbg_ctl_dns, "failover: initiating failover attempt, current name_server=%d", name_server);
  if (!ns_down[name_server]) {
    ip_text_buffer buff;
    // mark this nameserver as down
    Dbg(dbg_ctl_dns, "failover: Marking nameserver %d as down", name_server);
    ns_down[name_server] = 1;
    Warning("connection to DNS server %s lost, marking as down",
            ats_ip_ntop(&m_res->nsaddr_list[name_server].sa, buff, sizeof(buff)));
  }

  // no hope, if we have only one server
  if (m_res->nscount > 1) {
    ip_text_buffer buff1, buff2;
    int            max_nscount = m_res->nscount;

    if (max_nscount > MAX_NAMED) {
      max_nscount = MAX_NAMED;
    }
    sockaddr const *old_addr = &m_res->nsaddr_list[name_server].sa;
    name_server              = (name_server + 1) % max_nscount;
    Dbg(dbg_ctl_dns, "failover: failing over to name_server=%d", name_server);

    IpEndpoint target;
    ats_ip_copy(&target.sa, &m_res->nsaddr_list[name_server].sa);

    Warning("failover: connection to DNS server %s lost, move to %s", ats_ip_ntop(old_addr, buff1, sizeof(buff1)),
            ats_ip_ntop(&target.sa, buff2, sizeof(buff2)));

    if (!target.isValid()) {
      target.setToLoopback(AF_INET);
    }

    open_cons(&target.sa, true, name_server);
    if (n_con <= name_server) {
      n_con = name_server + 1;
    }
    switch_named(name_server);
  } else {
    if (dns_conn_mode != DNS_CONN_MODE::TCP_ONLY) {
      udpcon[0].close();
    }
    if (dns_conn_mode != DNS_CONN_MODE::UDP_ONLY) {
      tcpcon[0].close();
    }
    ip_text_buffer buff;
    Warning("failover: connection to DNS server %s lost, retrying", ats_ip_ntop(&ip.sa, buff, sizeof(buff)));
  }
}

/** Mark one of the nameservers as down. */
void
DNSHandler::rr_failure(int ndx)
{
  // no hope, if we have only one server
  if (!ns_down[ndx]) {
    ip_text_buffer buff;
    // mark this nameserver as down
    Dbg(dbg_ctl_dns, "rr_failure: Marking nameserver %d as down", ndx);
    ns_down[ndx] = 1;
    Warning("connection to DNS server %s lost, marking as down", ats_ip_ntop(&m_res->nsaddr_list[ndx].sa, buff, sizeof(buff)));
  }

  int nscount = m_res->nscount;
  if (nscount > MAX_NAMED) {
    nscount = MAX_NAMED;
  }

  // See if all nameservers are down
  int all_down = 1;

  for (int i = 0; i < nscount && all_down; i++) {
    Dbg(dbg_ctl_dns, "nsdown[%d]=%d", i, ns_down[i]);
    if (!ns_down[i]) {
      all_down = 0;
    }
  }

  if (all_down && !dns_ns_rr_init_down) {
    Warning("connection to all DNS servers lost, retrying");
    // actual retries will be done in retry_named called from mainEvent
    // mark any outstanding requests as not sent for later retry
    for (DNSEntry *e = entries.head; e; e = static_cast<DNSEntry *>(e->link.next)) {
      e->written_flag = false;
      if (e->retries < dns_retries) {
        ++(e->retries); // give them another chance
      }
      --in_flight;
      Metrics::Gauge::decrement(dns_rsb.in_flight);
    }
  } else {
    // move outstanding requests that were sent to this nameserver to another
    for (DNSEntry *e = entries.head; e; e = static_cast<DNSEntry *>(e->link.next)) {
      if (e->which_ns == ndx) {
        e->written_flag = false;
        if (e->retries < dns_retries) {
          ++(e->retries); // give them another chance
        }
        --in_flight;
        Metrics::Gauge::decrement(dns_rsb.in_flight);
      }
    }
  }
}

static bool
good_rcode(char *buff)
{
  unsigned int r = get_rcode(buff);
  return NOERROR == r || NXDOMAIN == r;
}

void
DNSHandler::recv_dns(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
{
  DNSConnection *dnsc = nullptr;
  ip_text_buffer ipbuff1, ipbuff2;
  Ptr<HostEnt>   buf;
  while ((dnsc = static_cast<DNSConnection *>(triggered.dequeue()))) {
    while (true) {
      int        res;
      IpEndpoint from_ip;
      socklen_t  from_length = sizeof(from_ip);
      if (dnsc->opt._use_tcp) {
        if (dnsc->tcp_data.buf_ptr == nullptr) {
          dnsc->tcp_data.buf_ptr = make_ptr(dnsBufAllocator.alloc());
        }
        if (dnsc->tcp_data.total_length == 0) {
          // see if TS gets a two-byte size
          uint16_t tmp = 0;
          res          = dnsc->sock.recv(&tmp, sizeof(tmp), MSG_PEEK);
          if (res == -EAGAIN || res == 1) {
            break;
          }
          if (res <= 0) {
            goto Lerror;
          }
          // reading total size
          res = dnsc->sock.recv(&(dnsc->tcp_data.total_length), sizeof(dnsc->tcp_data.total_length), 0);
          if (res == -EAGAIN) {
            break;
          }
          if (res <= 0) {
            goto Lerror;
          }
          dnsc->tcp_data.total_length = ntohs(dnsc->tcp_data.total_length);
          if (res != sizeof(dnsc->tcp_data.total_length)) {
            goto Lerror;
          }
        }
        // continue reading data
        void *buf_start = dnsc->tcp_data.buf_ptr->buf + dnsc->tcp_data.done_reading;
        res             = dnsc->sock.recv(buf_start, dnsc->tcp_data.total_length - dnsc->tcp_data.done_reading, 0);
        if (res == -EAGAIN) {
          break;
        }
        if (res <= 0) {
          goto Lerror;
        }
        Dbg(dbg_ctl_dns, "received packet size = %d over TCP", res);
        dnsc->tcp_data.done_reading += res;
        if (dnsc->tcp_data.done_reading < dnsc->tcp_data.total_length) {
          break;
        }
        buf = dnsc->tcp_data.buf_ptr;
        res = dnsc->tcp_data.total_length;
        dnsc->tcp_data.reset();
        goto Lsuccess;
      }

      if (!hostent_cache) {
        hostent_cache = dnsBufAllocator.alloc();
      }

      res = dnsc->sock.recvfrom(hostent_cache->buf, MAX_DNS_RESPONSE_LEN, 0, &from_ip.sa, &from_length);
      Dbg(dbg_ctl_dns, "DNSHandler::recv_dns res = [%d]", res);
      if (res == -EAGAIN) {
        break;
      }
      if (res <= 0) {
      Lerror:
        Dbg(dbg_ctl_dns, "named error: %d", res);
        if (dns_ns_rr) {
          rr_failure(dnsc->num);
        } else if (dnsc->num == name_server) {
          failover();
        }
        break;
      }

      // verify that this response came from the correct server
      if (!ats_ip_addr_eq(&dnsc->ip.sa, &from_ip.sa)) {
        Warning("unexpected DNS response from %s (expected %s)", ats_ip_ntop(&from_ip.sa, ipbuff1, sizeof ipbuff1),
                ats_ip_ntop(&dnsc->ip.sa, ipbuff2, sizeof ipbuff2));
        continue;
      }
      buf              = hostent_cache;
      hostent_cache    = nullptr;
      buf->packet_size = res;
      Dbg(dbg_ctl_dns, "received packet size = %d", res);
    Lsuccess:
      if (dns_ns_rr) {
        Dbg(dbg_ctl_dns, "round-robin: nameserver %d DNS response code = %d", dnsc->num, get_rcode(buf->buf));
        if (good_rcode(buf->buf)) {
          received_one(dnsc->num);
          if (ns_down[dnsc->num]) {
            Warning("connection to DNS server %s restored",
                    ats_ip_ntop(&m_res->nsaddr_list[dnsc->num].sa, ipbuff1, sizeof ipbuff1));
            ns_down[dnsc->num] = 0;
          }
        }
      } else {
        if (!dnsc->num) {
          Dbg(dbg_ctl_dns, "primary DNS response code = %d", get_rcode(buf->buf));
          if (good_rcode(buf->buf)) {
            if (name_server) {
              recover();
            } else {
              received_one(name_server);
            }
          }
        }
      }
      if (dns_process(this, buf.get(), res)) {
        if (dnsc->num == name_server) {
          received_one(name_server);
        }
      }
    }
  }
}

void
DNSHandler::check_and_reset_tcp_conn()
{
  for (int i = 0; i < n_con; i++) {
    if (dns_max_tcp_continuous_failures > 0 && tcp_continuous_failures[i] >= dns_max_tcp_continuous_failures) {
      // The times of continuous failures are more than the threshold, have to reset the connection
      if (reset_tcp_conn(i)) {
        // Reset the counter after the new TCP connection
        // don't reset the counter if tcp conn reset failed, and we need continue to try to reset tcp conn next time
        Warning("Reset tcp connection: nameserver = %d, failures = %d, threshold = %d", i, tcp_continuous_failures[i],
                dns_max_tcp_continuous_failures);
        tcp_continuous_failures[i] = 0;
      }
    }
  }
}

/** Main event for the DNSHandler. Attempt to read from and write to named. */
int
DNSHandler::mainEvent(int event, Event *e)
{
  recv_dns(event, e);
  if (dns_ns_rr) {
    if (DNS_CONN_MODE::TCP_RETRY == dns_conn_mode) {
      check_and_reset_tcp_conn();
    }
    ink_hrtime t = ink_get_hrtime();
    if (t - last_primary_retry > DNS_PRIMARY_RETRY_PERIOD) {
      for (int i = 0; i < n_con; i++) {
        if (ns_down[i]) {
          Dbg(dbg_ctl_dns, "mainEvent: nameserver = %d is down", i);
          retry_named(i, t, true);
        }
      }
      last_primary_retry = t;
    }
    for (int i = 0; i < n_con; i++) {
      if (!ns_down[i] && failover_soon(i)) {
        Dbg(dbg_ctl_dns, "mainEvent: nameserver = %d failover soon", name_server);
        if (failover_now(i)) {
          rr_failure(i);
        } else {
          Dbg(dbg_ctl_dns, "mainEvent: nameserver = %d no failover now - retrying", i);
          retry_named(i, t, false);
          ++failover_soon_number[i];
        }
      }
    }
  } else {
    if (failover_soon(name_server)) {
      Dbg(dbg_ctl_dns, "mainEvent: will failover soon");
      if (failover_now(name_server)) {
        Dbg(dbg_ctl_dns, "mainEvent: failing over now to another nameserver");
        failover();
      } else {
        try_primary_named(false);
        ++failover_soon_number[name_server];
      }
    } else if (name_server) { // not on the primary named
      try_primary_named(true);
    }
  }

  if (entries.head) {
    write_dns(this);
  }

  return EVENT_CONT;
}

/** Find a DNSEntry by id. */
inline static DNSEntry *
get_dns(DNSHandler *h, uint16_t id)
{
  for (DNSEntry *e = h->entries.head; e; e = static_cast<DNSEntry *>(e->link.next)) {
    if (e->once_written_flag) {
      for (int j : e->id) {
        if (j == id) {
          return e;
        } else if (j < 0) {
          goto Lnext;
        }
      }
    }
  Lnext:;
  }
  return nullptr;
}

/** Find a DNSEntry by query name and type. */
inline static DNSEntry *
get_entry(DNSHandler *h, char *qname, int qtype)
{
  for (DNSEntry *e = h->entries.head; e; e = static_cast<DNSEntry *>(e->link.next)) {
    if (e->qtype == qtype) {
      if (is_addr_query(qtype)) {
        if (!strcmp(qname, e->qname)) {
          return e;
        }
      } else if (0 == memcmp(qname, e->qname, e->qname_len)) {
        return e;
      }
    }
  }
  return nullptr;
}

/** Write up to dns_max_dns_in_flight entries. */
static void
write_dns(DNSHandler *h, bool tcp_retry)
{
  Metrics::Counter::increment(dns_rsb.total_lookups);
  int max_nscount = h->m_res->nscount;
  if (max_nscount > MAX_NAMED) {
    max_nscount = MAX_NAMED;
  }
  if (max_nscount <= 0) {
    Warning("There is no name server found in the resolv.conf");
    if (h->entries.head) {
      dns_result(h, h->entries.head, nullptr, false);
    }
    return;
  }

  if (h->in_write_dns) {
    return;
  }
  h->in_write_dns = true;
  bool over_tcp   = (dns_conn_mode == DNS_CONN_MODE::TCP_ONLY) || ((dns_conn_mode == DNS_CONN_MODE::TCP_RETRY) && tcp_retry);
  if (h->in_flight < dns_max_dns_in_flight) {
    DNSEntry *e = h->entries.head;
    while (e) {
      DNSEntry *n = static_cast<DNSEntry *>(e->link.next);
      if (!e->written_flag) {
        if (dns_ns_rr) {
          int ns_start = h->name_server;
          do {
            h->name_server = (h->name_server + 1) % max_nscount;
          } while (h->ns_down[h->name_server] && h->name_server != ns_start);
        }
        if (h->ns_down[h->name_server] || !write_dns_event(h, e, over_tcp)) {
          break;
        }
      }
      if (h->in_flight >= dns_max_dns_in_flight) {
        break;
      }
      e = n;
    }
  }
  h->in_write_dns = false;
}

uint16_t
DNSHandler::get_query_id()
{
  uint16_t q1, q2;
  q2 = q1 = static_cast<uint16_t>(generator.random() & 0xFFFF);
  if (query_id_in_use(q2)) {
    uint16_t i = q2 >> 6;
    while (qid_in_flight[i] == UINT64_MAX) {
      if (++i == sizeof(qid_in_flight) / sizeof(uint64_t)) {
        i = 0;
      }
      if (i == q1 >> 6) {
        Error("[iocore_dns] get_query_id: Exhausted all DNS query ids");
        return q1;
      }
    }
    i  <<= 6;
    q2  &= 0x3F;
    while (query_id_in_use(i + q2)) {
      ++q2;
      q2 &= 0x3F;
      if (q2 == (q1 & 0x3F)) {
        Error("[iocore_dns] get_query_id: Exhausted all DNS query ids");
        return q1;
      }
    }
    q2 += i;
  }

  set_query_id_in_use(q2);
  return q2;
}

/**
  Construct and Write the request for a single entry (using send(3N)).

  @return true = keep going, false = give up for now.

*/
static bool
write_dns_event(DNSHandler *h, DNSEntry *e, bool over_tcp)
{
  unsigned char buffer[MAX_DNS_REQUEST_LEN];
  int           offset = over_tcp ? tcp_data_length_offset : 0;
  HEADER       *header = reinterpret_cast<HEADER *>(buffer + offset);
  int           r      = 0;

  if ((r = _ink_res_mkquery(h->m_res, e->qname, e->qtype, buffer, over_tcp)) <= 0) {
    Dbg(dbg_ctl_dns, "cannot build query: %s", e->qname);
    dns_result(h, e, nullptr, false);
    return true;
  }

  uint16_t i = h->get_query_id();
  header->id = htons(i);
  if (e->id[dns_retries - e->retries] >= 0) {
    // clear previous id in case named was switched or domain was expanded
    h->release_query_id(e->id[dns_retries - e->retries]);
  }
  e->id[dns_retries - e->retries] = i;
  UnixSocket con_sock             = over_tcp ? h->tcpcon[h->name_server].sock : h->udpcon[h->name_server].sock;
  Dbg(dbg_ctl_dns, "send query (qtype=%d) for %s to fd %d", e->qtype, e->qname, con_sock.get_fd());

  int s = con_sock.send(buffer, r, 0);
  if (s != r) {
    Dbg(dbg_ctl_dns, "send() failed: qname = %s, %d != %d, nameserver= %d", e->qname, s, r, h->name_server);

    if (over_tcp) {
      // add the counter for tcp connection failed
      Dbg(dbg_ctl_dns, "tcp query failed: name_server = %d, tcp_continuous_failures = %d", h->name_server,
          h->tcp_continuous_failures[h->name_server]);
      ++h->tcp_continuous_failures[h->name_server];
    }

    // changed if condition from 'r < 0' to 's < 0' - 8/2001 pas
    if (s < 0) {
      if (dns_ns_rr) {
        h->rr_failure(h->name_server);
      } else {
        h->failover();
      }
    }
    return false;
  }

  if (over_tcp && h->tcp_continuous_failures[h->name_server] > 0) {
    // reset the counter for any tcp connection succeed
    Dbg(dbg_ctl_dns, "reset tcp_continuous_failures: name_server = %d, tcp_continuous_failures = %d", h->name_server,
        h->tcp_continuous_failures[h->name_server]);
    h->tcp_continuous_failures[h->name_server] = 0;
  }

  e->written_flag      = true;
  e->which_ns          = h->name_server;
  e->once_written_flag = true;
  ++h->in_flight;
  Metrics::Gauge::increment(dns_rsb.in_flight);

  e->send_time = ink_get_hrtime();

  if (e->timeout) {
    e->timeout->cancel();
  }

  if (h->txn_lookup_timeout) {
    e->timeout = h->mutex->thread_holding->schedule_in(e, HRTIME_MSECONDS(h->txn_lookup_timeout)); // this is in msec
  } else {
    e->timeout = h->mutex->thread_holding->schedule_in(e, HRTIME_SECONDS(dns_timeout));
  }

  Dbg(dbg_ctl_dns, "sent qname = %s, id = %u, nameserver = %d", e->qname, e->id[dns_retries - e->retries], h->name_server);
  h->sent_one();
  return true;
}

int
DNSEntry::delayEvent(int event, Event *e)
{
  (void)event;
  if (dnsProcessor.handler) {
    SET_HANDLER(&DNSEntry::mainEvent);
    return handleEvent(EVENT_IMMEDIATE, e);
  }
  e->schedule_in(DNS_DELAY_PERIOD);
  return EVENT_CONT;
}

/** Handle timeout events. */
int
DNSEntry::mainEvent(int event, Event *e)
{
  switch (event) {
  default:
    ink_assert(!"bad case");
    return EVENT_DONE;
  case EVENT_IMMEDIATE: {
    if (!dnsH) {
      dnsH = dnsProcessor.handler;
    }
    if (!dnsH) {
      Dbg(dbg_ctl_dns, "handler not found, retrying...");
      SET_HANDLER(&DNSEntry::delayEvent);
      return handleEvent(event, e);
    }

    // trailing '.' indicates no domain expansion
    if (dns_search && ('.' != qname[orig_qname_len - 1])) {
      domains = dnsH->m_res->dnsrch;
      // start domain expansion straight away
      // if lookup name has no '.'
      if (domains && !strnchr(qname, '.', MAXDNAME)) {
        qname[orig_qname_len] = '.';
        qname_len = orig_qname_len + 1 + ink_strlcpy(qname + orig_qname_len + 1, *domains, MAXDNAME - (orig_qname_len + 1));
        ++domains;
      }
    } else {
      domains = nullptr;
    }
    Dbg(dbg_ctl_dns, "enqueuing query %s", qname);
    DNSEntry *dup = get_entry(dnsH, qname, qtype);
    if (dup) {
      Dbg(dbg_ctl_dns, "collapsing NS request");
      dup->dups.enqueue(this);
    } else {
      Dbg(dbg_ctl_dns, "adding first to collapsing queue");
      dnsH->entries.enqueue(this);
      dnsProcessor.thread->schedule_imm(dnsH);
    }
    return EVENT_DONE;
  }
  case EVENT_INTERVAL:
    Dbg(dbg_ctl_dns, "timeout for query %s", qname);
    if (dnsH->txn_lookup_timeout) {
      timeout = nullptr;
      dns_result(dnsH, this, result_ent.get(), false); // do not retry -- we are over TXN timeout on DNS alone!
      return EVENT_DONE;
    }
    if (written_flag) {
      Dbg(dbg_ctl_dns, "marking %s as not-written", qname);
      written_flag = false;
      --(dnsH->in_flight);
      Metrics::Gauge::decrement(dns_rsb.in_flight);
    }
    timeout = nullptr;
    dns_result(dnsH, this, result_ent.get(), true);
    return EVENT_DONE;
  }
}

Action *
DNSProcessor::getby(DNSQueryData x, int type, Continuation *cont, Options const &opt)
{
  if (type == T_PTR) {
    Dbg(dbg_ctl_dns, "received reverse query type = %d, timeout = %d", type, opt.timeout);
  } else {
    Dbg(dbg_ctl_dns, "received query %.*s type = %d, timeout = %d", int(x.name.size()), x.name.data(), type, opt.timeout);
    if (type == T_SRV) {
      Dbg(dbg_ctl_dns_srv, "DNSProcessor::getby attempting an SRV lookup for %.*s, timeout = %d", int(x.name.size()), x.name.data(),
          opt.timeout);
    }
  }
  DNSEntry *e = dnsEntryAllocator.alloc();
  e->retries  = dns_retries;
  e->init(x, type, cont, opt);
  MUTEX_TRY_LOCK(lock, e->mutex, this_ethread());
  if (!lock.is_locked()) {
    thread->schedule_imm(e);
  } else {
    e->handleEvent(EVENT_IMMEDIATE, nullptr);
  }
  return &e->action;
}

/**
  We have a result for an entry, return it to the user or retry if it
  is a retry-able and we have retries left.
*/
static void
dns_result(DNSHandler *h, DNSEntry *e, HostEnt *ent, bool retry, bool tcp_retry)
{
  bool cancelled = (e->action.cancelled ? true : false);
  retry          = retry || tcp_retry;

  if ((!ent || !ent->good) && !cancelled) {
    // try to retry operation
    if (retry && e->retries) {
      Dbg(dbg_ctl_dns, "doing retry for %s", e->qname);

      Metrics::Counter::increment(dns_rsb.tcp_retries);

      --(e->retries);
      write_dns(h, tcp_retry);
      return;
    } else if (e->domains && *e->domains) {
      do {
        Dbg(dbg_ctl_dns, "domain extending, last tried '%s', original '%.*s'", e->qname, e->orig_qname_len, e->qname);

        // Make sure the next try fits
        if (e->orig_qname_len + strlen(*e->domains) + 2 > MAXDNAME) {
          Dbg(dbg_ctl_dns, "domain too large %.*s + %s", e->orig_qname_len, e->qname, *e->domains);
        } else {
          e->qname[e->orig_qname_len] = '.';
          e->qname_len =
            e->orig_qname_len + 1 + ink_strlcpy(e->qname + e->orig_qname_len + 1, *e->domains, MAXDNAME - (e->orig_qname_len + 1));
          ++(e->domains);
          e->retries = dns_retries;
          Dbg(dbg_ctl_dns, "new name = %s retries = %d", e->qname, e->retries);
          write_dns(h, tcp_retry);

          return;
        }

        // Try another one
        ++(e->domains);
      } while (*e->domains);
    } else {
      e->qname[e->qname_len] = 0;
      if (!strchr(e->qname, '.') && !e->last) {
        e->last = true;
        write_dns(h, tcp_retry);
        return;
      }
    }
    if (retry) {
      Metrics::Counter::increment(dns_rsb.max_retries_exceeded);
    }
  }
  if (ent == BAD_DNS_RESULT) {
    ent = nullptr;
  }
  if (!cancelled) {
    // ToDo: Should this possibly be send_time() ??
    ink_hrtime diff = (ink_get_hrtime() - e->submit_time) / HRTIME_MSECOND;

    // These are rolling averages, this requires that the lookup_fail/success counters are incremented later
    if (!ent || !ent->good) {
      Metrics::Counter::increment(dns_rsb.fail_time, diff);
      Metrics::Counter::increment(dns_rsb.lookup_fail);
    } else {
      Metrics::Counter::increment(dns_rsb.success_time, diff);

      Metrics::Counter::increment(dns_rsb.lookup_success);
    }
  }

  // Remove head node from DNSHandler::entries queue
  h->entries.remove(e);
  // Release Query ID from DNSHandler
  for (int i : e->id) {
    if (i < 0) {
      break;
    }
    h->release_query_id(i);
  }

  if (dbg_ctl_dns.on()) {
    if (is_addr_query(e->qtype)) {
      ip_text_buffer buff;
      const char    *ptr    = "<none>";
      const char    *result = "FAIL";
      if (ent && ent->good) {
        result = "SUCCESS";
        ptr    = inet_ntop(e->qtype == T_AAAA ? AF_INET6 : AF_INET, ent->ent.h_addr_list[0], buff, sizeof(buff));
      }
      DbgPrint(dbg_ctl_dns, "%s result for %s = %s retry %d", result, e->qname, ptr, retry);
    } else {
      if (ent && ent->good) {
        DbgPrint(dbg_ctl_dns, "SUCCESS result for %s = %s af=%d retry %d", e->qname, ent->ent.h_name, ent->ent.h_addrtype, retry);
      } else {
        DbgPrint(dbg_ctl_dns, "FAIL result for %s = <not found> retry %d", e->qname, retry);
      }
    }
  }

  // Save HostEnt to the head node
  e->result_ent = ent;
  e->retries    = 0;
  SET_CONTINUATION_HANDLER(e, &DNSEntry::postAllEvent);
  e->handleEvent(EVENT_NONE, nullptr);
}

int
DNSEntry::postAllEvent(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
{
  /* Traverse the DNSEntry queue and callback
   *
   * The first DNSEntry object is head node,
   *   - Pushed into DNSHandler::entries queue,
   *   - Initial a DNS request and send to named server,
   *   - Maintained a dups queue which holds the DNSEntry object for the same DNS request,
   *   - All the DNSEntry in the queue share the same HostEnt result
   *
   * The head node callback the HostEnt result to the Continuation of all nodes one by one,
   *   - If one of the callback fails, put the node back to the dups queue and try again later by reschedule the head node,
   *   - Always call back the head node until the dups queue is empty.
   */
  DNSEntry *dup = nullptr;
  while ((dup = dups.dequeue())) {
    if (dup->post(dnsH, result_ent.get())) {
      // If one of the callback fails, put the node back to the dups queue
      dups.enqueue(dup);
      // Try again by reschedule the head node
      if (timeout) {
        timeout->cancel();
      }
      timeout = dnsH->mutex->thread_holding->schedule_in(this, MUTEX_RETRY_DELAY);
      return EVENT_DONE;
    }
  }

  // Process the head node at last
  if (post(dnsH, result_ent.get())) {
    // If the callback fails, switch the handler to DNSEntry::postOneEvent and reschedule it.
    mutex = action.mutex;
    SET_HANDLER(&DNSEntry::postOneEvent);
    submit_thread->schedule_imm(this);
  }
  return EVENT_DONE;
}

int
DNSEntry::post(DNSHandler *h, HostEnt *ent)
{
  if (timeout) {
    timeout->cancel(this);
    timeout = nullptr;
  }
  result_ent = ent;
  if (h->mutex->thread_holding == submit_thread) {
    MUTEX_TRY_LOCK(lock, action.mutex, h->mutex->thread_holding);
    if (!lock.is_locked()) {
      Dbg(dbg_ctl_dns, "failed lock for result %s", qname);
      return 1;
    }
    postOneEvent(0, nullptr);
  } else {
    mutex = action.mutex;
    SET_HANDLER(&DNSEntry::postOneEvent);
    submit_thread->schedule_imm(this);
  }
  return 0;
}

int
DNSEntry::postOneEvent(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
{
  if (!action.cancelled) {
    Dbg(dbg_ctl_dns, "called back continuation for %s", qname);
    action.continuation->handleEvent(DNS_EVENT_LOOKUP, result_ent.get());
  }
  result_ent   = nullptr;
  action.mutex = nullptr;
  mutex        = nullptr;
  dnsEntryAllocator.free(this);
  return EVENT_DONE;
}

/** Decode the reply from "named". */
static bool
dns_process(DNSHandler *handler, HostEnt *buf, int len)
{
  HEADER   *h         = reinterpret_cast<HEADER *>(buf->buf);
  DNSEntry *e         = get_dns(handler, static_cast<uint16_t>(ntohs(h->id)));
  bool      retry     = false;
  bool      tcp_retry = false;
  bool      server_ok = true;
  uint32_t  temp_ttl  = 0;

  const char *RCODE_NAME[] = {
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
  };

  const char *RCODE_DESCRIPTION[] = {
    "No Error",
    "Format Error",
    "Server Failure",
    "Non-Existent Domain",
    "Not Implemented",
    "Query Refused",
    "Name Exists when it should not",
    "RR Set Exists when it should not",
    "RR Set that should exist does not",
    "Not Authorized",
    "Name not contained in zone",
  };

  //
  // Do we have an entry for this id?
  //
  if (!e || !e->written_flag) {
    Dbg(dbg_ctl_dns, "unknown DNS id = %u", static_cast<uint16_t>(ntohs(h->id)));
    return false; // cannot count this as a success
  }
  //
  // It is no longer in flight
  //
  e->written_flag = false;
  --(handler->in_flight);
  Metrics::Gauge::decrement(dns_rsb.in_flight);
  // These are rolling averages
  ink_hrtime diff = (ink_get_hrtime() - e->send_time) / HRTIME_MSECOND;

  Metrics::Counter::increment(dns_rsb.response_time, diff);

  // retrying over TCP when truncated is set
  if (dns_conn_mode == DNS_CONN_MODE::TCP_RETRY && h->tc == 1) {
    Dbg(dbg_ctl_dns, "Retrying DNS query over TCP for [%s]", e->qname);
    tcp_retry = true;
    Metrics::Counter::increment(dns_rsb.tcp_retries);
    goto Lerror;
  }

  // Logs using SiteThrottled* version is helpful for noisy logs, being used here
  // instead of print statements to help with the possible retries when a dns code occurs
  if (h->rcode != NOERROR || !h->ancount) {
    Dbg(dbg_ctl_dns, "received rcode = %d", h->rcode);
    switch (h->rcode) {
    default:
      SiteThrottledWarning("UNKNOWN: DNS error %d for [%s]", h->rcode, e->qname);
      retry     = true;
      server_ok = false; // could be server problems
      goto Lerror;
    case NOERROR: // included for completeness.
      Dbg(dbg_ctl_dns, "%s: DNS error %d for [%s]: %s", RCODE_NAME[h->rcode], h->rcode, e->qname, RCODE_DESCRIPTION[h->rcode]);
      break;
    case SERVFAIL: // recoverable error
      SiteThrottledNote("%s: DNS error %d for [%s]: %s", RCODE_NAME[h->rcode], h->rcode, e->qname, RCODE_DESCRIPTION[h->rcode]);
      retry = true;
      break;
    case FORMERR: // unrecoverable errors
    case REFUSED:
    case NOTIMP:
      SiteThrottledNote("%s: DNS error %d for [%s]: %s", RCODE_NAME[h->rcode], h->rcode, e->qname, RCODE_DESCRIPTION[h->rcode]);
      server_ok = false; // could be server problems
      goto Lerror;
    case NXDOMAIN:
    case YXDOMAIN:
    case YXRRSET:
    case NXRRSET:
    case NOTAUTH:
    case NOTZONE:
      SiteThrottledNote("%s: DNS error %d for [%s]: %s", RCODE_NAME[h->rcode], h->rcode, e->qname, RCODE_DESCRIPTION[h->rcode]);
      goto Lerror;
    }
  } else {
    //
    // Initialize local data
    //
    //    struct in_addr host_addr;            unused
    u_char tbuf[MAXDNAME + 1];
    buf->ent.h_name = nullptr;

    int            ancount = ntohs(h->ancount);
    unsigned char *bp      = buf->hostbuf;
    int            buflen  = sizeof(buf->hostbuf);
    u_char        *cp      = (reinterpret_cast<u_char *>(h)) + HFIXEDSZ;
    u_char        *eom     = reinterpret_cast<u_char *>(h) + len;
    int            n;
    ink_assert(buf->srv_hosts.hosts.size() == 0 && buf->srv_hosts.srv_hosts_length == 0);
    buf->srv_hosts.hosts.clear();
    buf->srv_hosts.srv_hosts_length = 0;
    int rname_len                   = -1;

    Dbg(dbg_ctl_dns, "Got %d DNS records for [%s]", ancount, e->qname);
    //
    // Expand name
    //
    if ((n = ink_dn_expand(reinterpret_cast<u_char *>(h), eom, cp, bp, buflen)) < 0) {
      goto Lerror;
    }

    // Should we validate the query name?
    if (dns_validate_qname) {
      int qlen = e->qname_len;
      int rlen = strlen(reinterpret_cast<char *>(bp));

      rname_len = rlen; // Save for later use
      if ((qlen > 0) && ('.' == e->qname[qlen - 1])) {
        --qlen;
      }
      if ((rlen > 0) && ('.' == bp[rlen - 1])) {
        --rlen;
      }
      // TODO: At some point, we might want to care about the case here, and use an algorithm
      // to randomly pick upper case characters in the query, and validate the response with
      // case sensitivity.
      if ((qlen != rlen) || (strncasecmp(e->qname, reinterpret_cast<const char *>(bp), qlen) != 0)) {
        // Bad mojo, forged?
        Warning("received DNS response with query name of '%s', but response query name is '%s'", e->qname, bp);
        goto Lerror;
      } else {
        Dbg(dbg_ctl_dns, "query name validated properly for %s", e->qname);
      }
    }

    cp += n + QFIXEDSZ;
    if (is_addr_query(e->qtype)) {
      if (-1 == rname_len) {
        n = strlen(reinterpret_cast<char *>(bp)) + 1;
      } else {
        n = rname_len + 1;
      }
      buf->ent.h_name  = reinterpret_cast<char *>(bp);
      bp              += n;
      buflen          -= n;
    }
    //
    // Configure HostEnt data structure
    //
    u_char **ap          = buf->host_aliases;
    buf->ent.h_aliases   = reinterpret_cast<char **>(buf->host_aliases);
    u_char **hap         = buf->h_addr_ptrs;
    *hap                 = nullptr;
    buf->ent.h_addr_list = reinterpret_cast<char **>(buf->h_addr_ptrs);

    //
    // INKqa10938: For customer (i.e. USPS) with closed environment, need to
    // build up try_server_names[] with names already successfully resolved.
    // try_server_names[] gets filled up with every success dns response.
    // Once it's full, a new entry get inputted into try_server_names round-
    // robin style every 50 success dns response.

    if (local_num_entries >= DEFAULT_NUM_TRY_SERVER) {
      if ((attempt_num_entries % 50) == 0) {
        try_servers = (try_servers + 1) % countof(try_server_names);
        ink_strlcpy(try_server_names[try_servers], e->qname, MAXDNAME);
        attempt_num_entries = 0;
      }
      ++attempt_num_entries;
    } else {
      // fill up try_server_names for try_primary_named
      try_servers = local_num_entries++;
      ink_strlcpy(try_server_names[try_servers], e->qname, MAXDNAME);
    }

    /* added for SRV support [ebalsa]
       this skips the query section (qdcount)
     */
    unsigned char *here = reinterpret_cast<unsigned char *>(buf->buf) + HFIXEDSZ;
    if (e->qtype == T_SRV) {
      for (int ctr = ntohs(h->qdcount); ctr > 0; ctr--) {
        int strlen  = dn_skipname(here, eom);
        here       += strlen + QFIXEDSZ;
      }
    }
    //
    // Decode each answer
    //
    int answer = false, error = false;

    while (ancount-- > 0 && cp < eom && !error) {
      n = ink_dn_expand(reinterpret_cast<u_char *>(h), eom, cp, bp, buflen);
      if (n < 0) {
        ++error;
        break;
      }
      cp += n;
      short int type;
      NS_GET16(type, cp);
      cp += NS_INT16SZ;       // NS_GET16(cls, cp);
      NS_GET32(temp_ttl, cp); // NOTE: this is not a "long" but 32-bits (from nameser_compat.h)
      if ((temp_ttl < buf->ttl) || (buf->ttl == 0)) {
        buf->ttl = temp_ttl;
      }
      NS_GET16(n, cp);

      //
      // Decode cname
      //
      if ((is_addr_query(e->qtype) || e->qtype == T_SRV) && (type == T_CNAME || type == T_DNAME)) {
        if (ap >= &buf->host_aliases[DNS_MAX_ALIASES - 1]) {
          continue;
        }
        n = ink_dn_expand(reinterpret_cast<u_char *>(h), eom, cp, tbuf, sizeof(tbuf));
        if (n < 0) {
          ++error;
          break;
        }
        cp     += n;
        *ap++   = bp;
        n       = strlen(reinterpret_cast<char *>(bp)) + 1;
        bp     += n;
        buflen -= n;
        n       = strlen(reinterpret_cast<char *>(tbuf)) + 1;
        if (n > buflen) {
          ++error;
          break;
        }
        ink_strlcpy(reinterpret_cast<char *>(bp), reinterpret_cast<char *>(tbuf), buflen);
        bp     += n;
        buflen -= n;
        if (dbg_ctl_dns.on()) {
          switch (type) {
          case T_CNAME:
            DbgPrint(dbg_ctl_dns, "received cname = %s", tbuf);
            break;
          case T_DNAME:
            DbgPrint(dbg_ctl_dns, "received dname = %s", tbuf);
            break;
          }
        }
        continue;
      }
      if (e->qtype != type) {
        ++error;
        break;
      }
      //
      // Decode names
      //
      if (type == T_PTR) {
        n = ink_dn_expand(reinterpret_cast<u_char *>(h), eom, cp, bp, buflen);
        if (n < 0) {
          ++error;
          break;
        }
        cp += n;
        if (!answer) {
          buf->ent.h_name = reinterpret_cast<char *>(bp);
          Dbg(dbg_ctl_dns, "received PTR name = %s", bp);
          n       = strlen(reinterpret_cast<char *>(bp)) + 1;
          bp     += n;
          buflen -= n;
        } else if (ap < &buf->host_aliases[DNS_MAX_ALIASES - 1]) {
          *ap++ = bp;
          Dbg(dbg_ctl_dns, "received PTR alias = %s", bp);
          n       = strlen(reinterpret_cast<char *>(bp)) + 1;
          bp     += n;
          buflen -= n;
        }
      } else if (type == T_SRV) {
        if (buf->srv_hosts.hosts.size() >= hostdb_round_robin_max_count) {
          break;
        }
        cp                            = here; /* hack */
        int strlen                    = dn_skipname(cp, eom);
        cp                           += strlen;
        const unsigned char *srv_off  = cp;
        cp                           += SRV_FIXEDSZ;
        cp                           += dn_skipname(cp, eom);
        here                          = cp; /* hack */

        SRV srv;

        // expand the name
        n = ink_dn_expand(reinterpret_cast<u_char *>(h), eom, srv_off + SRV_SERVER, reinterpret_cast<u_char *>(srv.host), MAXDNAME);
        if (n < 0) {
          ++error;
          break;
        }
        Dbg(dbg_ctl_dns_srv, "Discovered SRV record [from NS lookup] with cost:%d weight:%d port:%d with host:%s",
            ink_get16(srv_off + SRV_COST), ink_get16(srv_off + SRV_WEIGHT), ink_get16(srv_off + SRV_PORT), srv.host);

        srv.port     = ink_get16(srv_off + SRV_PORT);
        srv.priority = ink_get16(srv_off + SRV_COST);
        srv.weight   = ink_get16(srv_off + SRV_WEIGHT);
        srv.host_len = ::strlen(srv.host) + 1;
        srv.key      = makeHostHash(srv.host);

        if (srv.host[0] != '\0') {
          buf->srv_hosts.srv_hosts_length += srv.host_len;
        } else {
          continue;
        }
        buf->srv_hosts.hosts.push_back(srv);
      } else if (is_addr_query(type)) {
        if (answer) {
          if (n != buf->ent.h_length) {
            cp += n;
            continue;
          }
        } else {
          int nn;
          buf->ent.h_length   = n;
          buf->ent.h_addrtype = T_A == type ? AF_INET : AF_INET6;
          buf->ent.h_name     = reinterpret_cast<char *>(bp);
          nn                  = strlen(reinterpret_cast<char *>(bp)) + 1;
          Dbg(dbg_ctl_dns, "received %s name = %s", QtypeName(type), bp);
          bp     += nn;
          buflen -= nn;
        }
        // attempt to use the original buffer (if it is word aligned)
        if (!((reinterpret_cast<uintptr_t>(cp)) % sizeof(unsigned int))) {
          *hap++  = cp;
          cp     += n;
        } else {
          ip_text_buffer ip_string;
          bp = static_cast<unsigned char *>(align_pointer_forward(bp, sizeof(int)));
          if (bp + n >= buf->hostbuf + DNS_HOSTBUF_SIZE) {
            ++error;
            break;
          }
          memcpy((*hap++ = bp), cp, n);
          Dbg(dbg_ctl_dns, "received %s = %s", QtypeName(type),
              inet_ntop(T_AAAA == type ? AF_INET6 : AF_INET, bp, ip_string, sizeof(ip_string)));
          bp += n;
          cp += n;
        }
      } else {
        goto Lerror;
      }
      ++answer;
    }
    if (answer) {
      *ap  = nullptr;
      *hap = nullptr;
      //
      // If the named didn't send us the name, insert the one
      // the user gave us...
      //
      if (!buf->ent.h_name) {
        Dbg(dbg_ctl_dns, "inserting name = %s", e->qname);
        ink_strlcpy(reinterpret_cast<char *>(bp), e->qname, sizeof(buf->hostbuf) - (bp - buf->hostbuf));
        buf->ent.h_name = reinterpret_cast<char *>(bp);
      }
      Dbg(dbg_ctl_dns, "Returning %d DNS records for [%s]", answer, e->qname);
      dns_result(handler, e, buf, retry);
      return server_ok;
    }
  }
Lerror:;
  Metrics::Counter::increment(dns_rsb.lookup_fail);
  buf->good = false;
  dns_result(handler, e, buf, retry, tcp_retry);
  return server_ok;
}

DNSStatsBlock dns_rsb;

void
ink_dns_init(ts::ModuleVersion v)
{
  static int init_called = 0;

  Dbg(dbg_ctl_dns, "ink_dns_init: called with init_called = %d", init_called);

  ink_release_assert(v.check(HOSTDB_MODULE_PUBLIC_VERSION));
  if (init_called) {
    return;
  }

  init_called = 1;

  //
  // Register statistics callbacks
  //
  dns_rsb.fail_time            = Metrics::Counter::createPtr("proxy.process.dns.fail_time");
  dns_rsb.in_flight            = Metrics::Gauge::createPtr("proxy.process.dns.in_flight");
  dns_rsb.lookup_fail          = Metrics::Counter::createPtr("proxy.process.dns.lookup_failures");
  dns_rsb.lookup_success       = Metrics::Counter::createPtr("proxy.process.dns.lookup_successes");
  dns_rsb.max_retries_exceeded = Metrics::Counter::createPtr("proxy.process.dns.max_retries_exceeded");
  dns_rsb.response_time        = Metrics::Counter::createPtr("proxy.process.dns.lookup_time");
  dns_rsb.retries              = Metrics::Counter::createPtr("proxy.process.dns.retries");
  dns_rsb.success_time         = Metrics::Counter::createPtr("proxy.process.dns.success_time");
  dns_rsb.tcp_reset            = Metrics::Counter::createPtr("proxy.process.dns.tcp_reset");
  dns_rsb.tcp_retries          = Metrics::Counter::createPtr("proxy.process.dns.tcp_retries");
  dns_rsb.total_lookups        = Metrics::Counter::createPtr("proxy.process.dns.total_dns_lookups");
}

#if TS_HAS_TESTS
struct DNSRegressionContinuation;
using DNSRegContHandler = int (DNSRegressionContinuation::*)(int, void *);

struct DNSRegressionContinuation : public Continuation {
  int             hosts;
  const char    **hostnames;
  int             type;
  int            *status;
  int             found;
  int             tofind;
  int             i;
  RegressionTest *test;

  int
  mainEvent(int event, HostEnt *he)
  {
    (void)event;
    if (event == DNS_EVENT_LOOKUP) {
      if (he) {
        struct in_addr in;
        ++found;
        in.s_addr = *reinterpret_cast<unsigned int *>(he->ent.h_addr_list[0]);
        rprintf(test, "host %s [%s] = %s\n", hostnames[i - 1], he->ent.h_name, inet_ntoa(in));
      } else {
        rprintf(test, "host %s not found\n", hostnames[i - 1]);
      }
    }
    if (i < hosts) {
      dnsProcessor.gethostbyname(this, hostnames[i], DNSProcessor::Options().setHostResStyle(HOST_RES_IPV4_ONLY));
      ++i;
      return EVENT_CONT;
    } else {
      if (found == tofind) {
        *status = REGRESSION_TEST_PASSED;
      } else {
        *status = REGRESSION_TEST_FAILED;
      }
      return EVENT_DONE;
    }
  }

  DNSRegressionContinuation(int ahosts, int atofind, const char **ahostnames, RegressionTest *t, int atype, int *astatus)
    : Continuation(new_ProxyMutex()),
      hosts(ahosts),
      hostnames(ahostnames),
      type(atype),
      status(astatus),
      found(0),
      tofind(atofind),
      i(0),
      test(t)
  {
    SET_HANDLER(&DNSRegressionContinuation::mainEvent);
  }
};

static const char *dns_test_hosts[] = {"www.apple.com", "www.ibm.com", "www.microsoft.com", "www.coke.com"};

REGRESSION_TEST(DNS)(RegressionTest *t, int atype, int *pstatus)
{
  eventProcessor.schedule_in(new DNSRegressionContinuation(4, 4, dns_test_hosts, t, atype, pstatus), HRTIME_SECONDS(1));
}

#endif
