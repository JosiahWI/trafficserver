/** @file

  Unit tests for ServerSessionPool::acquireSession.

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

#include "proxy/http/HttpSessionManager.h"
#include "proxy/http/HttpConfig.h"
#include "proxy/http/HttpSM.h"
#include "iocore/net/NetVConnection.h"
#include "iocore/net/TLSSNISupport.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <memory>
#include <vector>

namespace
{

/// A NetVConnection that does nothing but carry NetVCOptions.
class TestNetVConnection : public NetVConnection
{
public:
  VIO *
  do_io_read(Continuation *, int64_t, MIOBuffer *) override
  {
    return nullptr;
  }
  VIO *
  do_io_write(Continuation *, int64_t, IOBufferReader *, bool) override
  {
    return nullptr;
  }
  void
  do_io_close(int = -1) override
  {
  }
  void
  do_io_shutdown(ShutdownHowTo_t) override
  {
  }
  void
  reenable(VIO *) override
  {
  }
  void
  reenable_re(VIO *) override
  {
  }
  void
  set_active_timeout(ink_hrtime) override
  {
  }
  void
  set_inactivity_timeout(ink_hrtime) override
  {
  }
  void
  set_default_inactivity_timeout(ink_hrtime) override
  {
  }
  bool
  is_default_inactivity_timeout() override
  {
    return false;
  }
  void
  cancel_active_timeout() override
  {
  }
  void
  cancel_inactivity_timeout() override
  {
  }
  void
  add_to_keep_alive_queue() override
  {
  }
  void
  remove_from_keep_alive_queue() override
  {
  }
  bool
  add_to_active_queue() override
  {
    return true;
  }
  ink_hrtime
  get_active_timeout() override
  {
    return 0;
  }
  ink_hrtime
  get_inactivity_timeout() override
  {
    return 0;
  }
  void
  apply_options() override
  {
  }
  SOCKET
  get_socket() override { return NO_FD; }
  int
  set_tcp_congestion_control(tcp_congestion_control_side) override
  {
    return 0;
  }
  void
  set_local_addr() override
  {
  }
  void
  set_remote_addr() override
  {
  }
  void
  set_remote_addr(sockaddr const *) override
  {
  }
  void
  set_mptcp_state() override
  {
  }
};

/** A NetVConnection that advertises TLSSNISupport, as an SSL connection does.
 *
 * A null @a sni leaves the connection without a server name, which is not the
 * same thing as an empty one as far as TLSSNISupport is concerned.
 */
class TestTLSNetVConnection : public TestNetVConnection, public TLSSNISupport
{
public:
  TestTLSNetVConnection(char const *sni)
  {
    this->_set_service(static_cast<TLSSNISupport *>(this));
    if (sni != nullptr) {
      this->set_sni_server_name(sni);
    }
  }

protected:
  in_port_t
  _get_local_port() override
  {
    return 0;
  }
};

/** A minimal PoolableSession that can be pooled and matched.
 *
 * Only the remote address and the hostname hash participate in the match paths
 * that do not involve TLS, so those cases need no NetVConnection at all.
 */
class TestPoolableSession : public PoolableSession
{
public:
  TestPoolableSession(char const *addr_str, char const *hostname)
  {
    ink_release_assert(ats_ip_pton(addr_str, &_remote_addr) == 0);
    this->attach_hostname(hostname);
  }

  void
  new_connection(NetVConnection *, MIOBuffer *, IOBufferReader *) override
  {
  }
  void
  start() override
  {
  }
  void
  release(ProxyTransaction *) override
  {
  }
  void
  destroy() override
  {
  }
  void
  free() override
  {
  }
  void
  increment_current_active_connections_stat() override
  {
  }
  void
  decrement_current_active_connections_stat() override
  {
  }

  int
  get_transact_count() const override
  {
    return 0;
  }

  const char *
  get_protocol_string() const override
  {
    return "test";
  }

  IOBufferReader *
  get_remote_reader() override
  {
    return nullptr;
  }

  void
  do_io_close(int /* lerrno ATS_UNUSED */ = -1) override
  {
    ++close_count;
  }

  sockaddr const *
  get_remote_addr() const override
  {
    return &_remote_addr.sa;
  }

  bool
  is_multiplexing() const override
  {
    return _multiplexing;
  }

  void
  set_multiplexing(bool multiplexing)
  {
    _multiplexing = multiplexing;
  }

  int close_count = 0;

private:
  IpEndpoint _remote_addr;
  bool       _multiplexing = false;
};

/// Owns the test sessions and hands raw pointers to the pool under test.
class SessionFactory
{
public:
  TestPoolableSession *
  make(char const *addr_str, char const *hostname, NetVConnection *netvc = nullptr, bool multiplexing = false)
  {
    auto *session = _sessions.emplace_back(std::make_unique<TestPoolableSession>(addr_str, hostname)).get();

    session->set_netvc(netvc);
    session->set_multiplexing(multiplexing);
    return session;
  }

private:
  std::vector<std::unique_ptr<TestPoolableSession>> _sessions;
};

/// The pool bookkeeping updates this gauge, which is normally initialized via HttpConfig.
/// Create it here (when needed) and reset it between Catch2 runs so tests don't leak state.
void
init_metrics()
{
  if (http_rsb.pooled_server_connections == nullptr) {
    http_rsb.pooled_server_connections = Metrics::Gauge::createPtr("proxy.process.http.pooled_server_connections");
  }
  Metrics::Gauge::store(http_rsb.pooled_server_connections, 0);
}

CryptoHash
hash_of(char const *hostname)
{
  CryptoHash hash;

  CryptoContext().hash_immediate(hash, static_cast<unsigned char const *>(static_cast<void const *>(hostname)),
                                 std::strlen(hostname));
  return hash;
}

/// A sockaddr that can be passed inline to acquireSession.
struct Addr {
  Addr(char const *addr_str) { ink_release_assert(ats_ip_pton(addr_str, &_addr) == 0); }

  operator sockaddr const *() const { return &_addr.sa; }

private:
  IpEndpoint _addr;
};

constexpr auto SHARE_IP       = TS_SERVER_SESSION_SHARING_MATCH_MASK_IP;
constexpr auto SHARE_HOSTONLY = TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTONLY;
constexpr auto SHARE_BOTH     = static_cast<TSServerSessionSharingMatchMask>(TS_SERVER_SESSION_SHARING_MATCH_MASK_IP |
                                                                             TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTONLY);

TSServerSessionSharingMatchMask
match_with(TSServerSessionSharingMatchMask extra)
{
  return static_cast<TSServerSessionSharingMatchMask>(TS_SERVER_SESSION_SHARING_MATCH_MASK_IP | extra);
}

/** An HttpSM carrying just enough state for the acquireSession validators.
 *
 * The validators read the transaction scheme, the server request host, and the
 * outbound SNI and certificate, all of which come from the overridable
 * transaction config and the server request header.
 */
class TestHttpSM
{
public:
  TestHttpSM(int scheme, char const *host)
  {
    _sm.t_state.http_config_param = HttpConfig::acquire();
    _sm.t_state.setup_per_txn_configs();
    _sm.t_state.scheme = scheme;

    _sm.t_state.hdr_info.server_request.create(HTTPType::REQUEST);
    if (host != nullptr) {
      std::string const raw_request{std::string{"GET / HTTP/1.1\r\nHost: "} + host + "\r\n\r\n"};
      HTTPParser        parser;

      http_parser_init(&parser);

      auto const *start = raw_request.data();
      auto const *end   = start + raw_request.size();
      ParseResult err;

      while ((err = _sm.t_state.hdr_info.server_request.parse_req(&parser, &start, end, true)) == ParseResult::CONT) {
        ;
      }
      http_parser_clear(&parser);
      REQUIRE(err == ParseResult::DONE);
      REQUIRE(_sm.t_state.hdr_info.server_request.host_get() == std::string_view{host});
    }
  }

  ~TestHttpSM() { _sm.t_state.hdr_info.server_request.destroy(); }

  TestHttpSM(TestHttpSM const &)            = delete;
  TestHttpSM &operator=(TestHttpSM const &) = delete;

  /// The outbound certificate the SM would use for a new connection.
  /// The pointer is not owned by the transaction config, so a literal is fine.
  void
  set_outbound_cert(char const *cert_name)
  {
    _sm.t_state.my_txn_conf().ssl_client_cert_filename = const_cast<char *>(cert_name);
  }

  HttpSM *
  sm()
  {
    return &_sm;
  }

private:
  HttpSM _sm;
};

/// HttpConfig::startup registers the HTTP metrics and publishes the config the
/// transaction config is copied from. HttpSM's destructor requires the latter.
void
init_http_config()
{
  static bool initialized = false;

  if (!initialized) {
    initialized = true;
    HttpConfig::startup();
  }
}

} // namespace

TEST_CASE("ServerSessionPool::acquireSession", "[session_pool]")
{
  init_metrics();

  // Declared before the pool so the sessions outlive it.
  SessionFactory    factory;
  ServerSessionPool pool;

  PoolableSession *acquired = nullptr;

  SECTION("empty pool finds nothing")
  {
    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_IP, nullptr, acquired) ==
          HSMresult_t::NOT_FOUND);
    CHECK(acquired == nullptr);
  }

  SECTION("a match mask with neither IP nor host disables sharing")
  {
    pool.addSession(factory.make("10.0.0.1:80", "one.example.com"));

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), TS_SERVER_SESSION_SHARING_MATCH_MASK_NONE, nullptr,
                              acquired) == HSMresult_t::NOT_FOUND);
    CHECK(acquired == nullptr);
    CHECK(pool.count() == 1);
  }

  SECTION("match on IP")
  {
    auto *session = factory.make("10.0.0.1:80", "one.example.com");

    pool.addSession(session);

    SECTION("address and port match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("other.example.com"), SHARE_IP, nullptr, acquired) ==
            HSMresult_t::DONE);
      CHECK(acquired == session);

      // A non-multiplexing session is handed off, not shared: it leaves both pools.
      CHECK(pool.count() == 0);
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
    }

    SECTION("a different address does not match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.2:80"}, hash_of("one.example.com"), SHARE_IP, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("a different port does not match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:81"}, hash_of("one.example.com"), SHARE_IP, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("match on IP returns the most recently pooled session")
  {
    auto *first  = factory.make("10.0.0.1:80", "one.example.com");
    auto *second = factory.make("10.0.0.1:80", "two.example.com");

    pool.addSession(first);
    pool.addSession(second);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_IP, nullptr, acquired) == HSMresult_t::DONE);
    CHECK(acquired == second);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_IP, nullptr, acquired) == HSMresult_t::DONE);
    CHECK(acquired == first);
  }

  SECTION("match on host only ignores the address but not the port")
  {
    auto *session = factory.make("10.0.0.1:80", "one.example.com");

    pool.addSession(session);

    SECTION("a different address with the same host and port matches")
    {
      CHECK(pool.acquireSession(Addr{"192.168.1.1:80"}, hash_of("one.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
            HSMresult_t::DONE);
      CHECK(acquired == session);
      CHECK(pool.count() == 0);
    }

    SECTION("a different host does not match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("other.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("a different port does not match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:81"}, hash_of("one.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("match on host only returns the most recently pooled session")
  {
    auto *first  = factory.make("10.0.0.1:80", "one.example.com");
    auto *second = factory.make("10.0.0.2:80", "one.example.com");

    pool.addSession(first);
    pool.addSession(second);

    CHECK(pool.acquireSession(Addr{"10.0.0.3:80"}, hash_of("one.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
          HSMresult_t::DONE);
    CHECK(acquired == second);

    CHECK(pool.acquireSession(Addr{"10.0.0.3:80"}, hash_of("one.example.com"), SHARE_HOSTONLY, nullptr, acquired) ==
          HSMresult_t::DONE);
    CHECK(acquired == first);
  }

  SECTION("match on both IP and host requires both to match")
  {
    auto *session = factory.make("10.0.0.1:80", "one.example.com");

    pool.addSession(session);

    SECTION("both match")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_BOTH, nullptr, acquired) ==
            HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("the address matches but the host does not")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("other.example.com"), SHARE_BOTH, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("the host matches but the address does not")
    {
      CHECK(pool.acquireSession(Addr{"192.168.1.1:80"}, hash_of("one.example.com"), SHARE_BOTH, nullptr, acquired) ==
            HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("only sessions in the requested address bucket are considered")
  {
    auto *wrong_addr = factory.make("10.0.0.2:80", "one.example.com");
    auto *right_addr = factory.make("10.0.0.1:80", "one.example.com");

    pool.addSession(wrong_addr);
    pool.addSession(right_addr);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, hash_of("one.example.com"), SHARE_BOTH, nullptr, acquired) == HSMresult_t::DONE);
    CHECK(acquired == right_addr);
    CHECK(pool.count() == 1);
  }

  pool.purge();
  Metrics::Gauge::store(http_rsb.pooled_server_connections, 0);
}

TEST_CASE("ServerSessionPool::acquireSession consults the HttpSM", "[session_pool]")
{
  url_init();
  mime_init();
  http_init();
  init_http_config();
  init_metrics();

  SessionFactory    factory;
  ServerSessionPool pool;

  PoolableSession *acquired = nullptr;
  auto const       request_hash{hash_of("one.example.com")};

  SECTION("a plain HTTP transaction skips the TLS validators")
  {
    TestHttpSM         sm{URL_WKSIDX_HTTP, "one.example.com"};
    TestNetVConnection netvc;
    auto              *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

    pool.addSession(session);

    auto const match_style = static_cast<TSServerSessionSharingMatchMask>(
      TS_SERVER_SESSION_SHARING_MATCH_MASK_IP | TS_SERVER_SESSION_SHARING_MATCH_MASK_SNI |
      TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTSNISYNC | TS_SERVER_SESSION_SHARING_MATCH_MASK_CERT);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
    CHECK(acquired == session);
  }

  SECTION("an HTTPS transaction rejects a connection without TLS SNI support")
  {
    TestHttpSM         sm{URL_WKSIDX_HTTPS, "one.example.com"};
    TestNetVConnection netvc;

    pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

    SECTION("when matching the SNI name")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_with(TS_SERVER_SESSION_SHARING_MATCH_MASK_SNI), sm.sm(),
                                acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("when keeping the SNI name in sync with the request host")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_with(TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTSNISYNC),
                                sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("matching the SNI name of an HTTPS connection")
  {
    auto const match_style = match_with(TS_SERVER_SESSION_SHARING_MATCH_MASK_SNI);

    SECTION("the proposed SNI name, taken from the request host, matches")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{"one.example.com"};
      auto                 *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

      pool.addSession(session);

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("a different SNI name does not match")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{"two.example.com"};

      pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("the SNI name comparison is case sensitive")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{"ONE.EXAMPLE.COM"};

      pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("a connection that negotiated no SNI name is not reused")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{nullptr};

      pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("a connection that negotiated no SNI name is not reused even when none is proposed")
    {
      // TLSSNISupport reports a missing server name as the empty string rather
      // than as a null pointer, so the "neither side has an SNI name" case that
      // validate_sni allows for is not reachable through a connection.
      TestHttpSM            sm{URL_WKSIDX_HTTPS, nullptr};
      TestTLSNetVConnection netvc{nullptr};

      pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("keeping the SNI name in sync with the request host")
  {
    auto const match_style = match_with(TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTSNISYNC);

    SECTION("the request host matches the SNI name")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{"one.example.com"};
      auto                 *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

      pool.addSession(session);

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("unlike the SNI name comparison, the host comparison ignores case")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "one.example.com"};
      TestTLSNetVConnection netvc{"ONE.EXAMPLE.COM"};
      auto                 *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

      pool.addSession(session);

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("a different request host does not match")
    {
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "two.example.com"};
      TestTLSNetVConnection netvc{"one.example.com"};

      pool.addSession(factory.make("10.0.0.1:80", "one.example.com", &netvc));

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("a connection that negotiated no SNI name imposes no constraint")
    {
      // validate_host_sni only compares when the connection has a server name.
      TestHttpSM            sm{URL_WKSIDX_HTTPS, "two.example.com"};
      TestTLSNetVConnection netvc{nullptr};
      auto                 *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

      pool.addSession(session);

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }
  }

  SECTION("matching the outbound certificate of an HTTPS connection")
  {
    // The certificate check reads NetVCOptions directly, so it needs no TLS service.
    auto const         match_style = match_with(TS_SERVER_SESSION_SHARING_MATCH_MASK_CERT);
    TestHttpSM         sm{URL_WKSIDX_HTTPS, "one.example.com"};
    TestNetVConnection netvc;
    auto              *session = factory.make("10.0.0.1:80", "one.example.com", &netvc);

    pool.addSession(session);

    SECTION("neither side uses a client certificate")
    {
      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("both sides use the same client certificate")
    {
      netvc.options.set_ssl_client_cert_name("client.pem");
      sm.set_outbound_cert("client.pem");

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::DONE);
      CHECK(acquired == session);
    }

    SECTION("the client certificates differ")
    {
      netvc.options.set_ssl_client_cert_name("client.pem");
      sm.set_outbound_cert("other.pem");

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("only the pooled connection uses a client certificate")
    {
      netvc.options.set_ssl_client_cert_name("client.pem");

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }

    SECTION("only the new request uses a client certificate")
    {
      sm.set_outbound_cert("client.pem");

      CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, match_style, sm.sm(), acquired) == HSMresult_t::NOT_FOUND);
      CHECK(acquired == nullptr);
      CHECK(pool.count() == 1);
    }
  }

  SECTION("a multiplexing session is shared rather than handed off")
  {
    TestHttpSM         sm{URL_WKSIDX_HTTPS, "one.example.com"};
    TestNetVConnection netvc;
    auto              *session = factory.make("10.0.0.1:80", "one.example.com", &netvc, true);

    pool.addSession(session);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, SHARE_IP, sm.sm(), acquired) == HSMresult_t::DONE);
    CHECK(acquired == session);

    // It stays in the pool for the next transaction, and is not closed.
    CHECK(pool.count() == 1);
    CHECK(session->close_count == 0);

    CHECK(pool.acquireSession(Addr{"10.0.0.1:80"}, request_hash, SHARE_IP, sm.sm(), acquired) == HSMresult_t::DONE);
    CHECK(acquired == session);
  }

  pool.purge();
  Metrics::Gauge::store(http_rsb.pooled_server_connections, 0);
}
