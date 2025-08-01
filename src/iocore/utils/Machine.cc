/** @file

  Support class for describing the local machine.

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

#include "iocore/utils/Machine.h"
#include "tscore/Diags.h"
#include "tscore/SnowflakeID.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_inet.h"

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

// Singleton
Machine *Machine::_instance = nullptr;

/** Compute the FNV-1a hash for the given string.
 * @param[in] str The string to hash.
 * @return The 64-bit FNV-1a hash of the string.
 */
static constexpr uint64_t
compute_fnv1a(std::string_view str)
{
  // Parameters set under guidance from:
  // http://isthe.com/chongo/tech/comp/fnv/#google_vignette.
  constexpr uint64_t FNV_PRIME  = 1099511628211u;
  constexpr uint64_t FNV_OFFSET = 14695981039346656037u;
  uint64_t           hash       = FNV_OFFSET;

  // Process each character in lowercase
  for (char c : str) {
    hash ^= static_cast<unsigned int>(c);
    hash *= FNV_PRIME;
  }
  return hash;
}

// Verify our FNV-1a hash implementation.
static_assert(compute_fnv1a("") == 14695981039346656037u, "64 bit FNV-1 hash for '' should be 14695981039346656037");
static_assert(compute_fnv1a("e1.myedge.colo.acme.com") == 9637442596227468504u,
              "64 bit FNV-1 hash for 'e1.myedge.colo.acme.com' should be 9637442596227468504");

Machine *
Machine::instance()
{
  ink_assert(_instance || !"Machine instance accessed before initialization");
  return Machine::_instance;
}

Machine *
Machine::init(char const *name, sockaddr const *ip)
{
  ink_assert(!_instance || !"Machine instance initialized twice.");
  Machine::_instance = new Machine(name, ip);
  return Machine::_instance;
}

Machine::Machine(char const *the_hostname, sockaddr const *addr)
{
  // Initialize the machine IP infomation
  bzero(&ip, sizeof(ip));
  bzero(&ip4, sizeof(ip4));
  bzero(&ip6, sizeof(ip6));

  int            status; // return for system calls.
  ip_text_buffer ip_strbuf;
  char           localhost[1024];

  process_uuid.initialize(TS_UUID_V4);
  ink_release_assert(nullptr != process_uuid.getString()); // The Process UUID must be available on startup

  if (!ats_is_ip(addr)) {
    if (!the_hostname) {
      // @c gethostname has a broken interface - there's no way to determine the actual size of
      // the host name explicitly - the error case doesn't return the size. The standards based
      // limit is 63, or 255 for a FQDN.
      auto result = gethostname(localhost, sizeof(localhost));
      ink_release_assert(result == 0);
      host_name.assign(localhost, strlen(localhost));
      insert_id(localhost);
    }

#if HAVE_IFADDRS_H
    ifaddrs *ifa_addrs = nullptr;
    status             = getifaddrs(&ifa_addrs);
#else
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    // This number is hard to determine, but needs to be much larger than
    // you would expect. On a normal system with just two interfaces and
    // one address / interface the return count is 120. Stack space is
    // cheap so it's best to go big.
    static constexpr int N_REQ = 1024;
    ifconf               conf;
    ifreq                req[N_REQ];
    if (0 <= s) {
      conf.ifc_len = sizeof(req);
      conf.ifc_req = req;
      status       = ioctl(s, SIOCGIFCONF, &conf);
    } else {
      status = -1;
    }
#endif

    if (0 != status) {
      Warning("Unable to determine local host '%.*s' address information - %s", int(host_name.size()), host_name.data(),
              strerror(errno));
    } else {
      // Loop through the interface addresses and prefer by type.
      enum {
        NA, // Not an (IP) Address.
        LO, // Loopback.
        LL, // Link Local
        PR, // Private.
        MC, // Multicast.
        GL  // Global.
      } spot_type = NA,
        ip4_type = NA, ip6_type = NA;
      sockaddr const *ifip;
      unsigned int    ifflags;
      for (
#if HAVE_IFADDRS_H
        ifaddrs *spot = ifa_addrs; spot; spot = spot->ifa_next
#else
        ifreq *spot = req, *req_limit = req + (conf.ifc_len / sizeof(*req)); spot < req_limit; ++spot
#endif
      ) {
#if HAVE_IFADDRS_H
        ifip    = spot->ifa_addr;
        ifflags = spot->ifa_flags;
#else
        ifip = &spot->ifr_addr;

        // get the interface's flags
        struct ifreq ifr;
        ink_strlcpy(ifr.ifr_name, spot->ifr_name, IFNAMSIZ);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
          ifflags = ifr.ifr_flags;
        } else {
          ifflags = 0; // flags not available, default to just looking at IP
        }
#endif
        if (!ats_is_ip(ifip)) {
          spot_type = NA;
        } else if (ats_is_ip_loopback(ifip) || (IFF_LOOPBACK & ifflags)) {
          spot_type = LO;
        } else if (ats_is_ip_linklocal(ifip)) {
          spot_type = LL;
        } else if (ats_is_ip_private(ifip)) {
          spot_type = PR;
        } else if (ats_is_ip_multicast(ifip)) {
          spot_type = MC;
        } else {
          spot_type = GL;
        }
        if (spot_type == NA) {
          continue; // Next!
        }

        if (ats_is_ip4(ifip) || ats_is_ip6(ifip)) {
          ink_zero(ip_strbuf);
          ink_zero(localhost);
          ats_ip_ntop(ifip, ip_strbuf, sizeof(ip_strbuf));
          insert_id(ip_strbuf);
          if (spot_type != LL && getnameinfo(ifip, ats_ip_size(ifip), localhost, sizeof(localhost) - 1, nullptr, 0, 0) == 0) {
            insert_id(localhost);
          }
          insert_id(IpAddr(ifip));
          if (ats_is_ip4(ifip)) {
            if (spot_type > ip4_type) {
              ats_ip_copy(&ip4, ifip);
              ip4_type = spot_type;
            }
          } else if (ats_is_ip6(ifip)) {
            if (spot_type > ip6_type) {
              ats_ip_copy(&ip6, ifip);
              ip6_type = spot_type;
            }
          }
        }
      }

#if HAVE_IFADDRS_H
      freeifaddrs(ifa_addrs);
#endif

      // What about the general address? Prefer IPv4?
      if (ip4_type >= ip6_type) {
        ats_ip_copy(&ip.sa, &ip4.sa);
      } else {
        ats_ip_copy(&ip.sa, &ip6.sa);
      }
    }
#if !HAVE_IFADDRS_H
    close(s);
#endif
  } else { // address provided.
    ats_ip_copy(&ip, addr);
    if (ats_is_ip4(addr)) {
      ats_ip_copy(&ip4, addr);
    } else if (ats_is_ip6(addr)) {
      ats_ip_copy(&ip6, addr);
    }

    status = getnameinfo(addr, ats_ip_size(addr), localhost, sizeof(localhost) - 1, nullptr, 0, 0); // no flags

    if (0 != status) {
      ip_text_buffer ipbuff;
      Warning("Failed to find hostname for address '%s' - %s", ats_ip_ntop(addr, ipbuff, sizeof(ipbuff)), gai_strerror(status));
    } else {
      host_name.assign(localhost);
      insert_id(localhost);
    }
  }

  host_fnv1a = compute_fnv1a(host_name);
  SnowflakeIDUtils::set_machine_id(host_fnv1a);
  process_snowflake_id = std::make_unique<SnowflakeIdNoSequence>();

  char hex_buff[TS_IP6_SIZE * 2 + 1];
  ats_ip_to_hex(&ip.sa, hex_buff, sizeof(hex_buff));
  ip_hex_string.assign(hex_buff);
}

Machine::~Machine() {}

bool
Machine::is_self(std::string const &name)
{
  return machine_id_strings.find(name) != machine_id_strings.end();
}

bool
Machine::is_self(std::string_view name)
{
  return this->is_self(std::string(name));
}

bool
Machine::is_self(char const *name)
{
  return this->is_self(std::string(name));
}

bool
Machine::is_self(IpAddr const &ipaddr)
{
  return machine_id_ipaddrs.end() != machine_id_ipaddrs.find(ipaddr);
}

bool
Machine::is_self(struct sockaddr const *addr)
{
  return machine_id_ipaddrs.find(IpAddr(addr)) != machine_id_ipaddrs.end();
}

void
Machine::insert_id(char const *id)
{
  machine_id_strings.emplace(id);
}

void
Machine::insert_id(IpAddr const &ipaddr)
{
  ip_text_buffer buff;

  ipaddr.toString(buff, sizeof(buff));
  machine_id_strings.emplace(buff);
  machine_id_ipaddrs.emplace(ipaddr);
}
