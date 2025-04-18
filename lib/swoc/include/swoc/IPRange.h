// SPDX-License-Identifier: Apache-2.0
// Copyright Network Geographics 2014
/** @file
   IP address range utilities.
 */

#pragma once

#include <string_view>
#include <variant> // for std::monostate
#include <tuple>

#include <swoc/DiscreteRange.h>
#include <swoc/IPAddr.h>

namespace swoc { inline namespace SWOC_VERSION_NS {

using std::string_view;

class IP4Net;
class IP6Net;
class IPNet;

/** An inclusive range of IPv4 addresses.
 */
class IP4Range : public DiscreteRange<IP4Addr> {
  using self_type   = IP4Range;
  using super_type  = DiscreteRange<IP4Addr>;
  using metric_type = IP4Addr;

public:
  /// Default constructor, invalid range.
  constexpr IP4Range() = default;

  /// Construct from an network expressed as @a addr and @a mask.
  IP4Range(IP4Addr const &addr, IPMask const &mask);

  /// Construct from super type.
  /// @internal Why do I have to do this, even though the super type constructors are inherited?
  IP4Range(super_type const &r) : super_type(r) {}

  /** Construct range from @a text.
   *
   * @param text Range text.
   * @see IP4Range::load
   *
   * This results in an empty range if @a text is not a valid string. If this should be checked,
   * use @c load.
   *
   * @see load
   */
  IP4Range(string_view const &text);

  using super_type::super_type; ///< Import super class constructors.

  /** Set @a this range.
   *
   * @param addr Minimum address.
   * @param mask CIDR mask to compute maximum adddress from @a addr.
   * @return @a this
   */
  self_type &assign(IP4Addr const &addr, IPMask const &mask);

  using super_type::assign; ///< Import assign methods.

  /** Assign to this range from text.
   *
   * @param text Range text.
   *
   * The text must be in one of three formats.
   * - A dashed range, "addr1-addr2"
   * - A singleton, "addr". This is treated as if it were "addr-addr", a range of size 1.
   * - CIDR notation, "addr/cidr" where "cidr" is a number from 0 to the number of bits in the address.
   */
  bool load(string_view text);

  /** Compute the mask for @a this as a network.
   *
   * @return If @a this is a network, the mask for that network. Otherwise an invalid mask.
   *
   * @see IPMask::is_valid
   */
  IPMask network_mask() const;

  /// @return The range family.
  sa_family_t
  family() const {
    return AF_INET;
  }

  class NetSource;

  /** Generate a list of networks covering @a this range.
   *
   * @return A network generator.
   *
   * The returned object can be used as an iterator, or as a container to iterating over
   * the unique minimal set of networks that cover @a this range.
   *
   * @code
   * void (IP4Range const& range) {
   *   for ( auto const& net : range ) {
   *     net.addr(); // network address.
   *     net.mask(); // network mask;
   *   }
   * }
   * @endcode
   */
  NetSource networks() const;
};

/** Network generator class.
 * This generates networks from a range and acts as both a forward iterator and a container.
 *
 * @see IP4Range::networks
 */
class IP4Range::NetSource {
  using self_type = NetSource; ///< Self reference type.
public:
  using range_type = IP4Range; ///< Import base range type.

  /// Construct from @a range.
  explicit NetSource(range_type const &range);

  /// Copy constructor.
  NetSource(self_type const &that) = default;

  /// This class acts as a container and an iterator.
  using iterator = self_type;
  /// All iteration is constant so no distinction between iterators.
  using const_iterator = iterator;

  iterator begin() const; ///< First network.
  static iterator end();  ///< Past last network.

  /// Return @c true if there are valid networks, @c false if not.
  bool empty() const;

  /// @return The current network.
  IP4Net operator*() const;

  /// Access @a this as if it were an @c IP4Net.
  self_type *operator->();

  /// Iterator support.
  /// @return The current network address.
  IP4Addr const &addr() const;

  /// Iterator support.
  /// @return The current network mask.
  IPMask mask() const;

  /// Move to next network.
  self_type &operator++();

  /// Move to next network.
  self_type operator++(int);

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality.
  bool operator!=(self_type const &that) const;

protected:
  IP4Range _range; ///< Remaining range.
  /// Mask for current network.
  IP4Addr _mask{~static_cast<in_addr_t>(0)};
  IPMask::raw_type _cidr = IP4Addr::WIDTH; ///< Current CIDR value.

  void search_wider();

  void search_narrower();

  bool is_valid(IP4Addr mask) const;
};

/// Inclusive range of IPv6 addresses.
class IP6Range : public DiscreteRange<IP6Addr> {
  using self_type  = IP6Range;
  using super_type = DiscreteRange<IP6Addr>;

public:
  /// Construct from super type.
  /// @internal Why do I have to do this, even though the super type constructors are inherited?
  IP6Range(super_type const &r) : super_type(r) {}

  /** Construct range from @a text.
   *
   * @param text Range text.
   * @see IP6Range::load
   *
   * This results in an empty range if @a text is not a valid string. If this should be checked,
   * use @c load.
   */
  IP6Range(string_view const &text);

  using super_type::super_type; ///< Import super class constructors.

  /** Set @a this range.
   *
   * @param addr Minimum address.
   * @param mask CIDR mask to compute maximum adddress from @a addr.
   * @return @a this
   */
  self_type &assign(IP6Addr const &addr, IPMask const &mask);

  using super_type::assign; ///< Import assign methods.

  /** Assign to this range from text.
   *
   * @param text Range text.
   *
   * The text must be in one of three formats.
   * - A dashed range, "addr1-addr2"
   * - A singleton, "addr". This is treated as if it were "addr-addr", a range of size 1.
   * - CIDR notation, "addr/cidr" where "cidr" is a number from 0 to the number of bits in the address.
   */
  bool load(string_view text);

  /** Compute the mask for @a this as a network.
   *
   * @return If @a this is a network, the mask for that network. Otherwise an invalid mask.
   *
   * @see IPMask::is_valid
   */
  IPMask network_mask() const;

  /// @return The range family.
  sa_family_t
  family() const {
    return AF_INET6;
  }

  class NetSource;

  /** Generate a list of networks covering @a this range.
   *
   * @return A network generator.
   *
   * The returned object can be used as an iterator, or as a container to iterating over
   * the unique minimal set of networks that cover @a this range.
   *
   * @code
   * void (IP6Range const& range) {
   *   for ( auto const& net : range ) {
   *     net.addr(); // network address.
   *     net.mask(); // network mask;
   *   }
   * }
   * @endcode
   */
  NetSource networks() const;
};

/** Network generator class.
 * This generates networks from a range and acts as both a forward iterator and a container.
 *
 * @see IP6Range::networks
 */
class IP6Range::NetSource {
  using self_type = NetSource; ///< Self reference type.
public:
  using range_type = IP6Range; ///< Import base range type.

  /// Construct from @a range.
  explicit NetSource(range_type const &range);

  /// Copy constructor.
  NetSource(self_type const &that) = default;

  /// This class acts as a container and an iterator.
  using iterator = self_type;
  /// All iteration is constant so no distinction between iterators.
  using const_iterator = iterator;

  iterator begin() const; ///< First network.
  iterator end() const;   ///< Past last network.

  /// @return @c true if there are valid networks, @c false if not.
  bool empty() const;

  /// @return The current network.
  IP6Net operator*() const;

  /// Access @a this as if it were an @c IP6Net.
  self_type *operator->();

  /// @return The current network address.
  IP6Addr const &addr() const;

  /// Iterator support.
  /// @return The current network mask.
  IPMask mask() const;

  /// Move to next network.
  self_type &operator++();

  /// Move to next network.
  self_type operator++(int);

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality.
  bool operator!=(self_type const &that) const;

protected:
  IP6Range _range;              ///< Remaining range.
  IPMask _mask{IP6Addr::WIDTH}; ///< Current CIDR value.

  void search_wider();

  void search_narrower();

  bool is_valid(IPMask const &mask);
};

class IPRangeView; // Forward declare.

/** Range of IP addresses.
 * Although this can hold IPv4 or IPv6, any specific instance is one or the other, this can never contain
 * a range of different address families.
 */
class IPRange {
  using self_type = IPRange;

public:
  /// Default constructor - construct invalid range.
  IPRange() = default;

  /** Construct an inclusive range.
   *
   * @param min Minimum range value.
   * @param max Maximum range value.
   */
  IPRange(IPAddr const &min, IPAddr const &max);

  /** Construct an inclusive range.
   *
   * @param min Minimum range value.
   * @param max Maximum range value.
   */
  IPRange(IP4Addr const &min, IP4Addr const &max);

  /** Construct an inclusive range.
   *
   * @param min Minimum range value.
   * @param max Maximum range value.
   */
  IPRange(IP6Addr const &min, IP6Addr const &max);

  /** Construct a singleton range.
   *
   * @param addr Address of range.
   */
  IPRange(IPAddr const &addr) : IPRange(addr, addr) {}

  /** Construct a singleton range.
   *
   * @param addr Address of range.
   */
  IPRange(IP4Addr addr) : IPRange(addr, addr) {}

  /** Construct a singleton range.
   *
   * @param addr Address of range.
   */
  IPRange(IP6Addr const &addr) : IPRange(addr, addr) {}

  /// Construct from an IPv4 @a range.
  IPRange(IP4Range const &range);

  /// Construct from an IPv6 @a range.
  IPRange(IP6Range const &range);

  /// Construct from view.
  IPRange(IPRangeView const &view);

  /** Construct from a string format.
   *
   * @param text Text form of range.
   *
   * The string can be a single address, two addresses separated by a dash '-' or a CIDR network.
   */
  IPRange(string_view const &text);

  /** Update with an IPv4 range.
   *
   * @param min Minimum value.
   * @param max Maximum value.
   * @return @a this.
   */
  self_type &assign(IP4Addr const &min, IP4Addr const &max);

  /** Update with an IPv6 range.
   *
   * @param min Minimum address.
   * @param max Maximum address.
   * @return @a this
   */
  self_type &assign(IP6Addr const &min, IP6Addr const &max);

  /// Assign from view.
  self_type &operator=(IPRangeView const &rv);

  /// Equality
  bool operator==(self_type const &that) const;
  /// Inequality
  bool operator!=(self_type const &that) const;

  /// @return @c true if this is an IPv4 range, @c false if not.
  bool is_ip4() const;

  /// @return @c true if this is an IPv6 range, @c false if not.
  bool is_ip6() const;

  /** Check if @a this range is the IP address @a family.
   *
   * @param family IP address family.
   * @return @c true if this is @a family, @c false if not.
   */
  bool is(sa_family_t family) const;

  /** Load the range from @a text.
   *
   * @param text Range specifier in text format.
   * @return @c true if @a text was successfully parsed, @c false if not.
   *
   * A successful parse means @a this was loaded with the specified range. If not the range is
   * marked as invalid.
   */
  bool load(std::string_view const &text);

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IPAddr const& addr) const;

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IP6Addr const& addr) const;

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IP4Addr const& addr) const;

  /// @return The minimum address in the range.
  IPAddr min() const;

  /// @return The maximum address in the range.
  IPAddr max() const;

  /// @return @c true if there are no addresses in the range.
  bool empty() const;

  /// Make the range empty / invalid.
  self_type &clear();

  /// @return The IPv4 range.
  IP4Range const & ip4() const;

  /// @return The IPv6 range.
  IP6Range const & ip6() const;

  /// @return The range family.
  sa_family_t family() const;

  /** Compute the mask for @a this as a network.
   *
   * @return If @a this is a network, the mask for that network. Otherwise an invalid mask.
   *
   * @see IPMask::is_valid
   */
  IPMask network_mask() const;

  /// Container for remaining range for network generation.
  class NetSource;

  /** Generate a list of networks covering @a this range.
   *
   * @return A network generator.
   *
   * The returned object can be used as an iterator, or as a container to iterating over
   * the unique minimal set of networks that cover @a this range.
   *
   * @code
   * void (IPRange const& range) {
   *   for ( auto const& net : range ) {
   *     net.addr(); // network address.
   *     net.mask(); // network mask;
   *   }
   * }
   * @endcode
   */
  NetSource networks() const;

protected:
  /** Range container.
   *
   * @internal
   *
   * This was a @c std::variant at one point, but the complexity got in the way because
   * - These objects have no state, need no destruction.
   * - Construction was problematic because @c variant requires construction, then access,
   *   whereas this needs access to construct (e.g. via the @c load method).
   */
  union {
    std::monostate _nil; ///< Make constructor easier to implement.
    IP4Range _ip4;       ///< IPv4 range.
    IP6Range _ip6;       ///< IPv6 range.
  } _range{std::monostate{}};

  /// Family of @a _range.
  sa_family_t _family{AF_UNSPEC};
};

/** Network generator class.
 * This generates networks from a range and acts as both a forward iterator and a container.
 *
 * @see IPRange::networks
 */
class IPRange::NetSource {
  using self_type = NetSource; ///< Self reference type.
public:
  using range_type = IPRange; ///< Import base range type.

  /// Construct from @a range.
  explicit NetSource(range_type const &range);

  /// Construct from view.
  explicit NetSource(IPRangeView const &rv);

  /// Copy constructor.
  NetSource(self_type const &that) = default;

  /// This class acts as a container and an iterator.
  using iterator = self_type;
  /// All iteration is constant so no distinction between iterators.
  using const_iterator = iterator;

  iterator begin() const; ///< First network.
  iterator end() const;   ///< Past last network.

  /// @return The current network.
  IPNet operator*() const;

  /// Access @a this as if it were an @c IP6Net.
  self_type *operator->();

  /// Iterator support.
  /// @return The current network address.
  IPAddr addr() const;

  /// Iterator support.
  /// @return The current network mask.
  IPMask mask() const;

  /// Move to next network.
  self_type &operator++();

  /// Move to next network.
  self_type operator++(int);

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality.
  bool operator!=(self_type const &that) const;

protected:
  union {
    std::monostate _nil;      ///< Default value, no addresses.
    IP4Range::NetSource _ip4; ///< IPv4 addresses.
    IP6Range::NetSource _ip6; ///< IPv6 addresses.
  };

  sa_family_t _family = AF_UNSPEC; ///< Mark for union content.
};

/** View of a range.
 *
 * The point of this is @c IPRange is really a union on top of @c IP4Range and @c IP6Range therefore
 * using it requires copying. A view enable using an IPv4 or IPv6 range as a generic range without
 * the copy. This is useful in situations where performance is critical.
 *
 * Used primarily for iterator implementation where the ranges are stored in family specific ranges
 * in the container. The iterator can use this to provide access as an @c IPRange without a copying
 * every iteration.
 *
 * @note An earlier implementation used references and updated those to achieve this same effect but
 * that appeared to confusion the optimizer and odd effects would happen at higher optimization levels
 * (in particular, iterators would appear to not actually increment even thought the increment code
 * was invoked).
 */
class IPRangeView {
  using self_type = IPRangeView;
  friend IPRange;
  /// Storage for the view pointer - union because only one can be valid.
  union storage_type {
    std::monostate _nil; ///< No data present.
    IP4Range const *_4;  ///< IPv4 range.
    IP6Range const *_6;  ///< IPv6 range.
    void const *_void;   ///< Used only for fast copy in construction and assignment.

    // These constructors are needed to make the default construction / assignent methods work.
    // Otherwise the compiler thinks the union isn't initialized.
    storage_type() = default;
    storage_type(std::monostate) {}
    storage_type(storage_type const &that);
    storage_type &operator=(storage_type const &rhs);
  };

public:
  /// Default constructor - invalid view.
  IPRangeView() = default;

  /// Compare to a range.
  bool operator==(IPRange const &r) const;

  /// @return @c true if there is no valid view to a range.
  bool valid() const;

  // @return @c true if the range is empty (invalid views are empty)
  bool empty() const;

  /// Reset to invalid view.
  self_type &clear();

  /// Update the view.
  self_type &assign(IP4Range const &r);

  /// Update the view.
  self_type &assign(IP6Range const &r);

  /// @return @c true if this is an IPv4 range.
  bool is_ip4() const;

  /// @return @c true if this is an IPv6 range.
  bool is_ip6() const;

  /** Check if @a this range is the IP address @a family.
   *
   * @param family IP address family.
   * @return @c true if this is @a family, @c false if not.
   */
  bool is(sa_family_t family) const;

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IPAddr const& addr) const;

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IP6Addr const& addr) const;

  /** Test if an address is in the range.
   *
   * @param addr Address to test.
   * @return @c true if in @a this range, @c false if not.
   */
  bool contains(IP4Addr const& addr) const;

  /// @return Reference to the viewed IPv4 range.
  IP4Range const &ip4() const;

  /// @return Reference to the viewd IPv6 range.
  IP6Range const &ip6() const;

  /// @{
  /// Forwarding methods.

  /// @return The minimum address in the range.
  IPAddr min() const;

  /// @return The maximum value in the range.
  IPAddr max() const;

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality.
  bool operator!=(self_type const &that) const;

  /** Generate a list of networks covering @a this range.
   *
   * @return A network generator.
   *
   * @see IPRange::networks
   */
  IPRange::NetSource
  networks() const {
    return IPRange::NetSource(*this);
  }

  /// @}

protected:
  storage_type _raw   = {std::monostate()}; ///< Storage for the view pointer.
  sa_family_t _family = AF_UNSPEC;          ///< Range address family.
};

/// An IPv4 network.
class IP4Net {
  using self_type = IP4Net; ///< Self reference type.
public:
  IP4Net()                      = default; ///< Construct invalid network.
  IP4Net(self_type const &that) = default; ///< Copy constructor.

  /** Construct from @a addr and @a mask.
   *
   * @param addr An address in the network.
   * @param mask The mask for the network.
   *
   * The network is based on the mask, and the resulting network address is chosen such that the
   * network will contain @a addr. For a given @a addr and @a mask there is only one network
   * that satisifies these criteria.
   */
  IP4Net(IP4Addr addr, IPMask mask);

  IP4Net(swoc::TextView text) { this->load(text); }

  /** Parse network as @a text.
   *
   * @param text String describing the network in CIDR format.
   * @return @c true if a valid string, @c false if not.
   */
  bool load(swoc::TextView text);

  /// @return @c true if the network contains no addresses (is invalid).
  bool empty() const;

  /// @return Network address - smallest address in the network.
  IP4Addr min() const;

  /// @return The largest address in the network.
  IP4Addr max() const;

  /// @return The mask for the network.
  IPMask const &mask() const;

  /// @return A range that exactly covers the network.
  IP4Range as_range() const;

  /** Assign an @a addr and @a mask to @a this.
   *
   * @param addr Network addres.
   * @param mask Network mask.
   * @return @a this.
   */
  self_type &assign(IP4Addr const &addr, IPMask const &mask);

  /// Reset network to invalid state.
  self_type &
  clear() {
    _mask.clear();
    return *this;
  }

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality
  bool operator!=(self_type const &that) const;

protected:
  IP4Addr _addr; ///< Network address (also lower_node).
  IPMask _mask;  ///< Network mask.
};

/// IPv6 network.
class IP6Net {
  using self_type = IP6Net; ///< Self reference type.
public:
  IP6Net()                      = default; ///< Construct invalid network.
  IP6Net(self_type const &that) = default; ///< Copy constructor.

  /** Construct from @a addr and @a mask.
   *
   * @param addr An address in the network.
   * @param mask The mask for the network.
   *
   * The network is based on the mask, and the resulting network address is chosen such that the
   * network will contain @a addr. For a given @a addr and @a mask there is only one network
   * that satisifies these criteria.
   */
  IP6Net(IP6Addr addr, IPMask mask);

  /** Construct from text.
   *
   * @param text Network description.
   *
   * The format must be "addr/mask" where "addr" is a valid address and mask is either a single
   * number for the mask width (CIDR) or a mask in address notation.
   */
  IP6Net(TextView text) { this->load(text); }

  /** Parse network as @a text.
   *
   * @param text String describing the network in CIDR format.
   * @return @c true if a valid string, @c false if not.
   */
  bool load(swoc::TextView text);

  /// @return @c true if the network contains no addresses (is invalid).
  bool empty() const;

  /// @return Network address - smallest address in the network.
  IP6Addr min() const;

  /// @return Largest address in the network.
  IP6Addr max() const;

  /// @return The mask for the network.
  IPMask const &mask() const;

  /// @return A range that exactly covers the network.
  IP6Range as_range() const;

  /** Assign an @a addr and @a mask to @a this.
   *
   * @param addr Network addres.
   * @param mask Network mask.
   * @return @a this.
   */
  self_type &assign(IP6Addr const &addr, IPMask const &mask);

  /// Reset network to invalid state.
  self_type &
  clear() {
    _mask.clear();
    return *this;
  }

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality
  bool operator!=(self_type const &that) const;

protected:
  IP6Addr _addr; ///< Network address (also lower_node).
  IPMask _mask;  ///< Network mask.
};

/** Representation of an IP address network.
 *
 */
class IPNet {
  using self_type = IPNet; ///< Self reference type.
public:
  IPNet()                      = default; ///< Construct invalid network.
  IPNet(self_type const &that) = default; ///< Copy constructor.

  /** Construct from @a addr and @a mask.
   *
   * @param addr An address in the network.
   * @param mask The mask for the network.
   *
   * The network is based on the mask, and the resulting network address is chosen such that the
   * network will contain @a addr. For a given @a addr and @a mask there is only one network
   * that satisifies these criteria.
   */
  IPNet(IPAddr const &addr, IPMask const &mask);

  /** Construct from text.
   *
   * @param text Network description.
   *
   * The format must be "addr/mask" where "addr" is a valid address and mask is either a single
   * number for the mask width (CIDR) or a mask in address notation.
   */
  IPNet(TextView text);

  /** Parse network as @a text.
   *
   * @param text String describing the network in CIDR format.
   * @return @c true if a valid string, @c false if not.
   */
  bool load(swoc::TextView text);

  /// @return @c true if the network contains no addresses (is invalid).
  bool empty() const;

  /// @return Network address - smallest address in the network.
  IPAddr min() const;

  /// @return Largest address in the network.
  IPAddr max() const;

  /// @return The number of bits in the mask.
  IPMask::raw_type width() const;

  /// @return The mask for the network.
  IPMask const &mask() const;

  /// @return A range that exactly covers the network.
  IPRange as_range() const;

  /// @return @c true if network is IPv4.
  bool
  is_ip4() const {
    return _addr.is_ip4();
  }

  /// @return @c true if network is IPv6.
  bool
  is_ip6() const {
    return _addr.is_ip6();
  }

  /// Address family of network.
  sa_family_t
  family() const {
    return _addr.family();
  }

  /// @return The network as explicitly IPv4.
  IP4Net ip4() const;

  /// @return The network as explicitly IPv6.
  IP6Net ip6() const;

  /** Assign an @a addr and @a mask to @a this.
   *
   * @param addr Network addres.
   * @param mask Network mask.
   * @return @a this.
   */
  self_type &assign(IPAddr const &addr, IPMask const &mask);

  /// Reset network to invalid state.
  self_type &clear();

  /// Equality.
  bool operator==(self_type const &that) const;

  /// Inequality
  bool operator!=(self_type const &that) const;

protected:
  IPAddr _addr; ///< Address and family.
  IPMask _mask; ///< Network mask.
};

// --------------------------------------------------------------------------
namespace detail {
/** Value type for @c IPSpace constant iterator.
 *
 * @tparam PAYLOAD User data type to be stored.
 *
 * @internal Exported because inner classes in template classes cannot be used in partial
 * specialization which is required for tuple support.
 *
 * @internal The value type must be split in two to provide @c const consistency. The structured
 * bidingin types are determined only by the type of the value, therefore if the structured binding
 * should vary in whether the payload binding is @c const then there must be two types. I tested using
 * @c const in the typle type templates but the binding always used the @c const variant regardless of
 * the @const state of the payload instance.
 *
 * @note The @c assign methods are used to update iterators.
 *
 * @see IPSpace
 */
template <typename PAYLOAD> struct ip_space_const_value_type {
  using self_type = ip_space_const_value_type;

  IPRangeView _rv;             ///< View to the current range.
  PAYLOAD *_payload = nullptr; ///< Payload for @a _range.

  ip_space_const_value_type() = default;

  /// Reset to default constructed state.
  self_type &clear();

  /** Update the internal state.
   *
   * @param r Range.
   * @param payload Payload.
   * @return @a this.
   */
  self_type &assign(IP4Range const &r, PAYLOAD &payload);

  /** Update the internal state.
   *
   * @param r Range.
   * @param payload Payload.
   * @return @a this.
   */
  self_type &assign(IP6Range const &r, PAYLOAD &payload);

  /** Update from another instance.
   *
   * @param that Other instance.
   * @return @a this.
   */
  self_type &assign(self_type const &that);

  /// Support assignemnt to @c std::tie.
  std::tuple<IPRangeView, PAYLOAD &>
  tuple() const {
    return {_rv, *_payload};
  }

  /// Equality against an equivalent tuple.
  bool operator==(std::tuple<swoc::IPRange, PAYLOAD> const &t) const;

  /// @return The address range.
  IPRange
  range() const {
    return _rv;
  }

  /// @return The range view.
  IPRangeView
  range_view() const {
    return _rv;
  }

  /// @return A reference to the payload (user content).
  PAYLOAD const &
  payload() const {
    return *_payload;
  }
};

/** Value type for @c IPSpace.
 *
 * @tparam PAYLOAD User data type to be stored.
 *
 * @internal Exported because inner classes in template classes cannot be used in partial
 * specialization which is required for tuple support. This should be removed next API incompatible
 * change release because tuple access is being deprecated.
 *
 * @note The @c assign methods are used to update iterators.
 *
 * @see IPSpace
 */
template <typename PAYLOAD> struct ip_space_value_type : ip_space_const_value_type<PAYLOAD> {
  using self_type  = ip_space_value_type;
  using super_type = ip_space_const_value_type<PAYLOAD>;

  /// @return A reference to the payload (user content).
  PAYLOAD &
  payload() {
    return *super_type::_payload;
  }
};

template <typename PAYLOAD>
auto
ip_space_const_value_type<PAYLOAD>::clear() -> self_type & {
  _rv.clear();
  _payload = nullptr;
  return *this;
}

template <typename PAYLOAD>
auto
ip_space_const_value_type<PAYLOAD>::assign(IP4Range const &r, PAYLOAD &payload) -> self_type & {
  _rv.assign(r);
  _payload = &payload;
  return *this;
}

template <typename PAYLOAD>
auto
ip_space_const_value_type<PAYLOAD>::assign(IP6Range const &r, PAYLOAD &payload) -> self_type & {
  _rv.assign(r);
  _payload = &payload;
  return *this;
}

template <typename PAYLOAD>
auto
ip_space_const_value_type<PAYLOAD>::assign(ip_space_const_value_type::self_type const &that) -> self_type & {
  _rv      = that._rv;
  _payload = that._payload;
  return *this;
}

template <typename PAYLOAD>
bool
ip_space_const_value_type<PAYLOAD>::operator==(std::tuple<swoc::IPRange, PAYLOAD> const &t) const {
  return _rv == std::get<0>(t) && std::get<1>(t) == *_payload;
}

} // namespace detail

/** Coloring of IP address space.
 *
 * @tparam PAYLOAD The color class.
 *
 * This is a class to do fast coloring and lookup of the IP address space. It is range oriented and
 * performs well for ranges, much less well for singletons. Conceptually every IP address is a key
 * in the space and can have a color / payload of type @c PAYLOAD.
 *
 * @c PAYLOAD must have the properties
 *
 * - Cheap to copy.
 * - Comparable via the equality and inequality operators.
 */
template <typename PAYLOAD> class IPSpace {
  using self_type = IPSpace;
  using IP4Space  = DiscreteSpace<IP4Addr, PAYLOAD>;
  using IP6Space  = DiscreteSpace<IP6Addr, PAYLOAD>;

public:
  using payload_t = PAYLOAD; ///< Export payload type.
  /// Iterator value, a range and payload.
  using value_type = detail::ip_space_value_type<PAYLOAD>;

  /// Construct an empty space.
  IPSpace() = default;

  /** Mark the range @a r with @a payload.
   *
   * @param range Range to mark.
   * @param payload Payload to assign.
   * @return @a this
   *
   * All addresses in @a r are set to have the @a payload.
   */
  self_type &mark(IPRange const &range, PAYLOAD const &payload);

  /** Mark ranges of IP4Addr in the IPSpace in one operation.
   *
   * @param range_payloads Array of range/payload pairs.
   * @param size Number of elements in @a range_payloads.
   * @param is_sorted @c true if input is sorted, @c false if not. Assumes not sorted.
   * @return @a this
   */
   self_type &mark_bulk(std::pair<DiscreteRange<IP4Addr>, PAYLOAD>* range_payloads, size_t size, bool is_sorted = false);

   //! vector-based interface for the previous function.
   self_type &mark_bulk(std::vector<std::pair<DiscreteRange<IP4Addr>, PAYLOAD>>& range_payloads, bool is_sorted = false);

   /** Mark ranges of IP6Addr in the IPSpace in one operation.
    *
    * @param range_payloads Array of range/payload pairs.
    * @param size Number of elements in @a range_payloads.
    * @param is_sorted @c true if input is sorted, @c false if not. Assumes not sorted.
    * @return @a this
    */
   self_type &mark_bulk(std::pair<DiscreteRange<IP6Addr>, PAYLOAD>* range_payloads, size_t size, bool is_sorted = false);

   //! vector-based interface for the previous function.
   self_type &mark_bulk(std::vector<std::pair<DiscreteRange<IP6Addr>, PAYLOAD>>& range_payloads, bool is_sorted = false);

  /** Fill the @a range with @a payload.
   *
   * @param range Destination range.
   * @param payload Payload for range.
   * @return this
   *
   * Addresses in @a range are set to have @a payload if the address does not already have a payload.
   */
  self_type &fill(IPRange const &range, PAYLOAD const &payload);

  /** Erase addresses in @a range.
   *
   * @param range Address range.
   * @return @a this
   */
  self_type &erase(IPRange const &range);

  /** Blend @a color in to the @a range.
   *
   * @tparam F Blending functor type (deduced).
   * @tparam U Data to blend in to payloads.
   * @param range Target range.
   * @param color Data to blend in to existing payloads in @a range.
   * @param blender Blending functor.
   * @return @a this
   *
   * @a blender is required to have the signature <tt>void(PAYLOAD& lhs , U CONST&rhs)</tt>. It must
   * act as a compound assignment operator, blending @a rhs into @a lhs. That is, if the result of
   * blending @a rhs in to @a lhs is defined as "lhs @ rhs" for the binary operator "@", then @a
   * blender computes "lhs @= rhs".
   *
   * Every address in @a range is assigned a payload. If the address does not already have a color,
   * it is assigned the default constructed @c PAYLOAD blended with @a color. If the address has a
   * @c PAYLOAD @a p, @a p is updated by invoking <tt>blender(p, color)</tt>, with the expectation
   * that @a p will be updated in place.
   */
  template <typename F, typename U = PAYLOAD> self_type &blend(IPRange const &range, U const &color, F &&blender);

  template <typename F, typename U = PAYLOAD> self_type &blend(IP4Range const &range, U const &color, F &&blender);

  template <typename F, typename U = PAYLOAD> self_type &blend(IP6Range const &range, U const &color, F &&blender);

  /// @return The number of distinct ranges.
  size_t count() const;

  /// @return The number of IPv4 ranges.
  size_t count_ip4() const;

  /// @return The number of IPv6 ranges.
  size_t count_ip6() const;

  /** Number of rnages for a specific address family.
   *
   * @param f Address family.
   * @return The number of ranges of @a family.
   */
  size_t count(sa_family_t f) const;

  /// @return @c true if there are no ranges in the space, @c false otherwise.
  bool empty() const;

  /// Remove all ranges.
  void clear();

  /** Constant iterator.
   * The value type is a tuple of the IP address range and the @a PAYLOAD. Both are constant.
   *
   * @internal The non-const iterator is a subclass of this, in order to share implementation. This
   * also makes it easy to convert from iterator to const iterator, which is desirable.
   *
   * @internal The return type is quite tricky because the value type of the nested containers is
   * not the same as the value type for this container. It's not even a composite - @c IPRange is
   * not an alias for either of the family specific range types. Therefore the iterator itself must
   * contain a synthesized instance of the value type, which creates scoping and update problems.
   * The approach here is to update the synthetic value when the iterator is modified and returning
   * it by value for the dereference operator because a return by reference means  code like
   * @code
   *   auto && [ r , p ] = *(space.find(addr));
   * @endcode
   * can fail due to the iterator going out of scope after the statement is finished making @a r
   * and @a p dangling references. If the return is by value the compiler takes care of it.
   */
  class const_iterator {
    using self_type = const_iterator; ///< Self reference type.
    friend class IPSpace;

  public:
    using value_type = detail::ip_space_const_value_type<PAYLOAD>; /// Import for API compliance.
    // STL algorithm compliance.
    using iterator_category = std::bidirectional_iterator_tag;
    using pointer           = value_type const *;
    using reference         = value_type const &;
    using difference_type   = int;

    /// Default constructor.
    const_iterator() = default;

    /// Copy constructor.
    const_iterator(self_type const &that) = default;

    /// Assignment.
    self_type &operator=(self_type const &that);

    /// Pre-increment.
    /// Move to the next element in the list.
    /// @return The iterator.
    self_type &operator++();

    /// Pre-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator.
    self_type &operator--();

    /// Post-increment.
    /// Move to the next element in the list.
    /// @return The iterator value before the increment.
    self_type operator++(int);

    /// Post-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator value before the decrement.
    self_type operator--(int);

    /// Dereference.
    /// @return A reference to the referent.
    reference operator*() const;

    /// Dereference.
    /// @return A pointer to the referent.
    pointer operator->() const;

    /// Equality
    bool operator==(self_type const &that) const;

    /// Inequality
    bool operator!=(self_type const &that) const;

  protected:
    // These are stored non-const to make implementing @c iterator easier. The containing class provides the
    // required @c const protection. Internally a tuple of iterators is stored for forward iteration. If
    // the primary (ipv4) iterator is at the end, then use the secondary (ipv6) iterator. The reverse
    // is done for reverse iteration. This depends on the extra support @c IntrusiveDList iterators
    // provide.
    typename IP4Space::iterator _iter_4; ///< IPv4 sub-space iterator.
    typename IP6Space::iterator _iter_6; ///< IPv6 sub-space iterator.
    /// Current value.
    value_type _value;

    /** Internal constructor.
     *
     * @param iter4 Starting place for IPv4 subspace.
     * @param iter6 Starting place for IPv6 subspace.
     *
     * In practice, at most one iterator should be "internal", the other should be the beginning or end.
     */
    const_iterator(typename IP4Space::const_iterator const &iter4, typename IP6Space::const_iterator const &iter6);

    // These are required because the actual range type for the subspaces is @c DiscreteRange<T>
    // and returning that type without a cast creates a temporary which causes some nasty side effects.

    /// @return Properly type cast range from iterator.
    IP4Range const &
    r4() {
      return static_cast<IP4Range const &>(_iter_4->range());
    }
    /// @return Properly type cast range from iterator.
    IP6Range const &
    r6() {
      return static_cast<IP6Range const &>(_iter_6->range());
    }
  };

  /** Iterator.
   * The value type is a tuple of the IP address range and the @a PAYLOAD. The range is constant
   * and the @a PAYLOAD is a reference. This can be used to update the @a PAYLOAD for this range.
   *
   * @note Range merges are not triggered by modifications of the @a PAYLOAD via an iterator.
   */
  class iterator : public const_iterator {
    using self_type  = iterator;
    using super_type = const_iterator;

    friend class IPSpace;

  protected:
    using super_type::super_type; /// Inherit supertype constructors.
    /// Protected constructor to convert const to non-const.
    /// @note This makes for much less code duplication in iterator relevant methods.
    iterator(const_iterator const &that) : const_iterator(that) {}

  public:
    /// Value type of iteration.
    using value_type = detail::ip_space_value_type<PAYLOAD>;
    using pointer    = value_type *;
    using reference  = value_type &;

    /// Default constructor.
    iterator() = default;

    /// Copy constructor.
    iterator(self_type const &that) = default;

    /// Assignment.
    self_type &operator=(self_type const &that);

    /// Pre-increment.
    /// Move to the next element in the list.
    /// @return The iterator.
    self_type &operator++();

    /// Pre-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator.
    self_type &operator--();

    /// Post-increment.
    /// Move to the next element in the list.
    /// @return The iterator value before the increment.
    self_type operator++(int);

    /// Post-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator value before the decrement.
    self_type operator--(int);

    /// Dereference.
    /// @return A reference to the referent.
    reference operator*() const;

    /// Dereference.
    /// @return A pointer to the referent.
    pointer operator->() const;

  protected:
    // Retrieve the value and convert from the super (const) type value to the value for iterator.
    value_type &value() const;
  };

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return Iterator for the range containing @a addr.
   */
  iterator find(IPAddr const &addr);

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return Iterator for the range containing @a addr.
   */
  const_iterator find(IPAddr const &addr) const;

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return An iterator which is valid if @a addr was found, @c end if not.
   */
  iterator find(IP4Addr const &addr);

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return An iterator which is valid if @a addr was found, @c end if not.
   */
  const_iterator find(IP4Addr const &addr) const;

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return An iterator which is valid if @a addr was found, @c end if not.
   */
  iterator find(IP6Addr const &addr);

  /** Find the payload for an @a addr.
   *
   * @param addr Address to find.
   * @return An iterator which is valid if @a addr was found, @c end if not.
   */
  const_iterator find(IP6Addr const &addr) const;

  /// @return An iterator to the first element.
  iterator begin();

  /// @return A constant iterator to the first element.
  const_iterator begin() const;

  /// @return An iterator past the last element.
  iterator end();

  /// @return A constant iterator past the last element.
  const_iterator end() const;

  /// @return Iterator to the first IPv4 address.
  iterator begin_ip4();
  /// @return Iterator to the first IPv4 address.
  const_iterator begin_ip4() const;

  /// @return Iterator past the last IPv4 address.
  iterator end_ip4();
  /// @return Iterator past the last IPv4 address.
  const_iterator end_ip4() const;

  /// @return Iterator at the first IPv6 address.
  iterator begin_ip6();
  /// @return Iterator at the first IPv6 address.
  const_iterator begin_ip6() const;
  /// @return Iterator past the last IPv6 address.
  iterator end_ip6();
  /// @return Iterator past the last IPv6 address.
  const_iterator end_ip6() const;

  /// @return Iterator to the first address of @a family.
  const_iterator begin(sa_family_t family) const;

  /// @return Iterator past the last address of @a family.
  const_iterator end(sa_family_t family) const;

  /** Sequnce of ranges that intersect @a r.
   *
   * @param r Search range.
   * @return Iterator pair covering ranges that intersect @a r.
   */
  std::pair<iterator, iterator>
  intersection(IP4Range const &r) {
    auto &&[begin, end] = _ip4.intersection(r);
    return {this->iterator_at(begin), this->iterator_at(end)};
  }

  /** Sequnce of ranges that intersect @a r.
   *
   * @param r Search range.
   * @return Iterator pair covering ranges that intersect @a r.
   */
  std::pair<iterator, iterator>
  intersection(IP6Range const &r) {
    auto &&[begin, end] = _ip6.intersection(r);
    return {this->iterator_at(begin), this->iterator_at(end)};
  }

  /** Sequnce of ranges that intersect @a r.
   *
   * @param r Search range.
   * @return Iterator pair covering ranges that intersect @a r.
   */
  std::pair<iterator, iterator>
  intersection(IPRange const &r) {
    if (r.is_ip4()) {
      return this->intersection(r.ip4());
    } else if (r.is_ip6()) {
      return this->intersection(r.ip6());
    }
    return {this->end(), this->end()};
  }

protected:
  IP4Space _ip4; ///< Sub-space containing IPv4 ranges.
  IP6Space _ip6; ///< sub-space containing IPv6 ranges.

  iterator
  iterator_at(typename IP4Space::const_iterator const &spot) {
    return iterator(spot, _ip6.begin());
  }
  iterator
  iterator_at(typename IP6Space::const_iterator const &spot) {
    return iterator(_ip4.end(), spot);
  }

  friend class IPRangeSet;
};

/** An IPSpace that contains only addresses.
 *
 * This is to @c IPSpace as @c std::set is to @c std::map. The @c value_type is removed from the API
 * and only the keys are visible. This suits use cases where the goal is to track the presence of
 * addresses without any additional data.
 *
 * @note Because there is only one value stored, there is no difference between @c mark and @c fill.
 */
class IPRangeSet {
  using self_type = IPRangeSet;

  /// Empty struct to use for payload.
  /// This declares the struct and defines the singleton instance used.
  /// @internal For some reason @c std::monostate didn't work, but I don't remember why.
  static inline constexpr struct Mark {
    using self_type = Mark;
    /// @internal @c IPSpace requires equality / inequality operators.
    /// These make all instance equal to each other.
    bool operator==(self_type const &that);
    bool operator!=(self_type const &that);
  } MARK{};

  /// Range set type.
  using Space = swoc::IPSpace<Mark>;

public:
  /// Default construct empty set.
  IPRangeSet() = default;

  /** Add addresses to the set.
   *
   * @param r Range of addresses to add.
   * @return @a this
   *
   * Identical to @c fill.
   */
  self_type &mark(swoc::IPRange const &r);

  /** Add addresses to the set.
   *
   * @param r Range of addresses to add.
   * @return @a this
   *
   * Identical to @c mark.
   */
  self_type &fill(swoc::IPRange const &r);

  /// @return @c true if @a addr is in the set.
  bool contains(swoc::IPAddr const &addr) const;

  /// @return Number of ranges in the set.
  size_t count() const;

  bool empty() const;

  /// Remove all addresses in the set.
  void clear();

  /// Bidirectional constant iterator for iteration over ranges.
  class const_iterator {
    using self_type  = const_iterator; ///< Self reference type.
    using super_type = Space::const_iterator;
    friend class IPRangeSet;

  public:
    using value_type = IPRangeView;
    // STL algorithm compliance.
    using iterator_category = std::bidirectional_iterator_tag;
    using pointer           = value_type const *;
    using reference         = value_type const &;
    using difference_type   = int;

    /// Default constructor.
    const_iterator() = default;

    /// Copy constructor.
    const_iterator(self_type const &that) = default;

    /// Assignment.
    self_type &operator=(self_type const &that) = default;

    /// Pre-increment.
    /// Move to the next element in the list.
    /// @return The iterator.
    self_type &operator++();

    /// Pre-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator.
    self_type &operator--();

    /// Post-increment.
    /// Move to the next element in the list.
    /// @return The iterator value before the increment.
    self_type operator++(int);

    /// Post-decrement.
    /// Move to the previous element in the list.
    /// @return The iterator value before the decrement.
    self_type operator--(int);

    /// Dereference.
    /// @return A reference to the referent.
    reference operator*() const;

    /// Dereference.
    /// @return A pointer to the referent.
    pointer operator->() const;

    /// Equality
    bool operator==(self_type const &that) const;

    /// Inequality
    bool operator!=(self_type const &that) const;

  protected:
    const_iterator(super_type const &spot) : _iter(spot) {}

    super_type _iter; ///< Underlying iterator.
    IPRange _r;       ///< Some less temporary storage for dereferences.
  };

  using iterator = const_iterator;

  /// @return Iterator to first range.
  const_iterator
  begin() const {
    return _addrs.begin();
  }
  /// @return Iterator past last range.
  const_iterator
  end() const {
    return _addrs.end();
  }

protected:
  /// The address set.
  Space _addrs;
};

inline auto
IPRangeSet::mark(swoc::IPRange const &r) -> self_type & {
  _addrs.mark(r, MARK);
  return *this;
}

inline auto
IPRangeSet::fill(swoc::IPRange const &r) -> self_type & {
  _addrs.mark(r, MARK);
  return *this;
}

inline bool
IPRangeSet::contains(swoc::IPAddr const &addr) const {
  return _addrs.find(addr) != _addrs.end();
}

inline size_t
IPRangeSet::count() const {
  return _addrs.count();
}

inline bool
IPRangeSet::empty() const {
  return _addrs.empty();
}

inline void
IPRangeSet::clear() {
  _addrs.clear();
}

inline bool
IPRangeSet::Mark::operator==(IPRangeSet::Mark::self_type const &) {
  return true;
}

inline bool
IPRangeSet::Mark::operator!=(IPRangeSet::Mark::self_type const &) {
  return false;
}

template <typename PAYLOAD>
IPSpace<PAYLOAD>::const_iterator::const_iterator(typename IP4Space::const_iterator const &iter4,
                                                 typename IP6Space::const_iterator const &iter6)
  : _iter_4(static_cast<typename IP4Space::iterator const &>(iter4)),
    _iter_6(static_cast<typename IP6Space::iterator const &>(iter6)) {
  if (_iter_4.has_next()) {
    _value.assign(this->r4(), _iter_4->payload());
  } else if (_iter_6.has_next()) {
    _value.assign(this->r6(), _iter_6->payload());
  }
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator=(self_type const &that) -> self_type & {
  _iter_4 = that._iter_4;
  _iter_6 = that._iter_6;
  _value.assign(that._value);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator++() -> self_type & {
  bool incr_p = false;
  if (_iter_4.has_next()) {
    ++_iter_4;
    incr_p = true;
    if (_iter_4.has_next()) {
      _value.assign(this->r4(), _iter_4->payload());
      return *this;
    }
  }

  if (_iter_6.has_next()) {
    if (incr_p || (++_iter_6).has_next()) {
      _value.assign(this->r6(), _iter_6->payload());
      return *this;
    }
  }
  _value.clear();
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator++(int) -> self_type {
  self_type zret(*this);
  ++*this;
  return zret;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator--() -> self_type & {
  if (_iter_6.has_prev()) {
    --_iter_6;
    _value.assign(this->r6(), _iter_6->payload());
    return *this;
  }
  if (_iter_4.has_prev()) {
    --_iter_4;
    _value.assign(this->r4(), _iter_4->payload());
    return *this;
  }
  _value.clear();
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator--(int) -> self_type {
  self_type zret(*this);
  --*this;
  return zret;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator*() const -> reference {
  return _value;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::const_iterator::operator->() const -> pointer {
  return &_value;
}

/* Bit of subtlety with equality - although it seems that if @a _iter_4 is valid, it doesn't matter
 * where @a _iter6 is (because it is really the iterator location that's being checked), it's
 * necessary to do the @a _iter_4 validity on both iterators to avoid the case of a false positive
 * where different internal iterators are valid. However, in practice the other (non-active)
 * iterator won't have an arbitrary value, it will be either @c begin or @c end in step with the
 * active iterator therefore it's effective and cheaper to just check both values.
 */

template <typename PAYLOAD>
bool
IPSpace<PAYLOAD>::const_iterator::operator==(self_type const &that) const {
  return _iter_4 == that._iter_4 && _iter_6 == that._iter_6;
}

template <typename PAYLOAD>
bool
IPSpace<PAYLOAD>::const_iterator::operator!=(self_type const &that) const {
  return _iter_4 != that._iter_4 || _iter_6 != that._iter_6;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator=(self_type const &that) -> self_type & {
  this->super_type::operator=(that);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::value() const -> value_type & {
  return reinterpret_cast<value_type &>(const_cast<self_type *>(this)->_value);
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator->() const -> pointer {
  return &(this->value());
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator*() const -> reference {
  return this->value();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator++() -> self_type & {
  this->super_type::operator++();
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator++(int) -> self_type {
  self_type zret{*this};
  ++*this;
  return zret;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator--() -> self_type & {
  this->super_type::operator--();
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::iterator::operator--(int) -> self_type {
  self_type zret{*this};
  --*this;
  return zret;
}

/// ------------------------------------------------------------------------------------

// +++ IPRange +++

inline IPRangeView::storage_type::storage_type(IPRangeView::storage_type const &that) : _void(that._void) {}

inline IPRangeView::storage_type &
IPRangeView::storage_type::operator=(IPRangeView::storage_type const &rhs) {
  _void = rhs._void;
  return *this;
}

inline IP4Range::IP4Range(string_view const &text) {
  this->load(text);
}

inline auto
IP4Range::networks() const -> NetSource {
  return {NetSource{*this}};
}

inline IP6Range::IP6Range(string_view const &text) {
  this->load(text);
}

inline auto
IP6Range::networks() const -> NetSource {
  return {NetSource{*this}};
}

inline IPRange::IPRange(IP4Range const &range) : _family(AF_INET) {
  _range._ip4 = range;
}

inline IPRange::IPRange(IP6Range const &range) : _family(AF_INET6) {
  _range._ip6 = range;
}

inline IPRange::IPRange(IP4Addr const &min, IP4Addr const &max) {
  this->assign(min, max);
}

inline IPRange::IPRange(IP6Addr const &min, IP6Addr const &max) {
  this->assign(min, max);
}

inline IPRange::IPRange(string_view const &text) {
  this->load(text);
}

inline IPRange::IPRange(IPRangeView const &view) {
  if (AF_INET == view._family) {
    *this = *view._raw._4;
  } else if (AF_INET6 == view._family) {
    *this = *view._raw._6;
  }
}

inline auto
IPRange::assign(IP4Addr const &min, IP4Addr const &max) -> self_type & {
  _range._ip4.assign(min, max);
  _family = AF_INET;
  return *this;
}

inline auto
IPRange::assign(IP6Addr const &min, IP6Addr const &max) -> self_type & {
  _range._ip6.assign(min, max);
  _family = AF_INET6;
  return *this;
}

inline auto
IPRange::operator=(const IPRangeView &rv) -> self_type & {
  if (AF_INET == rv._family) {
    *this = *rv._raw._4;
  } else if (AF_INET6 == rv._family) {
    *this = *rv._raw._6;
  }
  return *this;
}

inline auto
IPRange::clear() -> self_type & {
  _family = AF_UNSPEC;
  return *this;
}

inline auto
IPRange::networks() const -> NetSource {
  return {NetSource{*this}};
}

inline bool
IPRange::is(sa_family_t family) const {
  return family == _family;
}

inline bool
IPRange::operator!=(const self_type &that) const {
  return !(*this == that);
}

inline bool
IPRange::is_ip4() const {
  return AF_INET == _family;
}

inline bool
IPRange::is_ip6() const {
  return AF_INET6 == _family;
}

inline sa_family_t IPRange::family() const {
  return _family;
}
inline IP4Range const& IPRange::ip4() const {
  return _range._ip4;
}

inline IP6Range const& IPRange::ip6() const {
  return _range._ip6;
}

inline auto
IPRangeView::clear() -> self_type & {
  _family = AF_UNSPEC;
  return *this;
}

inline bool
IPRangeView::empty() const {
  if (AF_INET6 == _family) {
    return _raw._6->empty();
  } else if (AF_INET == _family) {
    return _raw._4->empty();
  } else {
    return true;
  }
}

inline bool
IPRangeView::is_ip4() const {
  return AF_INET == _family;
}

inline bool
IPRangeView::is_ip6() const {
  return AF_INET6 == _family;
}

inline bool
IPRangeView::is(sa_family_t f) const {
  return f == _family;
}

inline bool IPRange::contains(IPAddr const & addr) const {
  if (addr.family() != _family) {
    return false;
  }
  if (this->ip4()) {
    return _range._ip4.contains(addr.ip4());
  } else if (this->is_ip6()) {
    return _range._ip6.contains(addr.ip6());
  }
  return false;
}

inline bool IPRange::contains(IP6Addr const & addr) const {
  return this->is_ip6() && _range._ip6.contains(addr);
}

inline bool IPRange::contains(IP4Addr const & addr) const {
  return this->is_ip4() && _range._ip4.contains(addr);
}

inline IP4Range const &
IPRangeView::ip4() const {
  return *_raw._4;
}

inline IP6Range const &
IPRangeView::ip6() const {
  return *_raw._6;
}

inline bool
IPRangeView::valid() const {
  return AF_INET == _family || AF_INET6 == _family;
}

inline auto
IPRangeView::assign(IP4Range const &r) -> self_type & {
  _family = r.family();
  _raw._4 = &r;
  return *this;
}

inline auto
IPRangeView::assign(IP6Range const &r) -> self_type & {
  _family = r.family();
  _raw._6 = &r;
  return *this;
}

inline bool
IPRangeView::operator!=(IPRangeView::self_type const &that) const {
  return !(*this == that);
}

inline IPAddr
IPRangeView::min() const {
  return AF_INET == _family ? _raw._4->min() : AF_INET6 == _family ? _raw._6->min() : IPAddr::INVALID;
}

inline IPAddr
IPRangeView::max() const {
  return AF_INET == _family ? _raw._4->max() : AF_INET6 == _family ? _raw._6->max() : IPAddr::INVALID;
}

inline bool IPRangeView::contains(IPAddr const& addr) const {
  if (_family != addr.family()) {
    return false;
  }
  return (_family == addr.family() ) &&
         ( ( this->is_ip4() && _raw._4->contains(addr.ip4()) ) ||
           ( this->is_ip6() && _raw._6->contains(addr.ip6()) )
         );
}

inline bool IPRangeView::contains(IP6Addr const& addr) const {
  return this->is_ip6() && _raw._6->contains(addr);
}

inline bool IPRangeView::contains(IP4Addr const& addr) const {
  return this->is_ip4() && _raw._4->contains(addr);
}

// +++ IPNet +++

inline IP4Net::IP4Net(swoc::IP4Addr addr, swoc::IPMask mask) : _addr(addr & mask), _mask(mask) {}

inline IPMask const &
IP4Net::mask() const {
  return _mask;
}

inline bool
IP4Net::empty() const {
  return !_mask.is_valid();
}

inline IP4Addr
IP4Net::min() const {
  return _addr;
}

inline IP4Addr
IP4Net::max() const {
  return _addr | _mask;
}

inline IP4Range
IP4Net::as_range() const {
  return {this->min(), this->max()};
}

inline bool
IP4Net::operator==(self_type const &that) const {
  return _mask == that._mask && _addr == that._addr;
}

inline bool
IP4Net::operator!=(self_type const &that) const {
  return _mask != that._mask || _addr != that._addr;
}

inline IP4Net::self_type &
IP4Net::assign(IP4Addr const &addr, IPMask const &mask) {
  _addr = addr & mask;
  _mask = mask;
  return *this;
}

inline IP6Net::IP6Net(swoc::IP6Addr addr, swoc::IPMask mask) : _addr(addr & mask), _mask(mask) {}

inline IPMask const &
IP6Net::mask() const {
  return _mask;
}

inline bool
IP6Net::empty() const {
  return !_mask.is_valid();
}

inline IP6Addr
IP6Net::min() const {
  return _addr;
}

inline IP6Addr
IP6Net::max() const {
  return _addr | _mask;
}

inline IP6Range
IP6Net::as_range() const {
  return {this->min(), this->max()};
}

inline bool
IP6Net::operator==(self_type const &that) const {
  return _mask == that._mask && _addr == that._addr;
}

inline bool
IP6Net::operator!=(self_type const &that) const {
  return _mask != that._mask || _addr != that._addr;
}

inline IP6Net::self_type &
IP6Net::assign(IP6Addr const &addr, IPMask const &mask) {
  _addr = addr & mask;
  _mask = mask;
  return *this;
}

inline IPNet::IPNet(IPAddr const &addr, IPMask const &mask) : _addr(addr & mask), _mask(mask) {}

inline IPNet::IPNet(TextView text) {
  this->load(text);
}

inline bool
IPNet::empty() const {
  return !_mask.is_valid();
}

inline IPAddr
IPNet::min() const {
  return _addr;
}

inline IPAddr
IPNet::max() const {
  return _addr | _mask;
}

inline IPMask::raw_type
IPNet::width() const {
  return _mask.width();
}

inline IPMask const &
IPNet::mask() const {
  return _mask;
}

inline IPRange
IPNet::as_range() const {
  return {this->min(), this->max()};
}

inline IPNet::self_type &
IPNet::assign(IPAddr const &addr, IPMask const &mask) {
  _addr = addr & mask;
  _mask = mask;
  return *this;
}

inline bool
IPNet::operator==(IPNet::self_type const &that) const {
  return _mask == that._mask && _addr == that._addr;
}

inline bool
IPNet::operator!=(IPNet::self_type const &that) const {
  return _mask != that._mask || _addr != that._addr;
}

inline bool
operator==(IPNet const &lhs, IP4Net const &rhs) {
  return lhs.is_ip4() && lhs.ip4() == rhs;
}

inline bool
operator==(IP4Net const &lhs, IPNet const &rhs) {
  return rhs.is_ip4() && rhs.ip4() == lhs;
}

inline bool
operator==(IPNet const &lhs, IP6Net const &rhs) {
  return lhs.is_ip6() && lhs.ip6() == rhs;
}

inline bool
operator==(IP6Net const &lhs, IPNet const &rhs) {
  return rhs.is_ip6() && rhs.ip6() == lhs;
}

inline IP4Net
IPNet::ip4() const {
  return IP4Net{_addr.ip4(), _mask};
}

inline IP6Net
IPNet::ip6() const {
  return IP6Net{_addr.ip6(), _mask};
}

inline auto
IPNet::clear() -> self_type & {
  _mask.clear();
  return *this;
}

// +++ Range -> Network classes +++

inline bool
IP4Range::NetSource::is_valid(swoc::IP4Addr mask) const {
  return ((mask._addr & _range._min._addr) == _range._min._addr) && ((_range._min._addr | ~mask._addr) <= _range._max._addr);
}

inline IP4Net
IP4Range::NetSource::operator*() const {
  return IP4Net{_range.min(), IPMask{_cidr}};
}

inline IP4Range::NetSource::iterator
IP4Range::NetSource::begin() const {
  return *this;
}

inline IP4Range::NetSource::iterator
IP4Range::NetSource::end() {
  return self_type{range_type{}};
}

inline bool
IP4Range::NetSource::empty() const {
  return _range.empty();
}

inline IPMask
IP4Range::NetSource::mask() const {
  return IPMask{_cidr};
}

inline auto
IP4Range::NetSource::operator->() -> self_type * {
  return this;
}

inline IP4Addr const &
IP4Range::NetSource::addr() const {
  return _range.min();
}

inline bool
IP4Range::NetSource::operator==(IP4Range::NetSource::self_type const &that) const {
  return ((_cidr == that._cidr) && (_range == that._range)) || (_range.empty() && that._range.empty());
}

inline bool
IP4Range::NetSource::operator!=(IP4Range::NetSource::self_type const &that) const {
  return !(*this == that);
}

inline auto
IP6Range::NetSource::begin() const -> iterator {
  return *this;
}

inline auto
IP6Range::NetSource::end() const -> iterator {
  return self_type{range_type{}};
}

inline bool
IP6Range::NetSource::empty() const {
  return _range.empty();
}

inline IP6Net
IP6Range::NetSource::operator*() const {
  return IP6Net{_range.min(), _mask};
}

inline auto
IP6Range::NetSource::operator->() -> self_type * {
  return this;
}

inline bool
IP6Range::NetSource::is_valid(IPMask const &mask) {
  return ((_range.min() & mask) == _range.min()) && ((_range.min() | mask) <= _range.max());
}

inline bool
IP6Range::NetSource::operator==(IP6Range::NetSource::self_type const &that) const {
  return ((_mask == that._mask) && (_range == that._range)) || (_range.empty() && that._range.empty());
}

inline bool
IP6Range::NetSource::operator!=(IP6Range::NetSource::self_type const &that) const {
  return !(*this == that);
}

inline IP6Addr const &
IP6Range::NetSource::addr() const {
  return _range.min();
}

inline IPMask
IP6Range::NetSource::mask() const {
  return _mask;
}

inline IPRange::NetSource::NetSource(IPRange::NetSource::range_type const &range) {
  if (range.is_ip4()) {
    new (&_ip4) decltype(_ip4)(range.ip4());
    _family = AF_INET;
  } else if (range.is_ip6()) {
    new (&_ip6) decltype(_ip6)(range.ip6());
    _family = AF_INET6;
  }
}

inline IPRange::NetSource::NetSource(IPRangeView const &rv) {
  if (rv.is_ip4()) {
    new (&_ip4) decltype(_ip4)(rv.ip4());
    _family = AF_INET;
  } else if (rv.is_ip6()) {
    new (&_ip6) decltype(_ip6)(rv.ip6());
    _family = AF_INET6;
  }
}

inline auto
IPRange::NetSource::begin() const -> iterator {
  return *this;
}

inline auto
IPRange::NetSource::end() const -> iterator {
  return AF_INET == _family ? self_type{IP4Range{}} : AF_INET6 == _family ? self_type{IP6Range{}} : self_type{IPRange{}};
}

inline IPAddr
IPRange::NetSource::addr() const {
  if (AF_INET == _family) {
    return _ip4.addr();
  } else if (AF_INET6 == _family) {
    return _ip6.addr();
  }
  return {};
}

inline IPMask
IPRange::NetSource::mask() const {
  if (AF_INET == _family) {
    return _ip4.mask();
  } else if (AF_INET6 == _family) {
    return _ip6.mask();
  }
  return {};
}

inline IPNet
IPRange::NetSource::operator*() const {
  return {this->addr(), this->mask()};
}

inline auto
IPRange::NetSource::operator++() -> self_type & {
  if (AF_INET == _family) {
    ++_ip4;
  } else if (AF_INET6 == _family) {
    ++_ip6;
  }
  return *this;
}

inline auto
IPRange::NetSource::operator->() -> self_type * {
  return this;
}

inline bool
IPRange::NetSource::operator==(self_type const &that) const {
  if (_family != that._family) {
    return false;
  }
  if (AF_INET == _family) {
    return _ip4 == that._ip4;
  } else if (AF_INET6 == _family) {
    return _ip6 == that._ip6;
  } else if (AF_UNSPEC == _family) {
    return true;
  }
  return false;
}

inline bool
IPRange::NetSource::operator!=(self_type const &that) const {
  return !(*this == that);
}

// --- IPSpace

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::mark_bulk(std::pair<DiscreteRange<IP4Addr>, PAYLOAD>* range_payloads, size_t size, bool is_sorted) -> self_type & {
  _ip4.mark_bulk(range_payloads, size, is_sorted);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::mark_bulk(std::pair<DiscreteRange<IP6Addr>, PAYLOAD>* range_payloads, size_t size, bool is_sorted) -> self_type & {
  _ip6.mark_bulk(range_payloads, size, is_sorted);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::mark_bulk(std::vector<std::pair<DiscreteRange<IP4Addr>, PAYLOAD>>& range_payloads, bool is_sorted) -> self_type & {
  _ip4.mark_bulk(range_payloads, is_sorted);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::mark_bulk(std::vector<std::pair<DiscreteRange<IP6Addr>, PAYLOAD>>& range_payloads, bool is_sorted) -> self_type & {
  _ip6.mark_bulk(range_payloads, is_sorted);
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::mark(IPRange const &range, PAYLOAD const &payload) -> self_type & {
  if (range.is(AF_INET)) {
    _ip4.mark(range.ip4(), payload);
  } else if (range.is(AF_INET6)) {
    _ip6.mark(range.ip6(), payload);
  }
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::fill(IPRange const &range, PAYLOAD const &payload) -> self_type & {
  if (range.is(AF_INET6)) {
    _ip6.fill(range.ip6(), payload);
  } else if (range.is(AF_INET)) {
    _ip4.fill(range.ip4(), payload);
  }
  return *this;
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::erase(IPRange const &range) -> self_type & {
  if (range.is(AF_INET)) {
    _ip4.erase(range.ip4());
  } else if (range.is(AF_INET6)) {
    _ip6.erase(range.ip6());
  }
  return *this;
}

template <typename PAYLOAD>
template <typename F, typename U>
auto
IPSpace<PAYLOAD>::blend(IPRange const &range, U const &color, F &&blender) -> self_type & {
  if (range.is(AF_INET)) {
    _ip4.blend(range.ip4(), color, blender);
  } else if (range.is(AF_INET6)) {
    _ip6.blend(range.ip6(), color, blender);
  }
  return *this;
}

template <typename PAYLOAD>
template <typename F, typename U>
auto
IPSpace<PAYLOAD>::blend(IP4Range const &range, U const &color, F &&blender) -> self_type & {
  _ip4.blend(range, color, std::forward<F>(blender));
  return *this;
}

template <typename PAYLOAD>
template <typename F, typename U>
auto
IPSpace<PAYLOAD>::blend(IP6Range const &range, U const &color, F &&blender) -> self_type & {
  _ip6.blend(range, color, std::forward<F>(blender));
  return *this;
}

template <typename PAYLOAD>
void
IPSpace<PAYLOAD>::clear() {
  _ip4.clear();
  _ip6.clear();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin() -> iterator {
  return iterator{_ip4.begin(), _ip6.begin()};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin() const -> const_iterator {
  return const_cast<self_type *>(this)->begin();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end() -> iterator {
  return iterator{_ip4.end(), _ip6.end()};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end() const -> const_iterator {
  return const_cast<self_type *>(this)->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin_ip4() -> iterator {
  return this->begin();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin_ip4() const -> const_iterator {
  return this->begin();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end_ip4() -> iterator {
  return {_ip4.end(), _ip6.begin()};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end_ip4() const -> const_iterator {
  return const_cast<self_type *>(this)->end_ip4();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin_ip6() -> iterator {
  return {_ip4.end(), _ip6.begin()};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin_ip6() const -> const_iterator {
  return const_cast<self_type *>(this)->begin_ip6();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end_ip6() -> iterator {
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end_ip6() const -> const_iterator {
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IPAddr const &addr) -> iterator {
  if (addr.is_ip4()) {
    return this->find(addr.ip4());
  } else if (addr.is_ip6()) {
    return this->find(addr.ip6());
  }
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IPAddr const &addr) const -> const_iterator {
  if (addr.is_ip4()) {
    return this->find(addr.ip4());
  } else if (addr.is_ip6()) {
    return this->find(addr.ip6());
  }
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IP4Addr const &addr) -> iterator {
  if (auto spot = _ip4.find(addr); spot != _ip4.end()) {
    return {spot, _ip6.begin()};
  }
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IP4Addr const &addr) const -> const_iterator {
  if (auto spot = _ip4.find(addr); spot != _ip4.end()) {
    return {spot, _ip6.begin()};
  }
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IP6Addr const &addr) -> iterator {
  return {_ip4.end(), _ip6.find(addr)};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::find(IP6Addr const &addr) const -> const_iterator {
  return const_iterator{_ip4.end(), _ip6.find(addr)};
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::begin(sa_family_t family) const -> const_iterator {
  if (AF_INET == family) {
    return this->begin_ip4();
  } else if (AF_INET6 == family) {
    return this->begin_ip6();
  }
  return this->end();
}

template <typename PAYLOAD>
auto
IPSpace<PAYLOAD>::end(sa_family_t family) const -> const_iterator {
  if (AF_INET == family) {
    return this->end_ip4();
  } else if (AF_INET6 == family) {
    return this->end_ip6();
  }
  return this->end();
}

template <typename PAYLOAD>
size_t
IPSpace<PAYLOAD>::count_ip4() const {
  return _ip4.count();
}

template <typename PAYLOAD>
size_t
IPSpace<PAYLOAD>::count_ip6() const {
  return _ip6.count();
}

template <typename PAYLOAD>
size_t
IPSpace<PAYLOAD>::count() const {
  return _ip4.count() + _ip6.count();
}

template <typename PAYLOAD>
size_t
IPSpace<PAYLOAD>::count(sa_family_t f) const {
  return IP4Addr::AF_value == f ? _ip4.count() : IP6Addr::AF_value == f ? _ip6.count() : 0;
}

template <typename PAYLOAD>
bool
IPSpace<PAYLOAD>::empty() const {
  return _ip4.empty() && _ip6.empty();
}

inline auto
IPRangeSet::const_iterator::operator++() -> self_type & {
  ++_iter;
  return *this;
}

inline auto
IPRangeSet::const_iterator::operator--() -> self_type & {
  --_iter;
  return *this;
}

inline auto
IPRangeSet::const_iterator::operator++(int) -> self_type {
  self_type zret{*this};
  ++_iter;
  return zret;
}

inline auto
IPRangeSet::const_iterator::operator--(int) -> self_type {
  self_type zret{*this};
  --_iter;
  return zret;
}

inline auto
IPRangeSet::const_iterator::operator*() const -> reference {
  return _iter->_rv;
}

inline auto
IPRangeSet::const_iterator::operator->() const -> pointer {
  return &(_iter->_rv);
}

inline bool
IPRangeSet::const_iterator::operator==(IPRangeSet::const_iterator::self_type const &that) const {
  return _iter == that._iter;
}

inline bool
IPRangeSet::const_iterator::operator!=(IPRangeSet::const_iterator::self_type const &that) const {
  return _iter != that._iter;
}

}} // namespace swoc::SWOC_VERSION_NS

/// @cond NOT_DOCUMENTED
namespace std {

// -- Tuple support for IP4Net --
template <> class tuple_size<swoc::IP4Net> : public std::integral_constant<size_t, 2> {};

template <size_t IDX> class tuple_element<IDX, swoc::IP4Net> {
  static_assert("swoc::IP4Net tuple index out of range");
};

template <> class tuple_element<0, swoc::IP4Net> {
public:
  using type = swoc::IP4Addr;
};

template <> class tuple_element<1, swoc::IP4Net> {
public:
  using type = swoc::IPMask;
};

// -- Tuple support for IP6Net --
template <> class tuple_size<swoc::IP6Net> : public std::integral_constant<size_t, 2> {};

template <size_t IDX> class tuple_element<IDX, swoc::IP6Net> {
  static_assert("swoc::IP6Net tuple index out of range");
};

template <> class tuple_element<0, swoc::IP6Net> {
public:
  using type = swoc::IP6Addr;
};

template <> class tuple_element<1, swoc::IP6Net> {
public:
  using type = swoc::IPMask;
};

// -- Tuple support for IPNet --
template <> class tuple_size<swoc::IPNet> : public std::integral_constant<size_t, 2> {};

template <size_t IDX> class tuple_element<IDX, swoc::IPNet> {
  static_assert("swoc::IPNet tuple index out of range");
};

template <> class tuple_element<0, swoc::IPNet> {
public:
  using type = swoc::IPAddr;
};

template <> class tuple_element<1, swoc::IPNet> {
public:
  using type = swoc::IPMask;
};

} // namespace std

namespace swoc { inline namespace SWOC_VERSION_NS {

template <size_t IDX>
typename std::tuple_element<IDX, IP4Net>::type
get(swoc::IP4Net const &net) {
  if constexpr (IDX == 0) {
    return net.min();
  } else if constexpr (IDX == 1) {
    return net.mask();
  }
}

template <size_t IDX>
typename std::tuple_element<IDX, IP6Net>::type
get(swoc::IP6Net const &net) {
  if constexpr (IDX == 0) {
    return net.min();
  } else if constexpr (IDX == 1) {
    return net.mask();
  }
}

template <size_t IDX>
typename std::tuple_element<IDX, IPNet>::type
get(swoc::IPNet const &net) {
  if constexpr (IDX == 0) {
    return net.min();
  } else if constexpr (IDX == 1) {
    return net.mask();
  }
}
/// @endcond

}} // namespace swoc::SWOC_VERSION_NS

// Tuple support for IPSpace values.
/// @cond NOT_DOCUMENTED

namespace std {

template <typename P> class tuple_size<swoc::detail::ip_space_value_type<P>> : public integral_constant<size_t, 2> {};
template <typename P> class tuple_size<swoc::detail::ip_space_const_value_type<P>> : public integral_constant<size_t, 2> {};

template <size_t IDX, typename P> class tuple_element<IDX, swoc::detail::ip_space_value_type<P>> {
  static_assert("swoc::IPSpace::value_type tuple index out of range");
};
template <size_t IDX, typename P> class tuple_element<IDX, swoc::detail::ip_space_const_value_type<P>> {
  static_assert("swoc::IPSpace::value_type tuple index out of range");
};

template <typename P> class tuple_element<0, swoc::detail::ip_space_value_type<P>> {
public:
  using type = swoc::IPRangeView const &;
};

template <typename P> class tuple_element<1, swoc::detail::ip_space_value_type<P>> {
public:
  using type = P &;
};

template <typename P> class tuple_element<0, swoc::detail::ip_space_const_value_type<P>> {
public:
  using type = swoc::IPRangeView const &;
};

template <typename P> class tuple_element<1, swoc::detail::ip_space_const_value_type<P>> {
public:
  using type = P const &;
};

} // namespace std

namespace swoc { inline namespace SWOC_VERSION_NS { namespace detail {
template <size_t IDX, typename P>
auto
get(ip_space_const_value_type<P> const &p) -> typename std::tuple_element<IDX, ip_space_const_value_type<P>>::type {
  if constexpr (IDX == 0) {
    return p._rv;
  } else if constexpr (IDX == 1) {
    return *(p._payload);
  }
}

template <size_t IDX, typename P>
auto
get(ip_space_value_type<P> const &p) -> typename std::tuple_element<IDX, ip_space_value_type<P>>::type {
  if constexpr (IDX == 0) {
    return p._rv;
  } else if constexpr (IDX == 1) {
    return *(p._payload);
  }
}
}}} // namespace swoc::SWOC_VERSION_NS::detail

// Support unqualified @c get because ADL doesn't seem to work.
using swoc::detail::get;
// Support @c std::get
namespace std {
using swoc::detail::get;
}

/// @endcond
