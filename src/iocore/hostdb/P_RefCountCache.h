/** @file

  A cache (with map-esque interface) for RefCountObjs

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
#pragma once

#include "iocore/eventsystem/UnixSocket.h"
#include "tscore/Allocator.h"
#include "tscore/Diags.h"
#include "tscore/PriorityQueue.h"
#include "tscore/Ptr.h"
#include "tsutil/TsSharedMutex.h"
#include "tscore/Version.h"
#include "tscore/ink_hrtime.h"
#include "tscore/ink_time.h"
#include "tsutil/Metrics.h"

#include "swoc/IntrusiveHashMap.h"
#include <cstdint>
#include <unistd.h>

using ts::Metrics;

#define REFCOUNT_CACHE_EVENT_SYNC REFCOUNT_CACHE_EVENT_EVENTS_START

#define REFCOUNTCACHE_MAGIC_NUMBER 0x0BAD2D9

static constexpr unsigned char     REFCOUNTCACHE_MAJOR_VERSION = 1;
static constexpr unsigned char     REFCOUNTCACHE_MINOR_VERSION = 0;
static constexpr ts::VersionNumber REFCOUNTCACHE_VERSION(1, 0);

// Stats
struct RefCountCacheBlock {
  Metrics::Gauge::AtomicType   *refcountcache_current_items;
  Metrics::Gauge::AtomicType   *refcountcache_current_size;
  Metrics::Counter::AtomicType *refcountcache_total_inserts;
  Metrics::Counter::AtomicType *refcountcache_total_failed_inserts;
  Metrics::Counter::AtomicType *refcountcache_total_lookups;
  Metrics::Counter::AtomicType *refcountcache_total_hits;
  Metrics::Counter::AtomicType *refcountcache_last_sync_time;
  Metrics::Counter::AtomicType *refcountcache_last_total_items;
  Metrics::Counter::AtomicType *refcountcache_last_total_size;
};

struct RefCountCacheItemMeta {
  uint64_t     key;
  unsigned int size;
  ink_time_t   expiry_time; // expire time as seconds since epoch
  RefCountCacheItemMeta(uint64_t key, unsigned int size, ink_time_t expiry_time = -1)
    : key(key), size(size), expiry_time(expiry_time)
  {
  }
};

// Layer of indirection for the hashmap-- since it needs lots of things inside of it
// We'll also use this as the item header, for persisting objects to disk
class RefCountCacheHashEntry
{
public:
  Ptr<RefCountObj>                              item;
  RefCountCacheHashEntry                       *_next{nullptr};
  RefCountCacheHashEntry                       *_prev{nullptr};
  PriorityQueueEntry<RefCountCacheHashEntry *> *expiry_entry = nullptr;
  RefCountCacheItemMeta                         meta;

  // Need a no-argument constructor to use the classAllocator
  RefCountCacheHashEntry() : item(Ptr<RefCountObj>()), meta(0, 0) {}
  void
  set(RefCountObj *i, uint64_t key, unsigned int size, time_t expire_time)
  {
    this->item = make_ptr(i);
    this->meta = RefCountCacheItemMeta(key, size, expire_time);
  }

  // make these values comparable -- so we can sort them
  bool
  operator<(const RefCountCacheHashEntry &v2) const
  {
    return this->meta.expiry_time < v2.meta.expiry_time;
  }

  static RefCountCacheHashEntry *alloc();
  static void                    dealloc(RefCountCacheHashEntry *e);

  template <typename C>
  static void
  free(RefCountCacheHashEntry *e)
  {
    // Since the Value is actually RefCountObj-- when this gets deleted normally it calls the wrong
    // `free` method, this forces the delete/decr to happen with the right type
    Ptr<C> *tmp = reinterpret_cast<Ptr<C> *>(&e->item);
    tmp->clear();

    e->~RefCountCacheHashEntry();
    dealloc(e);
  }
};

// Since the hashing values are all fixed size, we can simply use a classAllocator to avoid mallocs
extern ClassAllocator<PriorityQueueEntry<RefCountCacheHashEntry *>> expiryQueueEntry;

struct RefCountCacheLinkage {
  using key_type   = uint64_t const;
  using value_type = RefCountCacheHashEntry;

  static value_type *&
  next_ptr(value_type *value)
  {
    return value->_next;
  }
  static value_type *&
  prev_ptr(value_type *value)
  {
    return value->_prev;
  }
  static uint64_t
  hash_of(key_type key)
  {
    return key;
  }
  static uint64_t
  key_of(value_type *v)
  {
    return v->meta.key;
  }
  static bool
  equal(key_type lhs, key_type rhs)
  {
    return lhs == rhs;
  }
};

class RefCountCacheBase
{
protected:
  inline static DbgCtl dbg_ctl{"refcountcache"};
};

// The RefCountCachePartition is simply a map of key -> Ptr<YourClass>
// We partition the cache to reduce lock contention
template <class C> class RefCountCachePartition : private RefCountCacheBase
{
public:
  using hash_type = swoc::IntrusiveHashMap<RefCountCacheLinkage>;

  RefCountCachePartition(unsigned int part_num, uint64_t max_size, unsigned int max_items, RefCountCacheBlock *rsb = nullptr);
  Ptr<C> get(uint64_t key);
  void   put(uint64_t key, C *item, int size = 0, time_t expire_time = 0);
  void   erase(uint64_t key, ink_time_t expiry_time = -1);

  void clear();
  bool is_full() const;
  bool make_space_for(unsigned int);
  void dealloc_entry(hash_type::iterator ptr);

  size_t count() const;
  void   copy(std::vector<RefCountCacheHashEntry *> &items);

  hash_type &get_map();

  ts::shared_mutex lock;

private:
  unsigned int part_num;
  uint64_t     max_size;
  unsigned int max_items;
  uint64_t     size;
  unsigned int items;

  hash_type item_map;

  PriorityQueue<RefCountCacheHashEntry *> expiry_queue;
  RefCountCacheBlock                     *rsb;
};

template <class C>
RefCountCachePartition<C>::RefCountCachePartition(unsigned int part_num, uint64_t max_size, unsigned int max_items,
                                                  RefCountCacheBlock *rsb)
  : part_num(part_num), max_size(max_size), max_items(max_items), size(0), items(0), rsb(rsb)
{
}

template <class C>
Ptr<C>
RefCountCachePartition<C>::get(uint64_t key)
{
  Metrics::Counter::increment(this->rsb->refcountcache_total_lookups);
  if (auto it = this->item_map.find(key); it != this->item_map.end()) {
    // found
    Metrics::Counter::increment(this->rsb->refcountcache_total_hits);
    return make_ptr(static_cast<C *>(it->item.get()));
  } else {
    return Ptr<C>();
  }
}

template <class C>
void
RefCountCachePartition<C>::put(uint64_t key, C *item, int size, time_t expire_time)
{
  Metrics::Counter::increment(this->rsb->refcountcache_total_inserts);
  size += sizeof(C);
  // Remove any colliding entries
  this->erase(key);

  // if we are full, and can't make space-- then don't store the item
  if (this->is_full() && !this->make_space_for(size)) {
    Dbg(dbg_ctl, "partition %d is full-- not storing item key=%" PRIu64, this->part_num, key);
    Metrics::Counter::increment(this->rsb->refcountcache_total_failed_inserts);
    return;
  }

  // Create our value-- which has a ref to the `item`
  RefCountCacheHashEntry *val = RefCountCacheHashEntry::alloc();
  val->set(item, key, size, expire_time);

  // add expiry_entry to expiry queue, if the expire time is positive (otherwise it means don't expire)
  if (expire_time >= 0) {
    Dbg(dbg_ctl, "partition %d adding entry with expire_time=%" PRIdMAX, this->part_num, expire_time);
    PriorityQueueEntry<RefCountCacheHashEntry *> *expiry_entry = expiryQueueEntry.alloc();
    new (expiry_entry) PriorityQueueEntry<RefCountCacheHashEntry *>(val);
    expiry_queue.push(expiry_entry);
    val->expiry_entry = expiry_entry;
  }

  // add the item to the map
  this->item_map.insert(val);
  this->size += val->meta.size;
  this->items++;
  Metrics::Gauge::increment(this->rsb->refcountcache_current_size, static_cast<int64_t>(val->meta.size));
  Metrics::Gauge::increment(this->rsb->refcountcache_current_items);
}

template <class C>
void
RefCountCachePartition<C>::erase(uint64_t key, ink_time_t expiry_time)
{
  if (auto it = this->item_map.find(key); it != this->item_map.end()) {
    if (expiry_time >= 0 && it->meta.expiry_time != expiry_time) {
      return;
    }
    this->item_map.erase(it);
    this->dealloc_entry(it);
  }
}

template <class C>
void
RefCountCachePartition<C>::dealloc_entry(hash_type::iterator ptr)
{
  // decrement usage are not cleaned up. The values are not touched in this method, therefore it is safe
  // counters
  this->size -= ptr->meta.size;
  this->items--;

  Metrics::Gauge::decrement(this->rsb->refcountcache_current_size, ptr->meta.size);
  Metrics::Gauge::decrement(this->rsb->refcountcache_current_items);

  // remove from expiry queue
  if (ptr->expiry_entry != nullptr) {
    Dbg(dbg_ctl, "partition %d deleting item from expiry_queue idx=%d", this->part_num, ptr->expiry_entry->index);

    this->expiry_queue.erase(ptr->expiry_entry);
    expiryQueueEntry.free(ptr->expiry_entry);
    ptr->expiry_entry = nullptr; // To avoid the destruction of `l` calling the destructor again-- and causing issues
  }

  RefCountCacheHashEntry::free<C>(ptr);
}

template <class C>
void
RefCountCachePartition<C>::clear()
{
  // Since the hash nodes embed the list pointers, you can't iterate over the
  // hash elements and deallocate them, let alone remove them from the hash.
  // Hence, this monstrosity.
  auto it = this->item_map.begin();
  while (it != this->item_map.end()) {
    auto cur = it++;

    this->item_map.erase(cur);
    this->dealloc_entry(cur);
  }
}

// Are we full?
template <class C>
bool
RefCountCachePartition<C>::is_full() const
{
  Dbg(dbg_ctl, "partition %d is full? items %d/%d size %" PRIu64 "/%" PRIu64 "\n\n", this->part_num, this->items, this->max_items,
      this->size, this->max_size);
  return (this->max_items > 0 && this->items >= this->max_items) || (this->max_size > 0 && this->size >= this->max_size);
}

// Attempt to make space for item of `size`
template <class C>
bool
RefCountCachePartition<C>::make_space_for(unsigned int size)
{
  ink_time_t now = ink_time();
  while (this->is_full() || (size > 0 && this->size + size > this->max_size)) {
    PriorityQueueEntry<RefCountCacheHashEntry *> *top_item = expiry_queue.top();
    // if there is nothing in the expiry queue, then we can't make space
    if (top_item == nullptr) {
      return false;
    }

    // If the first item has expired, lets evict it, and then go around again
    if (top_item->node->meta.expiry_time < now) {
      this->erase(top_item->node->meta.key);
    } else { // if the first item isn't expired-- the rest won't be either (queue is sorted)
      return false;
    }
  }
  return true;
}

template <class C>
size_t
RefCountCachePartition<C>::count() const
{
  return this->items;
}

template <class C>
void
RefCountCachePartition<C>::copy(std::vector<RefCountCacheHashEntry *> &items)
{
  for (auto &&it : this->item_map) {
    RefCountCacheHashEntry *val = RefCountCacheHashEntry::alloc();
    val->set(it.item.get(), it.meta.key, it.meta.size, it.meta.expiry_time);
    items.push_back(val);
  }
}

template <class C>
swoc::IntrusiveHashMap<RefCountCacheLinkage> &
RefCountCachePartition<C>::get_map()
{
  return this->item_map;
}

// The header for the cache, this is used to check if the serialized cache is compatible
class RefCountCacheHeader
{
public:
  unsigned int      magic = REFCOUNTCACHE_MAGIC_NUMBER;
  ts::VersionNumber version{REFCOUNTCACHE_VERSION};
  ts::VersionNumber object_version; // version passed in of whatever it is we are caching

  RefCountCacheHeader(ts::VersionNumber object_version = ts::VersionNumber());
  bool operator==(RefCountCacheHeader const &that) const;
  bool compatible(RefCountCacheHeader *that) const;
};

// RefCountCache is a ref-counted key->value map to store classes that inherit from RefCountObj.
// Once an item is `put` into the cache, the cache will maintain a Ptr<> to that object until erase
// or clear is called-- which will remove the cache's Ptr<> to the object.
//
// This cache may be Persisted (RefCountCacheSync) as well as loaded from disk (LoadRefCountCacheFromPath).
// This class will optionally emit metrics at the given `metrics_prefix`.
//
// Note: although this cache does allow you to set expiry times this cache does not actively GC itself-- meaning
// it will only remove expired items once the space is required. So to ensure that the cache is bounded either a
// size or an item limit must be set-- otherwise the cache will not GC.
//
// Also note, that if keys collide the previous
// entry for a given key will be removed, so this "leak" concern is assuming you don't have sufficient space to store
// an item for each possible key
template <class C> class RefCountCache
{
public:
  // Constructor
  RefCountCache(unsigned int num_partitions, int size = -1, int items = -1, ts::VersionNumber object_version = ts::VersionNumber(),
                const std::string &metrics_prefix = ".refcountcache");
  // Destructor
  ~RefCountCache();

  // User interface to the cache
  Ptr<C> get(uint64_t key);
  void   put(uint64_t key, C *item, int size = 0, ink_time_t expiry_time = -1);
  void   erase(uint64_t key);
  void   clear();

  // Some methods to get some internal state
  int                        partition_for_key(uint64_t key);
  ts::shared_mutex          &lock_for_key(uint64_t key);
  size_t                     partition_count() const;
  RefCountCachePartition<C> &get_partition(int pnum);
  size_t                     count() const;
  RefCountCacheHeader       &get_header();
  RefCountCacheBlock        *get_rsb();

private:
  int                                                     max_size;  // Total size
  int                                                     max_items; // Total number of items allowed
  unsigned int                                            num_partitions;
  std::vector<std::unique_ptr<RefCountCachePartition<C>>> partitions;
  // Header
  RefCountCacheHeader header; // Our header
  RefCountCacheBlock  rsb;
};

template <class C>
RefCountCache<C>::RefCountCache(unsigned int num_partitions, int size, int items, ts::VersionNumber object_version,
                                const std::string &metrics_prefix)
  : header(RefCountCacheHeader(object_version))
{
  this->max_size       = size;
  this->max_items      = items;
  this->num_partitions = num_partitions;

  this->rsb.refcountcache_current_items        = Metrics::Gauge::createPtr((metrics_prefix + "current_items").c_str());
  this->rsb.refcountcache_current_size         = Metrics::Gauge::createPtr((metrics_prefix + "current_size").c_str());
  this->rsb.refcountcache_total_inserts        = Metrics::Counter::createPtr((metrics_prefix + "total_inserts").c_str());
  this->rsb.refcountcache_total_failed_inserts = Metrics::Counter::createPtr((metrics_prefix + "total_failed_inserts").c_str());
  this->rsb.refcountcache_total_lookups        = Metrics::Counter::createPtr((metrics_prefix + "total_lookups").c_str());
  this->rsb.refcountcache_total_hits           = Metrics::Counter::createPtr((metrics_prefix + "total_hits").c_str());
  this->rsb.refcountcache_last_sync_time       = Metrics::Counter::createPtr((metrics_prefix + "last_sync.time").c_str());
  this->rsb.refcountcache_last_total_items     = Metrics::Counter::createPtr((metrics_prefix + "last_sync.total_items").c_str());
  this->rsb.refcountcache_last_total_size      = Metrics::Counter::createPtr((metrics_prefix + "last_sync.total_size").c_str());

  // Now lets create all the partitions
  this->partitions.reserve(num_partitions);
  for (unsigned int i = 0; i < num_partitions; i++) {
    this->partitions.push_back(
      std::make_unique<RefCountCachePartition<C>>(i, size / num_partitions, items / num_partitions, &this->rsb));
  }
}

// Deconstruct the class
template <class C> RefCountCache<C>::~RefCountCache()
{
  num_partitions = 0;
}

template <class C>
Ptr<C>
RefCountCache<C>::get(uint64_t key)
{
  return this->partitions[this->partition_for_key(key)]->get(key);
}

template <class C>
void
RefCountCache<C>::put(uint64_t key, C *item, int size, ink_time_t expiry_time)
{
  return this->partitions[this->partition_for_key(key)]->put(key, item, size, expiry_time);
}

// Pick a partition for a given item
template <class C>
int
RefCountCache<C>::partition_for_key(uint64_t key)
{
  return key % this->num_partitions;
}

template <class C>
RefCountCacheHeader &
RefCountCache<C>::get_header()
{
  return this->header;
}

template <class C>
ts::shared_mutex &
RefCountCache<C>::lock_for_key(uint64_t key)
{
  return this->partitions[this->partition_for_key(key)]->lock;
}

template <class C>
RefCountCachePartition<C> &
RefCountCache<C>::get_partition(int pnum)
{
  return *this->partitions[pnum];
}

template <class C>
size_t
RefCountCache<C>::count() const
{
  size_t c = 0;
  for (unsigned int i = 0; i < this->num_partitions; i++) {
    c += this->partitions[i]->count();
  }
  return c;
}

template <class C>
size_t
RefCountCache<C>::partition_count() const
{
  return this->num_partitions;
}

template <class C>
RefCountCacheBlock *
RefCountCache<C>::get_rsb()
{
  return &this->rsb;
}

template <class C>
void
RefCountCache<C>::erase(uint64_t key)
{
  this->partitions[this->partition_for_key(key)]->erase(key);
}

template <class C>
void
RefCountCache<C>::clear()
{
  for (unsigned int i = 0; i < this->num_partitions; i++) {
    this->partitions[i]->clear();
  }
}

// Fill `cache` with items in file `filepath` using `load_func` to unmarshall the record.
// Errors are -1
template <typename CacheEntryType>
int
LoadRefCountCacheFromPath(RefCountCache<CacheEntryType> &cache, const std::string &filepath,
                          CacheEntryType *(*load_func)(char *, unsigned int))
{
  // If we have no load method, then we can't load anything so lets just stop right here
  if (load_func == nullptr) {
    return -1; // TODO: some specific error code
  }

  int fd = open(filepath.c_str(), O_RDONLY);
  if (fd < 0) {
    Warning("Unable to open file %s; [Error]: %s", filepath.c_str(), strerror(errno));
    return -1;
  }

  // read in the header
  RefCountCacheHeader tmpHeader = RefCountCacheHeader();
  int                 read_ret  = read(fd, reinterpret_cast<char *>(&tmpHeader), sizeof(RefCountCacheHeader));
  if (read_ret != sizeof(RefCountCacheHeader)) {
    UnixSocket{fd}.close();
    Warning("Error reading cache header from disk (expected %ld): %d", sizeof(RefCountCacheHeader), read_ret);
    return -1;
  }
  if (!cache.get_header().compatible(&tmpHeader)) {
    UnixSocket{fd}.close();
    Warning("Incompatible cache at %s, not loading.", filepath.c_str());
    return -1; // TODO: specific code for incompatible
  }

  RefCountCacheItemMeta tmpValue = RefCountCacheItemMeta(0, 0);
  while (true) { // TODO: better loop
    read_ret = read(fd, reinterpret_cast<char *>(&tmpValue), sizeof(tmpValue));
    if (read_ret != sizeof(tmpValue)) {
      break;
    }
    char buf[tmpValue.size];
    read_ret = read(fd, reinterpret_cast<char *>(&buf), tmpValue.size);
    if (read_ret != static_cast<int>(tmpValue.size)) {
      Warning("Encountered error reading item from cache: %d", read_ret);
      break;
    }

    CacheEntryType *newItem = load_func(reinterpret_cast<char *>(&buf), tmpValue.size);
    if (newItem != nullptr) {
      cache.put(tmpValue.key, newItem, tmpValue.size - sizeof(CacheEntryType));
    }
  };

  UnixSocket{fd}.close();
  return 0;
}
