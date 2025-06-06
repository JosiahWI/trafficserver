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

#pragma once

#include "iocore/eventsystem/EventSystem.h"
#include "iocore/cache/CacheDefs.h"
#include "iocore/cache/HttpConfigAccessor.h"

static constexpr ts::ModuleVersion CACHE_MODULE_VERSION(1, 0);

#define CACHE_WRITE_OPT_OVERWRITE      0x0001
#define CACHE_WRITE_OPT_CLOSE_COMPLETE 0x0002
#define CACHE_WRITE_OPT_SYNC           (CACHE_WRITE_OPT_CLOSE_COMPLETE | 0x0004)
#define CACHE_WRITE_OPT_OVERWRITE_SYNC (CACHE_WRITE_OPT_SYNC | CACHE_WRITE_OPT_OVERWRITE)

#define SCAN_KB_PER_SECOND 8192 // 1TB/8MB = 131072 = 36 HOURS to scan a TB

#define RAM_CACHE_ALGORITHM_CLFUS 0
#define RAM_CACHE_ALGORITHM_LRU   1

#define CACHE_COMPRESSION_NONE    0
#define CACHE_COMPRESSION_FASTLZ  1
#define CACHE_COMPRESSION_LIBZ    2
#define CACHE_COMPRESSION_LIBLZMA 3

enum { RAM_HIT_COMPRESS_NONE = 1, RAM_HIT_COMPRESS_FASTLZ, RAM_HIT_COMPRESS_LIBZ, RAM_HIT_COMPRESS_LIBLZMA, RAM_HIT_LAST_ENTRY };

struct CacheVC;
class CacheEvacuateDocVC;
struct CacheDisk;
class URL;
class HTTPHdr;
class HTTPInfo;

using CacheHTTPHdr  = HTTPHdr;
using CacheURL      = URL;
using CacheHTTPInfo = HTTPInfo;

struct CacheProcessor : public Processor {
  CacheProcessor()
    : min_stripe_version(CACHE_DB_MAJOR_VERSION, CACHE_DB_MINOR_VERSION),
      max_stripe_version(CACHE_DB_MAJOR_VERSION, CACHE_DB_MINOR_VERSION)

  {
  }

  int         start(int n_cache_threads = 0, size_t stacksize = DEFAULT_STACKSIZE) override;
  virtual int start_internal(int flags = 0);
  void        stop();

  int dir_check(bool fix);

  Action *lookup(Continuation *cont, const CacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_NONE,
                 std::string_view hostname = std::string_view{});
  Action *open_read(Continuation *cont, const CacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_NONE,
                    std::string_view hostname = std::string_view{});
  Action *open_write(Continuation *cont, CacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_NONE,
                     int expected_size = CACHE_EXPECTED_SIZE, int options = 0, time_t pin_in_cache = 0,
                     std::string_view hostname = std::string_view{});
  Action *remove(Continuation *cont, const CacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_NONE,
                 std::string_view hostname = std::string_view{});
  Action *scan(Continuation *cont, std::string_view hostname = std::string_view{}, int KB_per_second = SCAN_KB_PER_SECOND);
  Action *lookup(Continuation *cont, const HttpCacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_HTTP);
  Action *open_read(Continuation *cont, const HttpCacheKey *key, CacheHTTPHdr *request, const HttpConfigAccessor *params,
                    CacheFragType frag_type = CACHE_FRAG_TYPE_HTTP);
  Action *open_write(Continuation *cont, const HttpCacheKey *key, CacheHTTPInfo *old_info, time_t pin_in_cache = 0,
                     CacheFragType frag_type = CACHE_FRAG_TYPE_HTTP);
  Action *remove(Continuation *cont, const HttpCacheKey *key, CacheFragType frag_type = CACHE_FRAG_TYPE_HTTP);

  /** Mark physical disk/device/file as offline.
      All stripes for this device are disabled.

      @return @c true if there are any storage devices remaining online, @c false if not.

      @note This is what is called if a disk is disabled due to I/O errors.
  */
  bool mark_storage_offline(CacheDisk *d, bool admin = false);

  /** Find the storage for a @a path.
      If @a len is 0 then @a path is presumed null terminated.
      @return @c nullptr if the path does not match any defined storage.
   */
  CacheDisk *find_by_path(std::string_view path = std::string_view{});

  /** Check if there are any online storage devices.
      If this returns @c false then the cache should be disabled as there is no storage available.
  */
  bool has_online_storage() const;

  static CacheInitState IsCacheEnabled();

  static bool IsCacheReady(CacheFragType type);

  /// Type for callback function.
  using CALLBACK_FUNC = void (*)();
  /** Lifecycle callback.

      The function @a cb is called after cache initialization has
      finished and the cache is ready or has failed.

      @internal If we need more lifecycle callbacks, this should be
      generalized ala the standard hooks style, with a type enum used
      to specific the callback type and passed to the callback
      function.
  */
  void afterInitCallbackSet(CALLBACK_FUNC cb);

  // private members
  void diskInitialized();

  void cacheInitialized();

  int
  waitForCache() const
  {
    return wait_for_cache;
  }

  static uint32_t       cache_ready;
  static CacheInitState initialized;
  static int            start_done;
  static bool           clear;
  static bool           fix;
  static bool           check;
  static int            start_internal_flags;
  static int            auto_clear_flag;

  ts::VersionNumber min_stripe_version;
  ts::VersionNumber max_stripe_version;

  CALLBACK_FUNC cb_after_init  = nullptr;
  int           wait_for_cache = 0;
};

inline void
CacheProcessor::afterInitCallbackSet(CALLBACK_FUNC cb)
{
  cb_after_init = cb;
}

struct CacheVConnection : public VConnection {
  VIO         *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override                           = 0;
  virtual VIO *do_io_pread(Continuation *c, int64_t nbytes, MIOBuffer *buf, int64_t offset)                   = 0;
  VIO         *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override = 0;
  void         do_io_close(int lerrno = -1) override                                                          = 0;
  void         reenable(VIO *avio) override                                                                   = 0;
  void         reenable_re(VIO *avio) override                                                                = 0;
  void
  do_io_shutdown(ShutdownHowTo_t /* howto ATS_UNUSED */) override
  {
    ink_assert(!"CacheVConnection::do_io_shutdown unsupported");
  }

  virtual int get_header(void **ptr, int *len)      = 0;
  virtual int set_header(void *ptr, int len)        = 0;
  virtual int get_single_data(void **ptr, int *len) = 0;

  virtual void set_http_info(CacheHTTPInfo *info)  = 0;
  virtual void get_http_info(CacheHTTPInfo **info) = 0;

  virtual bool    is_ram_cache_hit() const   = 0;
  virtual bool    set_pin_in_cache(time_t t) = 0;
  virtual time_t  get_pin_in_cache()         = 0;
  virtual int64_t get_object_size()          = 0;
  virtual bool
  is_compressed_in_ram() const
  {
    return false;
  }

  virtual int
  get_volume_number() const
  {
    return -1;
  }

  virtual const char *
  get_disk_path() const
  {
    return nullptr;
  }

  /** Test if the VC can support pread.
      @return @c true if @c do_io_pread will work, @c false if not.
  */
  virtual bool is_pread_capable() = 0;

  CacheVConnection();
};

void                  ink_cache_init(ts::ModuleVersion version);
extern CacheProcessor cacheProcessor;
extern Continuation  *cacheRegexDeleteCont;
