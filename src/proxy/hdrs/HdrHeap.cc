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

   HdrBuf.cc

   Description:


 ****************************************************************************/

#include "tscore/ink_platform.h"
#include "tscore/Diags.h"
#include "proxy/hdrs/HdrHeap.h"
#include "proxy/hdrs/URL.h"
#include "proxy/hdrs/MIME.h"
#include "proxy/hdrs/HTTP.h"
#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/Thread.h"

static constexpr size_t   MAX_LOST_STR_SPACE      = 1024;
static constexpr uint32_t MAX_HDR_HEAP_OBJ_LENGTH = (1 << 20) - 1; ///< m_length is 20 bit

Allocator hdrHeapAllocator("hdrHeap", HdrHeap::DEFAULT_SIZE);
Allocator strHeapAllocator("hdrStrHeap", HdrStrHeap::DEFAULT_SIZE);

namespace
{
DbgCtl dbg_ctl_http{"http"};

} // end anonymous namespace

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
obj_describe(HdrHeapObjImpl *obj, bool recurse)
{
  static const char *obj_names[] = {"EMPTY", "RAW", "URL", "HTTP_HEADER", "MIME_HEADER", "FIELD_BLOCK"};

  Dbg(dbg_ctl_http, "%s %p: [T: %d, L: %4d, OBJFLAGS: %X]  ", obj_names[obj->m_type], obj, obj->m_type, obj->m_length,
      obj->m_obj_flags);

  switch (static_cast<HdrHeapObjType>(obj->m_type)) {
  case HdrHeapObjType::EMPTY:
    break;
  case HdrHeapObjType::RAW:
    break;
  case HdrHeapObjType::MIME_HEADER:
    mime_hdr_describe(obj, recurse);
    break;
  case HdrHeapObjType::FIELD_BLOCK:
    mime_field_block_describe(obj, recurse);
    break;
  case HdrHeapObjType::HTTP_HEADER:
    http_hdr_describe(obj, recurse);
    break;
  case HdrHeapObjType::URL:
    url_describe(obj, recurse);
    break;
  default:
    break;
  }
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

inline void
HdrHeap::init()
{
  m_data_start = m_free_start = (reinterpret_cast<char *>(this)) + HDR_HEAP_HDR_SIZE;
  m_magic                     = HdrBufMagic::ALIVE;
  m_writeable                 = true;

  m_next      = nullptr;
  m_free_size = m_size - HDR_HEAP_HDR_SIZE;

  // We need to clear m_ptr directly since it's garbage and
  //  using the operator functions will to free() what ever
  //  garbage it is pointing to
  m_read_write_heap.detach();

  for (auto &i : m_ronly_heap) {
    i.m_heap_start = nullptr;
    i.m_ref_count_ptr.detach();
    i.m_locked   = false;
    i.m_heap_len = 0;
  }
  m_lost_string_space = 0;

  ink_assert(m_free_size > 0);
}

HdrHeap *
new_HdrHeap(int size)
{
  HdrHeap *h;
  if (size <= HdrHeap::DEFAULT_SIZE) {
    size = HdrHeap::DEFAULT_SIZE;
    h    = static_cast<HdrHeap *>(THREAD_ALLOC(hdrHeapAllocator, this_ethread()));
  } else {
    h = static_cast<HdrHeap *>(ats_malloc(size));
  }

  h->m_size = size;
  h->init();

  return h;
}

HdrStrHeap *
HdrStrHeap::alloc(int heap_size)
{
  // The callee is asking for a string heap to be created
  //  that can allocate at least size bytes.  As such we,
  //  need to include the size of the string heap header in
  //  our calculations

  int alloc_size = heap_size + sizeof(HdrStrHeap);

  HdrStrHeap *sh;
  if (alloc_size <= HdrStrHeap::DEFAULT_SIZE) {
    alloc_size = HdrStrHeap::DEFAULT_SIZE;
    sh         = static_cast<HdrStrHeap *>(THREAD_ALLOC(strHeapAllocator, this_ethread()));
  } else {
    alloc_size = swoc::round_up<HdrStrHeap::DEFAULT_SIZE * 2>(alloc_size);
    sh         = static_cast<HdrStrHeap *>(ats_malloc(alloc_size));
  }

  // Placement new the HdrStrHeap.
  sh = new (sh) HdrStrHeap(alloc_size);

  sh->_avail_size = alloc_size - sizeof(HdrStrHeap);

  ink_assert(sh->refcount() == 0);

  ink_assert(int(sh->total_size()) == alloc_size);

  ink_assert(sh->_avail_size > 0);

  return sh;
}

void
HdrHeap::destroy()
{
  if (m_next) {
    m_next->destroy();
  }

  m_read_write_heap = nullptr;
  for (auto &i : m_ronly_heap) {
    i.m_ref_count_ptr = nullptr;
  }

  if (m_size == HdrHeap::DEFAULT_SIZE) {
    THREAD_FREE(this, hdrHeapAllocator, this_thread());
  } else {
    ats_free(this);
  }
}

HdrHeapObjImpl *
HdrHeap::allocate_obj(int nbytes, HdrHeapObjType type)
{
  char           *new_space;
  HdrHeapObjImpl *obj;

  ink_assert(m_writeable);

  nbytes = HdrHeapMarshalBlocks{swoc::round_up(nbytes)};

  if (nbytes > static_cast<int>(HDR_MAX_ALLOC_SIZE)) {
    ink_assert(!"alloc too big");
    return nullptr;
  }

  HdrHeap *h = this;

  while (true) {
    if (static_cast<unsigned>(nbytes) <= (h->m_free_size)) {
      new_space        = h->m_free_start;
      h->m_free_start += nbytes;
      h->m_free_size  -= nbytes;

      obj = reinterpret_cast<HdrHeapObjImpl *>(new_space);
      obj_init_header(obj, type, nbytes, 0);
      ink_assert(obj_is_aligned(obj));

      return obj;
    }

    if (h->m_next == nullptr) {
      // Allocate our next pointer heap
      //   twice as large as this one so
      //   number of pointer heaps is O(log n)
      //   with regard to number of bytes allocated
      h->m_next = new_HdrHeap(h->m_size * 2);
    }

    h = h->m_next;
  }
}

void
HdrHeap::deallocate_obj(HdrHeapObjImpl *obj)
{
  ink_assert(m_writeable);
  obj->m_type = static_cast<uint32_t>(HdrHeapObjType::EMPTY);
}

char *
HdrHeap::allocate_str(int nbytes)
{
  int last_size = 0;
  int next_size = 0;
  ink_assert(m_writeable);

  // INKqa08287 - We could get infinite build up
  //   of dead strings on header merge.  To prevent
  //   this we keep track of the dead string space
  //   and force a heap coalesce if it is too large.
  //   Ideally this should be done on free_string()
  //   but I already no that this code path is
  //   safe for forcing a str coalesce so I'm doing
  //   it here for sanity's sake
  int coalesce = m_lost_string_space > static_cast<int>(MAX_LOST_STR_SPACE) ? 1 : 0;

  for (;;) {
    if (coalesce) {
      switch (coalesce) {
      case 2:
        Warning("HdrHeap=%p coalescing twice", this);
        break;
      case 3:
        Warning("HdrHeap=%p coalescing three or more times", this);
        break;
      default:
        break;
      }

      coalesce_str_heaps();
    }
    do {
      // First check to see if we have a read/write
      //   string heap
      if (!m_read_write_heap) {
        if (next_size) {
          Warning("HdrHeap=%p new read/write string heap twice last_size=%d", this, last_size);
        }
        next_size         = (last_size * 2) - int(sizeof(HdrStrHeap));
        next_size         = next_size > nbytes ? next_size : nbytes;
        m_read_write_heap = HdrStrHeap::alloc(next_size);
      }
      // Try to allocate of our read/write string heap
      if (char *new_space = m_read_write_heap->allocate(nbytes); new_space) {
        return new_space;
      }

      last_size = m_read_write_heap->total_size();

      // Our existing rw str heap doesn't have sufficient
      //  capacity.  We need to move the current rw heap
      //  out of the way and create a new one
    } while (demote_rw_str_heap() == 0);

    // We failed to demote.  We'll have to coalesce the heaps.
    ++coalesce;
    next_size = 0;
  }
}

// char* HdrHeap::expand_str(const char* old_str, int old_len, int new_len)
//
//   Attempt to grow an already allocated string.  For this to work,
//      the string  has to be the last one in the read-write string
//      heap and there has to be enough space that string heap
//   If expansion succeeds, we return old_str.  If it fails, we
//      return NULL
//
char *
HdrHeap::expand_str(const char *old_str, int old_len, int new_len)
{
  if (m_read_write_heap && m_read_write_heap->contains(old_str)) {
    return m_read_write_heap->expand(const_cast<char *>(old_str), old_len, new_len);
  }

  return nullptr;
}

// char* HdrHeap::duplicate_str(char* str, int nbytes)
//
//  Allocates a new string and copies the old data.
//  Returns the new string pointer.
//
char *
HdrHeap::duplicate_str(const char *str, int nbytes)
{
  HeapGuard guard(this, str); // Don't let the source get de-allocated.
  char     *new_str = allocate_str(nbytes);

  memcpy(new_str, str, nbytes);
  return (new_str);
}

// int HdrHeap::demote_rw_str_heap()
//
//  Returns 0 on success and non-zero failure
//   Failure means all the read only heap slots
//   were full
//
int
HdrHeap::demote_rw_str_heap()
{
  // First, see if we have any open slots for read
  //  only heaps
  for (auto &i : m_ronly_heap) {
    if (i.m_heap_start == nullptr) {
      // We've found a slot
      i.m_ref_count_ptr = m_read_write_heap.object();
      i.m_heap_start    = reinterpret_cast<char *>(m_read_write_heap.get());
      i.m_heap_len      = m_read_write_heap->total_size() - m_read_write_heap->space_avail();

      //          Dbg(dbg_ctl_hdrs, "Demoted rw heap of %d size", m_read_write_heap->total_size());
      m_read_write_heap = nullptr;
      return 0;
    }
  }

  // No open slots
  return 1;
}

// void HdrHeap::coalesce_heaps()
//
//    Take existing stringheaps and combine them to free up
//      slots in the heap array
//
//  FIX ME: Should we combine a subset of the heaps
//     or all of them?  Current plan is combine all heaps
//     since saves doing bounds checks every string.  At
//     expense of doing far more copying
//
void
HdrHeap::coalesce_str_heaps(int incoming_size)
{
  int new_heap_size = incoming_size;
  ink_assert(incoming_size >= 0);
  ink_assert(m_writeable);

  new_heap_size += required_space_for_evacuation();

  HdrStrHeap *new_heap = HdrStrHeap::alloc(new_heap_size);
  evacuate_from_str_heaps(new_heap);
  m_lost_string_space = 0;

  // At this point none of the currently used string
  //  heaps are needed since everything is in the
  //  new string heap.  So deallocate all the old heaps
  m_read_write_heap = new_heap;

  int heaps_removed = 0;
  for (auto &j : m_ronly_heap) {
    if (j.m_heap_start != nullptr && j.m_locked == false) {
      j.m_ref_count_ptr = nullptr;
      j.m_heap_start    = nullptr;
      j.m_heap_len      = 0;
      heaps_removed++;
    }
  }

  // This function is presumed to free up read only
  //   string heap slots or be for incoming heaps
  //   If we don't have any free heaps, we are screwed
  ink_assert(heaps_removed > 0 || incoming_size > 0 || m_ronly_heap[0].m_heap_start == nullptr);
}

void
HdrHeap::evacuate_from_str_heaps(HdrStrHeap *new_heap)
{
  //    printf("Str Evac\n");
  // Loop over the objects in heap and call the evacuation
  //  function in each one
  HdrHeap *h = this;
  ink_assert(m_writeable);

  while (h) {
    char *data = h->m_data_start;

    while (data < h->m_free_start) {
      HdrHeapObjImpl *obj = reinterpret_cast<HdrHeapObjImpl *>(data);

      // Object length cannot be 0 by design, otherwise something is wrong + infinite loop here!
      ink_release_assert(0 != obj->m_length);

      switch (static_cast<HdrHeapObjType>(obj->m_type)) {
      case HdrHeapObjType::URL:
        ((URLImpl *)obj)->move_strings(new_heap);
        break;
      case HdrHeapObjType::HTTP_HEADER:
        ((HTTPHdrImpl *)obj)->move_strings(new_heap);
        break;
      case HdrHeapObjType::MIME_HEADER:
        ((MIMEHdrImpl *)obj)->move_strings(new_heap);
        break;
      case HdrHeapObjType::FIELD_BLOCK:
        ((MIMEFieldBlockImpl *)obj)->move_strings(new_heap);
        break;
      case HdrHeapObjType::EMPTY:
      case HdrHeapObjType::RAW:
        // Nothing to do
        break;
      default:
        ink_release_assert(0);
      }

      data = data + obj->m_length;
    }

    h = h->m_next;
  }
}

size_t
HdrHeap::required_space_for_evacuation()
{
  size_t   ret = 0;
  HdrHeap *h   = this;
  while (h) {
    char           *data     = h->m_data_start;
    HdrHeapObjImpl *prev_obj = nullptr;

    while (data < h->m_free_start) {
      HdrHeapObjImpl *obj = reinterpret_cast<HdrHeapObjImpl *>(data);

      // Object length cannot be 0 by design, otherwise something is wrong + infinite loop here!
      ink_release_assert(0 != obj->m_length);

      switch (static_cast<HdrHeapObjType>(obj->m_type)) {
      case HdrHeapObjType::URL:
        ret += ((URLImpl *)obj)->strings_length();
        break;
      case HdrHeapObjType::HTTP_HEADER:
        ret += ((HTTPHdrImpl *)obj)->strings_length();
        break;
      case HdrHeapObjType::MIME_HEADER:
        ret += ((MIMEHdrImpl *)obj)->strings_length();
        break;
      case HdrHeapObjType::FIELD_BLOCK:
        ret += ((MIMEFieldBlockImpl *)obj)->strings_length();
        break;
      case HdrHeapObjType::EMPTY:
      case HdrHeapObjType::RAW:
        // Nothing to do
        break;
      default:
        ink_release_assert(0);
      }

      // coalesce empty objects next to each other
      if (static_cast<HdrHeapObjType>(obj->m_type) == HdrHeapObjType::EMPTY) {
        if (prev_obj != nullptr && prev_obj->m_length < (MAX_HDR_HEAP_OBJ_LENGTH - obj->m_length)) {
          prev_obj->m_length += obj->m_length;
          ink_release_assert(prev_obj->m_length > 0);
        } else {
          prev_obj = obj;
        }
      } else {
        prev_obj = nullptr;
      }

      data = data + obj->m_length;
    }
    h = h->m_next;
  }
  return ret;
}

void
HdrHeap::sanity_check_strs()
{
  int              num_heaps = 0;
  struct HeapCheck heaps[HDR_BUF_RONLY_HEAPS + 1];

  // Build up a string check table
  if (m_read_write_heap) {
    heaps[num_heaps].start = (reinterpret_cast<char *>(m_read_write_heap.get())) + sizeof(HdrStrHeap);

    int heap_size = m_read_write_heap->total_size() - (sizeof(HdrStrHeap) + m_read_write_heap->space_avail());

    heaps[num_heaps].end = heaps[num_heaps].start + heap_size;
    num_heaps++;
  }

  for (auto &i : m_ronly_heap) {
    if (i.m_heap_start != nullptr) {
      heaps[num_heaps].start = i.m_heap_start;
      heaps[num_heaps].end   = i.m_heap_start + i.m_heap_len;
      num_heaps++;
    }
  }

  // Loop over the objects in heap call the check
  //   function on each one
  HdrHeap *h = this;

  while (h) {
    char *data = h->m_data_start;

    while (data < h->m_free_start) {
      HdrHeapObjImpl *obj = reinterpret_cast<HdrHeapObjImpl *>(data);

      // Object length cannot be 0 by design, otherwise something is wrong + infinite loop here!
      ink_release_assert(0 != obj->m_length);

      switch (static_cast<HdrHeapObjType>(obj->m_type)) {
      case HdrHeapObjType::URL:
        ((URLImpl *)obj)->check_strings(heaps, num_heaps);
        break;
      case HdrHeapObjType::HTTP_HEADER:
        ((HTTPHdrImpl *)obj)->check_strings(heaps, num_heaps);
        break;
      case HdrHeapObjType::MIME_HEADER:
        ((MIMEHdrImpl *)obj)->check_strings(heaps, num_heaps);
        break;
      case HdrHeapObjType::FIELD_BLOCK:
        ((MIMEFieldBlockImpl *)obj)->check_strings(heaps, num_heaps);
        break;
      case HdrHeapObjType::EMPTY:
      case HdrHeapObjType::RAW:
        // Nothing to do
        break;
      default:
        ink_release_assert(0);
      }

      data = data + obj->m_length;
    }

    h = h->m_next;
  }
}

// int HdrHeap::marshal_length()
//
//  Determines what the length of a buffer needs to
//   be to marshal this header
//
int
HdrHeap::marshal_length()
{
  int len;

  // If there is more than one HdrHeap block, we'll
  //  coalesce the HdrHeap blocks together so we
  //  only need one block header
  len        = HDR_HEAP_HDR_SIZE;
  HdrHeap *h = this;

  while (h) {
    len += static_cast<int>(h->m_free_start - h->m_data_start);
    h    = h->m_next;
  }

  // Since when we unmarshal, we won't have a writable string
  //  heap, we can drop the header on the read/write
  //  string heap
  if (m_read_write_heap) {
    len += m_read_write_heap->total_size() - (sizeof(HdrStrHeap) + m_read_write_heap->space_avail());
  }

  for (auto &j : m_ronly_heap) {
    if (j.m_heap_start != nullptr) {
      len += j.m_heap_len;
    }
  }

  len = HdrHeapMarshalBlocks(swoc::round_up(len));
  return len;
}

#ifdef HDR_HEAP_CHECKSUMS
static uint32_t
compute_checksum(void *buf, int len)
{
  uint32_t cksum = 0;

  while (len > 4) {
    cksum += *((uint32_t *)buf);
    buf    = ((char *)buf) + 4;
    len   -= 4;
  }

  if (len > 0) {
    uint32_t tmp = 0;
    memcpy((char *)&tmp, buf, len);
    cksum += tmp;
  }

  return cksum;
}
#endif

// int HdrHeap::marshal(char* buf, int len)
//
//   Creates a marshalled representation of the contents
//     of HdrHeap.  The marshalled representation is ususable
//     as a read-only HdrHeap after an unmarshal operation which
//     only swizzles offsets to pointer.  Special care needs to be
//     taken not to mess up the alignment of objects in
//     the heap to make this representation usable in the read-only
//     form
//
int
HdrHeap::marshal(char *buf, int len)
{
  ink_assert((((uintptr_t)buf) & HDR_PTR_ALIGNMENT_MASK) == 0);

  HdrHeap *marshal_hdr = reinterpret_cast<HdrHeap *>(buf);
  char    *b           = buf + HDR_HEAP_HDR_SIZE;

  // Variables for the ptr translation table
  int           ptr_xl_size = 2;
  MarshalXlate  static_table[2];
  MarshalXlate *ptr_xlation = static_table;
  // need to initialize it here because of those gotos
  MarshalXlate str_xlation[HDR_BUF_RONLY_HEAPS + 1];

  // Let's start by skipping over the header block
  //  and copying the pointer blocks to marshalled
  //  buffer
  int ptr_heap_size = 0;
  int str_size      = 0;
  int ptr_heaps     = 0;
  int str_heaps     = 0;

  // Variables used later on.  Sunpro doesn't like
  //   bypassing initializations with gotos
  int used;

  HdrHeap *unmarshal_hdr = this;

  do {
    int copy_size = static_cast<int>(unmarshal_hdr->m_free_start - unmarshal_hdr->m_data_start);

    if (copy_size > len) {
      goto Failed;
    }
    memcpy(b, unmarshal_hdr->m_data_start, copy_size);

    // Expand ptr xlation table if necessary - shameless hackery
    if (ptr_heaps >= ptr_xl_size) {
      MarshalXlate *tmp_xl = static_cast<MarshalXlate *>(alloca(sizeof(MarshalXlate) * ptr_xl_size * 2));
      memcpy(tmp_xl, ptr_xlation, sizeof(MarshalXlate) * ptr_xl_size);
      ptr_xlation  = tmp_xl;
      ptr_xl_size *= 2;
    }
    // Add translation table entry for pointer heaps
    //   FIX ME - possible offset overflow issues?
    ptr_xlation[ptr_heaps].start  = unmarshal_hdr->m_data_start;
    ptr_xlation[ptr_heaps].end    = unmarshal_hdr->m_free_start;
    ptr_xlation[ptr_heaps].offset = unmarshal_hdr->m_data_start - (b - buf);

    ptr_heap_size += copy_size;
    b             += copy_size;
    len           -= copy_size;
    ptr_heaps++;

    unmarshal_hdr = unmarshal_hdr->m_next;
  } while (unmarshal_hdr);

  // Now that we've got the pointer blocks marshaled
  //  we can fill in the header on marshalled block
  marshal_hdr->m_free_start = nullptr;
  marshal_hdr->m_data_start = reinterpret_cast<char *>(HDR_HEAP_HDR_SIZE.value()); // offset
  marshal_hdr->m_magic      = HdrBufMagic::MARSHALED;
  marshal_hdr->m_writeable  = false;
  marshal_hdr->m_size       = ptr_heap_size + HDR_HEAP_HDR_SIZE;
  marshal_hdr->m_next       = nullptr;
  marshal_hdr->m_free_size  = 0;
  marshal_hdr->m_read_write_heap.detach();
  marshal_hdr->m_lost_string_space = this->m_lost_string_space;

  // We'have one read-only string heap after marshalling
  marshal_hdr->m_ronly_heap[0].m_heap_start = (char *)static_cast<intptr_t>(marshal_hdr->m_size); // offset
  marshal_hdr->m_ronly_heap[0].m_ref_count_ptr.detach();

  for (unsigned i = 1; i < HDR_BUF_RONLY_HEAPS; ++i) {
    marshal_hdr->m_ronly_heap[i].m_heap_start = nullptr;
  }

  // Next order of business is to copy over string heaps
  //   As we are copying over the string heaps, build
  //   translation table for string marshaling in the heap
  //   objects
  //
  // FIX ME - really ought to check to see if lost_string_space
  //   is too big and only copy over live strings if it is.  May
  //   not be too much of a problem since I've prevented too much
  //   lost string space both in string alloc and inherit

  if (m_read_write_heap) {
    char *copy_start = (reinterpret_cast<char *>(m_read_write_heap.get())) + sizeof(HdrStrHeap);
    int   nto_copy   = m_read_write_heap->total_size() - (sizeof(HdrStrHeap) + m_read_write_heap->space_avail());

    if (nto_copy > len) {
      goto Failed;
    }

    memcpy(b, copy_start, nto_copy);

    // FIX ME - possible offset overflow issues?
    str_xlation[str_heaps].start  = copy_start;
    str_xlation[str_heaps].end    = copy_start + nto_copy;
    str_xlation[str_heaps].offset = copy_start - (b - buf);

    b        += nto_copy;
    len      -= nto_copy;
    str_size += nto_copy;
    str_heaps++;
  }

  for (auto &i : m_ronly_heap) {
    if (i.m_heap_start != nullptr) {
      if (i.m_heap_len > len) {
        goto Failed;
      }

      memcpy(b, i.m_heap_start, i.m_heap_len);

      // Add translation table entry for string heaps
      //   FIX ME - possible offset overflow issues?
      str_xlation[str_heaps].start  = i.m_heap_start;
      str_xlation[str_heaps].end    = i.m_heap_start + i.m_heap_len;
      str_xlation[str_heaps].offset = str_xlation[str_heaps].start - (b - buf);
      ink_assert(str_xlation[str_heaps].start <= str_xlation[str_heaps].end);

      str_heaps++;
      b        += i.m_heap_len;
      len      -= i.m_heap_len;
      str_size += i.m_heap_len;
    }
  }

  // Patch the str heap len
  marshal_hdr->m_ronly_heap[0].m_heap_len = str_size;

  // Take our translation tables and loop over the objects
  //    and call the object marshal function to patch live
  //    strings pointers & live object pointers to offsets
  {
    char *obj_data  = (reinterpret_cast<char *>(marshal_hdr)) + HDR_HEAP_HDR_SIZE;
    char *mheap_end = (reinterpret_cast<char *>(marshal_hdr)) + marshal_hdr->m_size;

    while (obj_data < mheap_end) {
      HdrHeapObjImpl *obj = reinterpret_cast<HdrHeapObjImpl *>(obj_data);
      ink_assert(obj_is_aligned(obj));

      switch (static_cast<HdrHeapObjType>(obj->m_type)) {
      case HdrHeapObjType::URL:
        if (((URLImpl *)obj)->marshal(str_xlation, str_heaps) < 0) {
          goto Failed;
        }
        break;
      case HdrHeapObjType::HTTP_HEADER:
        if (((HTTPHdrImpl *)obj)->marshal(ptr_xlation, ptr_heaps, str_xlation, str_heaps) < 0) {
          goto Failed;
        }
        break;
      case HdrHeapObjType::FIELD_BLOCK:
        if (((MIMEFieldBlockImpl *)obj)->marshal(ptr_xlation, ptr_heaps, str_xlation, str_heaps) < 0) {
          goto Failed;
        }
        break;
      case HdrHeapObjType::MIME_HEADER:
        if (((MIMEHdrImpl *)obj)->marshal(ptr_xlation, ptr_heaps, str_xlation, str_heaps)) {
          goto Failed;
        }
        break;
      case HdrHeapObjType::EMPTY:
      case HdrHeapObjType::RAW:
        // Check to make sure we aren't stuck
        //   in an infinite loop
        if (obj->m_length <= 0) {
          ink_assert(0);
          goto Failed;
        }
        // Nothing to do
        break;
      default:
        ink_release_assert(0);
      }

      obj_data = obj_data + obj->m_length;
    }
  }

  // Add up the total bytes used
  used = ptr_heap_size + str_size + HDR_HEAP_HDR_SIZE;
  used = HdrHeapMarshalBlocks(swoc::round_up(used));

#ifdef HDR_HEAP_CHECKSUMS
  {
    uint32_t chksum           = compute_checksum(buf, used);
    marshal_hdr->m_free_start = (char *)chksum;
  }
#endif

  return used;

Failed:
  marshal_hdr->m_magic = HdrBufMagic::CORRUPT;
  return -1;
}

// bool HdrHeap::check_marshalled(char* buf, int buf_length)
//
//   Takes in marshalled buffer and verifies whether stuff appears
//     to be sane.  Returns true is sane.  Returns false if corrupt
//
bool
HdrHeap::check_marshalled(uint32_t buf_length)
{
  if (this->m_magic != HdrBufMagic::MARSHALED) {
    return false;
  }

  if (this->m_size < (uint32_t)HDR_HEAP_HDR_SIZE) {
    return false;
  }

  if (this->m_size != (uintptr_t)this->m_ronly_heap[0].m_heap_start) {
    return false;
  }

  if ((uintptr_t)(this->m_size + m_ronly_heap[0].m_heap_start) > buf_length) {
    return false;
  }

  if (this->m_writeable != false) {
    return false;
  }

  if (this->m_free_size != 0) {
    return false;
  }

  if (this->m_ronly_heap[0].m_heap_start == nullptr) {
    return false;
  }

  return true;
}

// int HdrHeap::unmarshal(int buf_length, int obj_type,
//                       HdrHeapObjImpl** found_obj,
//                       RefCountObj* block_ref)
//
//   Takes a marshalled representation and swizzles offsets
//     so they become live pointers and make the heap usable.
//     Sets *found_obj to first occurrence of object of
//     type obj_type in the heap
//
//   Return value is the number of bytes unmarshalled or -1
//     if error.  Caller is responsible for memory
//     management policy
//
int
HdrHeap::unmarshal(int buf_length, int obj_type, HdrHeapObjImpl **found_obj, RefCountObj *block_ref)
{
  *found_obj = nullptr;

  // Check out this heap and make sure it is OK
  if (m_magic != HdrBufMagic::MARSHALED) {
    ink_assert(!"HdrHeap::unmarshal bad magic");
    return -1;
  }

  int unmarshal_size = this->unmarshal_size();
  if (unmarshal_size > buf_length) {
    ink_assert(!"HdrHeap::unmarshal truncated header");
    return -1;
  }
#ifdef HDR_HEAP_CHECKSUMS
  if (m_free_start != NULL) {
    uint32_t stored_sum = (uint32_t)m_free_start;
    m_free_start        = NULL;
    int      sum_len    = ROUND(unmarshal_size, HDR_PTR_SIZE);
    uint32_t new_sum    = compute_checksum((void *)this, sum_len);

    if (stored_sum != new_sum) {
      fprintf(stderr, "WARNING: Unmarshal checksum comparison failed\n");
      dump_heap(unmarshal_size);
      ink_assert(!"HdrHeap::unmarshal checksum failure");
      return -1;
    }
  }
#else
  // Because checksums could have been enabled in the past
  //   and then be turned off without clearing the cache,
  //   always reset our variable we use for checksumming
  m_free_start = nullptr;
#endif

  ink_release_assert(m_writeable == false);
  ink_release_assert(m_free_size == 0);
  ink_release_assert(m_ronly_heap[0].m_heap_start != nullptr);

  ink_assert(m_free_start == nullptr);

  // Convert Heap offsets to pointers
  m_data_start                 = (reinterpret_cast<char *>(this)) + (intptr_t)m_data_start;
  m_free_start                 = (reinterpret_cast<char *>(this)) + m_size;
  m_ronly_heap[0].m_heap_start = (reinterpret_cast<char *>(this)) + (intptr_t)m_ronly_heap[0].m_heap_start;

  // Crazy Invariant - If we are sitting in a ref counted block,
  //   the HdrHeap lifetime is externally determined.  Whoever
  //   unmarshalls us should keep the block around as long as
  //   they want to use the header.  However, the strings can
  //   live beyond the heap life time because they are copied
  //   by reference into other header heap therefore we need
  //   to the set the refcount ptr for the strings.  We don't
  //   actually increase the refcount here since for the header
  //   the lifetime is explicit but copies will increase
  //   the refcount
  if (block_ref) {
    m_ronly_heap[0].m_ref_count_ptr.swizzle(block_ref);
  }

  // Loop over objects and swizzle there pointer to
  //  live offsets
  char    *obj_data = m_data_start;
  intptr_t offset   = (intptr_t)this;

  while (obj_data < m_free_start) {
    HdrHeapObjImpl *obj = reinterpret_cast<HdrHeapObjImpl *>(obj_data);
    ink_assert(obj_is_aligned(obj));

    // Object length cannot be 0 by design, otherwise something is wrong + infinite loop here!
    ink_release_assert(0 != obj->m_length);

    if (obj->m_type == static_cast<unsigned>(obj_type) && *found_obj == nullptr) {
      *found_obj = obj;
    }

    switch (static_cast<HdrHeapObjType>(obj->m_type)) {
    case HdrHeapObjType::HTTP_HEADER:
      ((HTTPHdrImpl *)obj)->unmarshal(offset);
      break;
    case HdrHeapObjType::URL:
      ((URLImpl *)obj)->unmarshal(offset);
      break;
    case HdrHeapObjType::FIELD_BLOCK:
      ((MIMEFieldBlockImpl *)obj)->unmarshal(offset);
      break;
    case HdrHeapObjType::MIME_HEADER:
      ((MIMEHdrImpl *)obj)->unmarshal(offset);
      break;
    case HdrHeapObjType::EMPTY:
      // Nothing to do
      break;
    default:
      fprintf(stderr, "WARNING: Unmarshal failed due to unknown obj type %d after %d bytes", static_cast<int>(obj->m_type),
              static_cast<int>(obj_data - reinterpret_cast<char *>(this)));
      dump_heap(unmarshal_size);
      return -1;
    }

    obj_data = obj_data + obj->m_length;
  }

  m_magic = HdrBufMagic::ALIVE;

  unmarshal_size = HdrHeapMarshalBlocks(swoc::round_up(unmarshal_size));
  return unmarshal_size;
}

inline bool
HdrHeap::attach_str_heap(char const *h_start, int h_len, RefCountObj *h_ref_obj, int *index)
{
  if (*index >= static_cast<int>(HDR_BUF_RONLY_HEAPS)) {
    return false;
  }

  // Loop over existing entries to see if this one is already present
  for (int z = 0; z < *index; z++) {
    if (m_ronly_heap[z].m_heap_start == h_start) {
      ink_assert(m_ronly_heap[z].m_ref_count_ptr.object() == h_ref_obj);

      // The lengths could be different because our copy could be
      //   read-only and the copy we are attaching from could be
      //   read-write and have expanded since the last time
      //   to was attached
      if (h_len > m_ronly_heap[z].m_heap_len) {
        m_ronly_heap[z].m_heap_len = h_len;
      }
      return true;
    }
  }

  m_ronly_heap[*index].m_ref_count_ptr = h_ref_obj;
  m_ronly_heap[*index].m_heap_start    = h_start;
  m_ronly_heap[*index].m_heap_len      = h_len;
  m_ronly_heap[*index].m_locked        = false;
  *index                               = *index + 1;

  return true;
}

// void HdrHeap::inhertit_string_heaps(const HdrHeap* inherit_from)
//
//    Inherits all of inherit_from's string heaps as read-only
//     string heaps
//
void
HdrHeap::inherit_string_heaps(const HdrHeap *inherit_from)
{
  // if heaps are the same, this is a no-op
  if (inherit_from == (const HdrHeap *)this) {
    return;
  }

  int first_free       = HDR_BUF_RONLY_HEAPS; // default is out of array bounds
  int free_slots       = 0;
  int inherit_str_size = 0;
  ink_assert(m_writeable);

  // Find the number of free heap slots & the first open index
  for (unsigned index = 0; index < HDR_BUF_RONLY_HEAPS; ++index) {
    if (m_ronly_heap[index].m_heap_start == nullptr) {
      if (first_free == HDR_BUF_RONLY_HEAPS) {
        first_free = index;
      }
      free_slots++;
    }
  }

  // Find out if we have enough slots
  if (inherit_from->m_read_write_heap) {
    free_slots--;
    inherit_str_size = inherit_from->m_read_write_heap->total_size();
  }
  for (const auto &index : inherit_from->m_ronly_heap) {
    if (index.m_heap_start != nullptr) {
      free_slots--;
      inherit_str_size += index.m_heap_len;
    } else {
      // Heaps are allocated from the front of the array, so if
      //  we hit a NULL, we know we can stop
      break;
    }
  }

  // Find out if we are building up too much lost space
  int new_lost_space = m_lost_string_space + inherit_from->m_lost_string_space;

  if (free_slots < 0 || new_lost_space > static_cast<int>(MAX_LOST_STR_SPACE)) {
    // Not enough free slots.  We need to force a coalesce of
    //  string heaps for both old heaps and the inherited from heaps.
    // Coalesce can't know the inherited str size so we pass it
    //  it in so that it can allocate a new read-write string heap
    //  large enough (INKqa07513).
    // INVARIANT: inherit_str_heaps can only be called after
    //  all the objects the callee wants to inherit strings for
    //  are put into the heap
    coalesce_str_heaps(inherit_str_size);
  } else {
    // Copy over read/write string heap if it exists
    if (inherit_from->m_read_write_heap) {
      int str_size =
        inherit_from->m_read_write_heap->total_size() - sizeof(HdrStrHeap) - inherit_from->m_read_write_heap->space_avail();
      ink_release_assert(attach_str_heap(reinterpret_cast<char *>(inherit_from->m_read_write_heap.get() + 1), str_size,
                                         inherit_from->m_read_write_heap.get(), &first_free));
    }
    // Copy over read only string heaps
    for (const auto &i : inherit_from->m_ronly_heap) {
      if (i.m_heap_start) {
        ink_release_assert(attach_str_heap(i.m_heap_start, i.m_heap_len, i.m_ref_count_ptr.get(), &first_free));
      }
    }

    m_lost_string_space += inherit_from->m_lost_string_space;
  }

  return;
}

// void HdrHeap::dump_heap(int len)
//
//   Debugging function to dump the heap in hex
void
HdrHeap::dump_heap(int len)
{
  int      count = 0;
  char    *tmp   = reinterpret_cast<char *>(this);
  char    *end;
  uint32_t content;

  if (len < 0) {
    len = m_size;
  }
  end = (reinterpret_cast<char *>(this)) + len;

  fprintf(stderr, "---- Dumping header heap @ 0x%" PRIx64 " - len %d ------", static_cast<uint64_t>((ptrdiff_t)this), len);

  while (tmp < end) {
    if (count % 4 == 0) {
      fprintf(stderr, "\n0x%" PRIx64 ": ", static_cast<uint64_t>((ptrdiff_t)tmp));
    }
    count++;

    // Load the content
    if (end - tmp > 4) {
      content = *(reinterpret_cast<uint32_t *>(tmp));
    } else {
      // Less than 4 bytes available so just
      //   grab the bytes we need
      content = 0;
      memcpy(&content, tmp, (end - tmp));
    }

    fprintf(stderr, "0x%x ", content);
    tmp += 4;
  }

  fprintf(stderr, "\n-------------- End header heap dump -----------\n");
}

uint64_t
HdrHeap::total_used_size() const
{
  uint64_t       size = 0;
  const HdrHeap *h    = this;

  while (h) {
    size += (h->m_free_start - h->m_data_start);
    h     = h->m_next;
  }

  return size;
}

//
// HdrStrHeap
//

void
HdrStrHeap::free()
{
  if (_total_size == HdrStrHeap::DEFAULT_SIZE) {
    THREAD_FREE(this, strHeapAllocator, this_thread());
  } else {
    ats_free(this);
  }
}

// char* HdrStrHeap::allocate(int nbytes)
//
//   Allocates nbytes from the str heap
//   Return NULL on allocation failure
//
char *
HdrStrHeap::allocate(int nbytes)
{
  if (_avail_size >= static_cast<unsigned>(nbytes)) {
    char *new_space  = reinterpret_cast<char *>(this) + _total_size - _avail_size;
    _avail_size     -= nbytes;
    return new_space;
  } else {
    return nullptr;
  }
}

// char* HdrStrHeap::expand(char* ptr, int old_size, int new_size)
//
//   Try to expand str in the heap.  If we succeed to
//     we return ptr, otherwise we return NULL
//
char *
HdrStrHeap::expand(char *ptr, int old_size, int new_size)
{
  unsigned int expand_size = new_size - old_size;

  ink_assert(contains(ptr));

  char *free_start = reinterpret_cast<char *>(this) + _total_size - _avail_size;
  if (ptr + old_size == free_start && expand_size <= _avail_size) {
    _avail_size -= expand_size;
    return ptr;
  } else {
    return nullptr;
  }
}
