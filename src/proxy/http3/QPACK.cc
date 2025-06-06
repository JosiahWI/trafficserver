/** @file
 *
 *  A brief file description
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/XPACK.h"
#include "proxy/http3/QPACK.h"
#include "tscore/ink_defs.h"
#include "tscore/ink_memory.h"

#define QPACKDebug(fmt, ...)   Dbg(dbg_ctl_qpack, "[%s] " fmt, this->_qc->cids().data(), ##__VA_ARGS__)
#define QPACKDTDebug(fmt, ...) Dbg(dbg_ctl_qpack, "" fmt, ##__VA_ARGS__)

namespace
{
DbgCtl dbg_ctl_qpack{"qpack"};

} // end anonymous namespace

// qpack-05 Appendix A.
const QPACK::Header QPACK::StaticTable::STATIC_HEADER_FIELDS[] = {
  {":authority",                       ""                                                     },
  {":path",                            "/"                                                    },
  {"age",                              "0"                                                    },
  {"content-disposition",              ""                                                     },
  {"content-length",                   "0"                                                    },
  {"cookie",                           ""                                                     },
  {"date",                             ""                                                     },
  {"etag",                             ""                                                     },
  {"if-modified-since",                ""                                                     },
  {"if-none-match",                    ""                                                     },
  {"last-modified",                    ""                                                     },
  {"link",                             ""                                                     },
  {"location",                         ""                                                     },
  {"referer",                          ""                                                     },
  {"set-cookie",                       ""                                                     },
  {":method",                          "CONNECT"                                              },
  {":method",                          "DELETE"                                               },
  {":method",                          "GET"                                                  },
  {":method",                          "HEAD"                                                 },
  {":method",                          "OPTIONS"                                              },
  {":method",                          "POST"                                                 },
  {":method",                          "PUT"                                                  },
  {":scheme",                          "http"                                                 },
  {":scheme",                          "https"                                                },
  {":status",                          "103"                                                  },
  {":status",                          "200"                                                  },
  {":status",                          "304"                                                  },
  {":status",                          "404"                                                  },
  {":status",                          "503"                                                  },
  {"accept",                           "*/*"                                                  },
  {"accept",                           "application/dns-message"                              },
  {"accept-encoding",                  "gzip, deflate, br"                                    },
  {"accept-ranges",                    "bytes"                                                },
  {"access-control-allow-headers",     "cache-control"                                        },
  {"access-control-allow-headers",     "content-type"                                         },
  {"access-control-allow-origin",      "*"                                                    },
  {"cache-control",                    "max-age=0"                                            },
  {"cache-control",                    "max-age=2592000"                                      },
  {"cache-control",                    "max-age=604800"                                       },
  {"cache-control",                    "no-cache"                                             },
  {"cache-control",                    "no-store"                                             },
  {"cache-control",                    "public, max-age=31536000"                             },
  {"content-encoding",                 "br"                                                   },
  {"content-encoding",                 "gzip"                                                 },
  {"content-type",                     "application/dns-message"                              },
  {"content-type",                     "application/javascript"                               },
  {"content-type",                     "application/json"                                     },
  {"content-type",                     "application/x-www-form-urlencoded"                    },
  {"content-type",                     "image/gif"                                            },
  {"content-type",                     "image/jpeg"                                           },
  {"content-type",                     "image/png"                                            },
  {"content-type",                     "text/css"                                             },
  {"content-type",                     "text/html; charset=utf-8"                             },
  {"content-type",                     "text/plain"                                           },
  {"content-type",                     "text/plain;charset=utf-8"                             },
  {"range",                            "bytes=0-"                                             },
  {"strict-transport-security",        "max-age=31536000"                                     },
  {"strict-transport-security",        "max-age=31536000; includesubdomains"                  },
  {"strict-transport-security",        "max-age=31536000; includesubdomains; preload"         },
  {"vary",                             "accept-encoding"                                      },
  {"vary",                             "origin"                                               },
  {"x-content-type-options",           "nosniff"                                              },
  {"x-xss-protection",                 "1; mode=block"                                        },
  {":status",                          "100"                                                  },
  {":status",                          "204"                                                  },
  {":status",                          "206"                                                  },
  {":status",                          "302"                                                  },
  {":status",                          "400"                                                  },
  {":status",                          "403"                                                  },
  {":status",                          "421"                                                  },
  {":status",                          "425"                                                  },
  {":status",                          "500"                                                  },
  {"accept-language",                  ""                                                     },
  {"access-control-allow-credentials", "FALSE"                                                },
  {"access-control-allow-credentials", "TRUE"                                                 },
  {"access-control-allow-headers",     "*"                                                    },
  {"access-control-allow-methods",     "get"                                                  },
  {"access-control-allow-methods",     "get, post, options"                                   },
  {"access-control-allow-methods",     "options"                                              },
  {"access-control-expose-headers",    "content-length"                                       },
  {"access-control-request-headers",   "content-type"                                         },
  {"access-control-request-method",    "get"                                                  },
  {"access-control-request-method",    "post"                                                 },
  {"alt-svc",                          "clear"                                                },
  {"authorization",                    ""                                                     },
  {"content-security-policy",          "script-src 'none'; object-src 'none'; base-uri 'none'"},
  {"early-data",                       "1"                                                    },
  {"expect-ct",                        ""                                                     },
  {"forwarded",                        ""                                                     },
  {"if-range",                         ""                                                     },
  {"origin",                           ""                                                     },
  {"purpose",                          "prefetch"                                             },
  {"server",                           ""                                                     },
  {"timing-allow-origin",              "*"                                                    },
  {"upgrade-insecure-requests",        "1"                                                    },
  {"user-agent",                       ""                                                     },
  {"x-forwarded-for",                  ""                                                     },
  {"x-frame-options",                  "deny"                                                 },
  {"x-frame-options",                  "sameorigin"                                           }
};

QPACK::QPACK(QUICConnection *qc, uint32_t max_field_section_size, uint16_t max_table_size, uint16_t max_blocking_streams)
  : QUICApplication(qc),
    _dynamic_table(max_table_size),
    _max_field_section_size(max_field_section_size),
    _max_table_size(max_table_size),
    _max_blocking_streams(max_blocking_streams)
{
  SET_HANDLER(&QPACK::event_handler);

  this->_encoder_stream_sending_instructions        = new_MIOBuffer(BUFFER_SIZE_INDEX_1K);
  this->_decoder_stream_sending_instructions        = new_MIOBuffer(BUFFER_SIZE_INDEX_1K);
  this->_encoder_stream_sending_instructions_reader = this->_encoder_stream_sending_instructions->alloc_reader();
  this->_decoder_stream_sending_instructions_reader = this->_decoder_stream_sending_instructions->alloc_reader();
}

QPACK::~QPACK()
{
  free_MIOBuffer(_encoder_stream_sending_instructions);
  free_MIOBuffer(_decoder_stream_sending_instructions);
}

void
QPACK::on_stream_open(QUICStream &stream)
{
  auto *info = new QUICStreamVCAdapter::IOInfo(stream);

  switch (stream.direction()) {
  case QUICStreamDirection::BIDIRECTIONAL:
    // ink_assert(!"QPACK does not use bidirectional streams");
    // QPACK offline interop uses stream 0 as a encoder stream.
    info->setup_write_vio(this);
    info->setup_read_vio(this);
    break;
  case QUICStreamDirection::SEND:
    info->setup_write_vio(this);
    break;
  case QUICStreamDirection::RECEIVE:
    info->setup_read_vio(this);
    break;
  default:
    ink_assert(false);
    break;
  }

  stream.set_io_adapter(&info->adapter);
}

void
QPACK::on_stream_close(QUICStream & /* stream ATS_UNUSED */)
{
}

int
QPACK::event_handler(int event, Event *data)
{
  VIO                 *vio     = reinterpret_cast<VIO *>(data->cookie);
  QUICStreamVCAdapter *adapter = static_cast<QUICStreamVCAdapter *>(vio->vc_server);
  int                  ret;

  switch (event) {
  case VC_EVENT_READ_READY:
    adapter->clear_read_ready_event(data);
    ret = this->_on_read_ready(vio);
    break;
  case VC_EVENT_READ_COMPLETE:
    adapter->clear_read_complete_event(data);
    ret = EVENT_DONE;
    break;
  case VC_EVENT_WRITE_READY:
    adapter->clear_write_ready_event(data);
    ret = this->_on_write_ready(vio);
    break;
  case VC_EVENT_WRITE_COMPLETE:
    adapter->clear_write_complete_event(data);
    ret = EVENT_DONE;
    break;
  case VC_EVENT_EOS:
    adapter->clear_eos_event(data);
    ret = EVENT_DONE;
    break;
  default:
    ret = EVENT_DONE;
  }
  return ret;
}

int
QPACK::encode(uint64_t stream_id, HTTPHdr &header_set, MIOBuffer *header_block, uint64_t &header_block_len)
{
  if (!header_block) {
    return -1;
  }

  uint16_t base_index = this->_largest_known_received_index;

  // Compress headers and record the largest reference
  uint16_t       referred_index     = 0;
  uint16_t       largest_reference  = 0;
  uint16_t       smallest_reference = 0;
  IOBufferBlock *compressed_headers = new_IOBufferBlock();
  compressed_headers->alloc(BUFFER_SIZE_INDEX_2K);

  for (auto &field : header_set) {
    int ret            = this->_encode_header(field, base_index, compressed_headers, referred_index);
    largest_reference  = std::max(largest_reference, referred_index);
    smallest_reference = std::min(smallest_reference, referred_index);
    if (ret < 0) {
      compressed_headers->free();
      return ret;
    }
  }
  struct EntryReference eref = {smallest_reference, largest_reference};
  this->_references.emplace(stream_id, eref);

  // Make an IOBufferBlock for Header Data Prefix
  IOBufferBlock *header_data_prefix = new_IOBufferBlock();
  header_data_prefix->alloc(BUFFER_SIZE_INDEX_128);
  this->_encode_prefix(largest_reference, base_index, header_data_prefix);

  header_block->append_block(header_data_prefix);
  header_block_len += header_data_prefix->size();

  header_block->append_block(compressed_headers);
  header_block_len += compressed_headers->size();

  return 0;
}

int
QPACK::decode(uint64_t stream_id, const uint8_t *header_block, size_t header_block_len, HTTPHdr &hdr, Continuation *cont,
              EThread *thread)
{
  if (!cont || !header_block) {
    return -1;
  }

  if (this->_invalid) {
    thread->schedule_imm(cont, QPACK_EVENT_DECODE_FAILED, nullptr);
    return -1;
  }

  uint64_t tmp = 0;
  int64_t  ret = xpack_decode_integer(tmp, header_block, header_block + header_block_len, 8);
  if (ret < 0 && tmp > 0xFFFF) {
    return -1;
  }
  uint16_t largest_reference = tmp;

  if (largest_reference != 0 && (this->_dynamic_table.is_empty() || this->_dynamic_table.largest_index() < largest_reference)) {
    // Blocked
    if (this->_add_to_blocked_list(
          new DecodeRequest(largest_reference, thread, cont, stream_id, header_block, header_block_len, hdr))) {
      return 1;
    } else {
      // Number of blocked streams exceed the limit
      return -2;
    }
  }

  this->_decode(thread, cont, stream_id, header_block, header_block_len, hdr);

  return 0;
}

void
QPACK::set_encoder_stream(QUICStreamId id)
{
  this->_encoder_stream_id = id;
}

void
QPACK::set_decoder_stream(QUICStreamId id)
{
  this->_decoder_stream_id = id;
}

void
QPACK::update_max_field_section_size(uint32_t max_field_section_size)
{
  this->_max_field_section_size = max_field_section_size;
}

void
QPACK::update_max_table_size(uint16_t max_table_size)
{
  this->_max_table_size = max_table_size;
}

void
QPACK::update_max_blocking_streams(uint16_t max_blocking_streams)
{
  this->_max_blocking_streams = max_blocking_streams;
}

int
QPACK::_encode_prefix(uint16_t largest_reference, uint16_t base_index, IOBufferBlock *prefix)
{
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(prefix->end()),
                                  reinterpret_cast<uint8_t *>(prefix->end() + prefix->write_avail()), largest_reference, 8)) < 0) {
    return -1;
  }
  prefix->fill(ret);

  uint16_t delta;
  prefix->end()[0] = 0x0;
  if (base_index < largest_reference) {
    prefix->end()[0] |= 0x80;
    delta             = largest_reference - base_index;
  } else {
    delta = base_index - largest_reference;
  }

  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(prefix->end()),
                                  reinterpret_cast<uint8_t *>(prefix->end() + prefix->write_avail()), delta, 7)) < 0) {
    return -2;
  }
  prefix->fill(ret);

  QPACKDebug("Encoded Header Data Prefix: largest_ref=%d, base_index=%d, delta=%d", largest_reference, base_index, delta);

  return 0;
}

int
QPACK::_encode_header(const MIMEField &field, uint16_t base_index, IOBufferBlock *compressed_header, uint16_t &referred_index)
{
  auto  name{field.name_get()};
  char *lowered_name = this->_arena.str_store(name.data(), name.length());
  for (size_t i = 0; i < name.length(); i++) {
    lowered_name[i] = ParseRules::ink_tolower(lowered_name[i]);
  }
  auto value{field.value_get()};

  // TODO Set never_index flag on/off according to encoding headers
  bool never_index = false;

  // Find from tables, and insert / duplicate a entry prior to encode it
  XpackLookupResult lookup_result_static;
  XpackLookupResult lookup_result_dynamic;
  lookup_result_static = StaticTable::lookup(lowered_name, name.length(), value.data(), value.length());
  if (lookup_result_static.match_type != XpackLookupResult::MatchType::EXACT) {
    lookup_result_dynamic = this->_dynamic_table.lookup(lowered_name, name.length(), value.data(), value.length());
    if (lookup_result_dynamic.match_type == XpackLookupResult::MatchType::EXACT) {
      if (this->_dynamic_table.should_duplicate(lookup_result_dynamic.index)) {
        // Duplicate an entry and use the new entry
        uint16_t current_index = lookup_result_dynamic.index;
        lookup_result_dynamic  = this->_dynamic_table.duplicate_entry(current_index);
        if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
          this->_write_duplicate(current_index);
          QPACKDebug("Wrote Duplicate: current_index=%d", current_index);
          this->_dynamic_table.ref_entry(current_index);
        }
      }
    } else if (lookup_result_static.match_type == XpackLookupResult::MatchType::NAME) {
      if (never_index) {
        // Name in static table is always available. Do nothing.
      } else {
        // Insert both the name and the value
        lookup_result_dynamic = this->_dynamic_table.insert_entry(lowered_name, name.length(), value.data(), value.length());
        if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
          this->_write_insert_with_name_ref(lookup_result_static.index, false, value.data(), value.length());
          QPACKDebug("Wrote Insert With Name Ref: index=%u, dynamic_table=%d value=%.*s", lookup_result_static.index, false,
                     static_cast<int>(value.length()), value.data());
        }
      }
    } else if (lookup_result_dynamic.match_type == XpackLookupResult::MatchType::NAME) {
      if (never_index) {
        if (this->_dynamic_table.should_duplicate(lookup_result_dynamic.index)) {
          // Duplicate an entry and use the new entry
          uint16_t current_index = lookup_result_dynamic.index;
          lookup_result_dynamic  = this->_dynamic_table.duplicate_entry(current_index);
          if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
            this->_write_duplicate(current_index);
            QPACKDebug("Wrote Duplicate: current_index=%d", current_index);
            this->_dynamic_table.ref_entry(current_index);
          }
        }
      } else {
        if (this->_dynamic_table.should_duplicate(lookup_result_dynamic.index)) {
          // Duplicate an entry and use the new entry
          uint16_t current_index = lookup_result_dynamic.index;
          lookup_result_dynamic  = this->_dynamic_table.duplicate_entry(current_index);
          if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
            this->_write_duplicate(current_index);
            QPACKDebug("Wrote Duplicate: current_index=%d", current_index);
            this->_dynamic_table.ref_entry(current_index);
          }
        } else {
          // Insert both the name and the value
          uint16_t current_index = lookup_result_dynamic.index;
          lookup_result_dynamic  = this->_dynamic_table.insert_entry(lowered_name, name.length(), value.data(), value.length());
          if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
            this->_write_insert_with_name_ref(current_index, true, value.data(), value.length());
            QPACKDebug("Wrote Insert With Name Ref: index=%u, dynamic_table=%d, value=%.*s", current_index, true,
                       static_cast<int>(value.length()), value.data());
          }
        }
      }
    } else {
      if (never_index) {
        // Insert only the name
        lookup_result_dynamic = this->_dynamic_table.insert_entry(lowered_name, name.length(), "", 0);
        if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
          this->_write_insert_without_name_ref(lowered_name, name.length(), "", 0);
          QPACKDebug("Wrote Insert Without Name Ref: name=%.*s value=%.*s", static_cast<int>(name.length()), lowered_name, 0, "");
        }
      } else {
        // Insert both the name and the value
        lookup_result_dynamic = this->_dynamic_table.insert_entry(lowered_name, name.length(), value.data(), value.length());
        if (lookup_result_dynamic.match_type != XpackLookupResult::MatchType::NONE) {
          this->_write_insert_without_name_ref(lowered_name, name.length(), value.data(), value.length());
          QPACKDebug("Wrote Insert Without Name Ref: name=%.*s value=%.*s", static_cast<int>(name.length()), lowered_name,
                     static_cast<int>(value.length()), value.data());
        }
      }
    }
  }

  // Encode
  if (lookup_result_static.match_type == XpackLookupResult::MatchType::EXACT) {
    this->_encode_indexed_header_field(lookup_result_static.index, base_index, false, compressed_header);
    QPACKDebug("Encoded Indexed Header Field: abs_index=%d, base_index=%d, dynamic_table=%d", lookup_result_static.index,
               base_index, false);
    referred_index = 0;
  } else if (lookup_result_dynamic.match_type == XpackLookupResult::MatchType::EXACT) {
    if (lookup_result_dynamic.index < this->_largest_known_received_index) {
      this->_encode_indexed_header_field(lookup_result_dynamic.index, base_index, true, compressed_header);
      QPACKDebug("Encoded Indexed Header Field: abs_index=%d, base_index=%d, dynamic_table=%d", lookup_result_dynamic.index,
                 base_index, true);
    } else {
      this->_encode_indexed_header_field_with_postbase_index(lookup_result_dynamic.index, base_index, never_index,
                                                             compressed_header);
      QPACKDebug("Encoded Indexed Header With Postbase Index: abs_index=%d, base_index=%d, never_index=%d",
                 lookup_result_dynamic.index, base_index, never_index);
    }
    this->_dynamic_table.ref_entry(lookup_result_dynamic.index);
    referred_index = lookup_result_dynamic.index;
  } else if (lookup_result_static.match_type == XpackLookupResult::MatchType::NAME) {
    this->_encode_literal_header_field_with_name_ref(lookup_result_static.index, false, base_index, value.data(), value.length(),
                                                     never_index, compressed_header);
    QPACKDebug(
      "Encoded Literal Header Field With Name Ref: abs_index=%d, base_index=%d, dynamic_table=%d, value=%.*s, never_index=%d",
      lookup_result_static.index, base_index, false, static_cast<int>(value.length()), value.data(), never_index);
    referred_index = 0;
  } else if (lookup_result_dynamic.match_type == XpackLookupResult::MatchType::NAME) {
    if (lookup_result_dynamic.index <= this->_largest_known_received_index) {
      this->_encode_literal_header_field_with_name_ref(lookup_result_dynamic.index, true, base_index, value.data(), value.length(),
                                                       never_index, compressed_header);
      QPACKDebug(
        "Encoded Literal Header Field With Name Ref: abs_index=%d, base_index=%d, dynamic_table=%d, value=%.*s, never_index=%d",
        lookup_result_dynamic.index, base_index, true, static_cast<int>(value.length()), value.data(), never_index);
    } else {
      this->_encode_literal_header_field_with_postbase_name_ref(lookup_result_dynamic.index, base_index, value.data(),
                                                                value.length(), never_index, compressed_header);
      QPACKDebug("Encoded Literal Header Field With Postbase Name Ref: abs_index=%d, base_index=%d, value=%.*s, never_index=%d",
                 lookup_result_dynamic.index, base_index, static_cast<int>(value.length()), value.data(), never_index);
    }
    this->_dynamic_table.ref_entry(lookup_result_dynamic.index);
    referred_index = lookup_result_dynamic.index;
  } else {
    this->_encode_literal_header_field_without_name_ref(lowered_name, name.length(), value.data(), value.length(), never_index,
                                                        compressed_header);
    QPACKDebug("Encoded Literal Header Field Without Name Ref: name=%.*s, value=%.*s, never_index=%d",
               static_cast<int>(name.length()), lowered_name, static_cast<int>(value.length()), value.data(), never_index);
  }

  this->_arena.str_free(lowered_name);

  return 0;
}

int
QPACK::_encode_indexed_header_field(uint16_t index, uint16_t base_index, bool dynamic_table, IOBufferBlock *compressed_header)
{
  char *buf     = compressed_header->end();
  char *buf_end = buf + compressed_header->write_avail();
  int   written = 0;

  // Indexed Header Field
  buf[0] = 0x80;

  // References static table or not
  if (dynamic_table) {
    // Use relative index if we refer Dynamic Table
    index = this->_calc_relative_index_from_absolute_index(base_index, index);
  } else {
    buf[0] |= 0x40;
  }

  // Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), index, 6)) <
      0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  compressed_header->fill(written);

  return 0;
}

int
QPACK::_encode_indexed_header_field_with_postbase_index(uint16_t index, uint16_t base_index, bool /* never_index ATS_UNUSED */,
                                                        IOBufferBlock *compressed_header)
{
  char *buf     = compressed_header->end();
  char *buf_end = buf + compressed_header->write_avail();
  int   written = 0;

  // Indexed Header Field with Post-Base Index
  buf[0] = 0x10;

  // Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end),
                                  this->_calc_postbase_index_from_absolute_index(base_index, index), 4)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  compressed_header->fill(written);

  return 0;
}

int
QPACK::_encode_literal_header_field_with_name_ref(uint16_t index, bool dynamic_table, uint16_t base_index, const char *value,
                                                  int value_len, bool never_index, IOBufferBlock *compressed_header)
{
  char *buf     = compressed_header->end();
  char *buf_end = buf + compressed_header->write_avail();
  int   written = 0;

  // Literal Header Field With Name Reference
  buf[0] = 0x40;

  if (never_index) {
    buf[0] |= 0x20;
  }

  // References static table or not
  if (dynamic_table) {
    // Use relative index if we refer Dynamic Table
    index = this->_calc_relative_index_from_absolute_index(base_index, index);
  } else {
    buf[0] |= 0x10;
  }

  // Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), index, 4)) <
      0) {
    return ret;
  }
  written += ret;

  // Value
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), value,
                                 value_len)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  compressed_header->fill(written);

  return 0;
}

int
QPACK::_encode_literal_header_field_without_name_ref(const char *name, int name_len, const char *value, int value_len,
                                                     bool never_index, IOBufferBlock *compressed_header)
{
  char *buf     = compressed_header->end();
  char *buf_end = buf + compressed_header->write_avail();
  int   written = 0;

  // Literal Header Field Without Name Reference
  buf[0] = 0x20;

  if (never_index) {
    buf[0] |= 0x10;
  }

  // Name
  int ret;
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), name, name_len,
                                 3)) < 0) {
    return ret;
  }
  written += ret;

  // Value
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), value, value_len,
                                 7)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  compressed_header->fill(written);

  return 0;
}

int
QPACK::_encode_literal_header_field_with_postbase_name_ref(uint16_t index, uint16_t base_index, const char *value, int value_len,
                                                           bool never_index, IOBufferBlock *compressed_header)
{
  char *buf     = compressed_header->end();
  char *buf_end = buf + compressed_header->write_avail();
  int   written = 0;

  // Literal Header Field With Post-Base Name Reference
  buf[0] = 0x00;

  if (never_index) {
    buf[0] |= 0x08;
  }

  // Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end),
                                  this->_calc_postbase_index_from_absolute_index(base_index, index), 3)) < 0) {
    return ret;
  }
  written += ret;

  // Value
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), value, value_len,
                                 7)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  compressed_header->fill(written);

  return 0;
}

int
QPACK::_decode_indexed_header_field(int16_t base_index, const uint8_t *buf, size_t buf_len, HTTPHdr &hdr, uint32_t &header_len)
{
  // Read index field
  int      len = 0;
  uint64_t index;
  int      ret = xpack_decode_integer(index, buf, buf + buf_len, 6);
  if (ret < 0) {
    return -1;
  }
  len += ret;

  // Lookup a table
  const char       *name      = nullptr;
  size_t            name_len  = 0;
  const char       *value     = nullptr;
  size_t            value_len = 0;
  XpackLookupResult result;

  if (buf[0] & 0x40) { // Static table
    result = StaticTable::lookup(index, &name, &name_len, &value, &value_len);
  } else { // Dynamic table
    result = this->_dynamic_table.lookup(this->_calc_absolute_index_from_relative_index(base_index, index), &name, &name_len,
                                         &value, &value_len);
  }
  if (result.match_type != XpackLookupResult::MatchType::EXACT) {
    return -1;
  }

  // Create and attach a header
  this->_attach_header(hdr, name, name_len, value, value_len, false);
  header_len = name_len + value_len;

  QPACKDebug("Decoded Indexed Header Field: base_index=%d, abs_index=%d, name=%.*s, value=%.*s", base_index, result.index,
             static_cast<int>(name_len), name, static_cast<int>(value_len), value);

  return len;
}

int
QPACK::_decode_literal_header_field_with_name_ref(int16_t base_index, const uint8_t *buf, size_t buf_len, HTTPHdr &hdr,
                                                  uint32_t &header_len)
{
  int read_len = 0;

  // Never index field
  bool never_index = false;
  if (buf[0] & 0x20) {
    never_index = true;
  }

  // Read name index field
  uint64_t index;
  int      ret = xpack_decode_integer(index, buf, buf + buf_len, 4);
  if (ret < 0) {
    return -1;
  }
  read_len += ret;

  // Lookup the name
  const char       *name      = nullptr;
  size_t            name_len  = 0;
  const char       *dummy     = nullptr;
  size_t            dummy_len = 0;
  XpackLookupResult result;

  if (buf[0] & 0x10) { // Static table
    result = StaticTable::lookup(index, &name, &name_len, &dummy, &dummy_len);
  } else { // Dynamic table
    result = this->_dynamic_table.lookup(this->_calc_absolute_index_from_relative_index(base_index, index), &name, &name_len,
                                         &dummy, &dummy_len);
  }
  if (result.match_type != XpackLookupResult::MatchType::EXACT) {
    return -1;
  }

  // Read value
  char    *value;
  uint64_t value_len;
  if ((ret = xpack_decode_string(this->_arena, &value, value_len, buf + read_len, buf + buf_len, 7)) < 0) {
    return -1;
  }
  read_len += ret;

  // Create and attach a header
  this->_attach_header(hdr, name, name_len, value, value_len, never_index);
  header_len = name_len + value_len;

  QPACKDebug("Decoded Literal Header Field With Name Ref: base_index=%d, abs_index=%d, name=%.*s, value=%.*s", base_index,
             result.index, static_cast<int>(name_len), name, static_cast<int>(value_len), value);

  this->_arena.str_free(value);

  return read_len;
}

int
QPACK::_decode_literal_header_field_without_name_ref(const uint8_t *buf, size_t buf_len, HTTPHdr &hdr, uint32_t &header_len)
{
  int read_len = 0;

  // Never index field
  bool never_index = false;
  if (buf[0] & 0x10) {
    never_index = true;
  }

  // Read name and value
  int64_t  ret;
  char    *name;
  uint64_t name_len;
  if ((ret = xpack_decode_string(this->_arena, &name, name_len, buf, buf + buf_len, 3)) < 0) {
    return -1;
  }
  read_len += ret;

  char    *value;
  uint64_t value_len;
  if ((ret = xpack_decode_string(this->_arena, &value, value_len, buf + read_len, buf + buf_len, 7)) < 0) {
    return -1;
  }
  read_len += ret;

  // Create and attach a header
  this->_attach_header(hdr, name, name_len, value, value_len, never_index);
  header_len = name_len + value_len;

  QPACKDebug("Decoded Literal Header Field Without Name Ref: name=%.*s, value=%.*s", static_cast<uint16_t>(name_len), name,
             static_cast<uint16_t>(value_len), value);

  this->_arena.str_free(name);
  this->_arena.str_free(value);

  return read_len;
}

int
QPACK::_decode_indexed_header_field_with_postbase_index(int16_t base_index, const uint8_t *buf, size_t buf_len, HTTPHdr &hdr,
                                                        uint32_t &header_len)
{
  // Read index field
  int      len = 0;
  uint64_t index;
  int      ret = xpack_decode_integer(index, buf, buf + buf_len, 4);
  if (ret < 0) {
    return -1;
  }
  len += ret;

  // Lookup a table
  const char       *name      = nullptr;
  size_t            name_len  = 0;
  const char       *value     = nullptr;
  size_t            value_len = 0;
  XpackLookupResult result;

  result = this->_dynamic_table.lookup(this->_calc_absolute_index_from_postbase_index(base_index, index), &name, &name_len, &value,
                                       &value_len);
  if (result.match_type != XpackLookupResult::MatchType::EXACT) {
    return -1;
  }

  // Create and attach a header
  this->_attach_header(hdr, name, name_len, value, value_len, false);
  header_len = name_len + value_len;

  QPACKDebug("Decoded Indexed Header Field With Postbase Index: base_index=%d, abs_index=%d, name=%.*s, value=%.*s", base_index,
             result.index, static_cast<int>(name_len), name, static_cast<int>(value_len), value);

  return len;
}

int
QPACK::_decode_literal_header_field_with_postbase_name_ref(int16_t base_index, const uint8_t *buf, size_t buf_len, HTTPHdr &hdr,
                                                           uint32_t &header_len)
{
  int read_len = 0;

  // Never index field
  bool never_index = false;
  if (buf[0] & 0x08) {
    never_index = true;
  }

  // Read name index field
  uint64_t index;
  int      ret = xpack_decode_integer(index, buf, buf + buf_len, 3);
  if (ret < 0) {
    return -1;
  }
  read_len += ret;

  // Lookup the name
  const char       *name      = nullptr;
  size_t            name_len  = 0;
  const char       *dummy     = nullptr;
  size_t            dummy_len = 0;
  XpackLookupResult result;

  result = this->_dynamic_table.lookup(this->_calc_absolute_index_from_postbase_index(base_index, index), &name, &name_len, &dummy,
                                       &dummy_len);
  if (result.match_type != XpackLookupResult::MatchType::EXACT) {
    return -1;
  }

  // Read value
  char    *value;
  uint64_t value_len;
  if ((ret = xpack_decode_string(this->_arena, &value, value_len, buf + read_len, buf + buf_len, 7)) < 0) {
    return -1;
  }
  read_len += ret;

  // Create and attach a header
  this->_attach_header(hdr, name, name_len, value, value_len, never_index);
  header_len = name_len + value_len;

  QPACKDebug("Decoded Literal Header Field With Postbase Name Ref: base_index=%d, abs_index=%d, name=%.*s, value=%.*s", base_index,
             static_cast<uint16_t>(index), static_cast<int>(name_len), name, static_cast<int>(value_len), value);

  this->_arena.str_free(value);

  return read_len;
}

int
QPACK::_decode_header(const uint8_t *header_block, size_t header_block_len, HTTPHdr &hdr)
{
  const uint8_t *pos        = header_block;
  size_t         remain_len = header_block_len;
  int64_t        ret;

  // Decode Header Data Prefix
  uint64_t tmp;
  if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  pos                        += ret;
  uint16_t largest_reference  = tmp;

  uint64_t delta_base_index;
  uint16_t base_index;
  if ((ret = xpack_decode_integer(delta_base_index, pos, pos + remain_len, 7)) < 0 && delta_base_index < 0xFFFF) {
    return -2;
  }

  if (pos[0] & 0x80) {
    if (delta_base_index == 0) {
      return -3;
    }
    base_index = largest_reference - delta_base_index;
  } else {
    base_index = largest_reference + delta_base_index;
  }
  pos += ret;

  uint32_t decoded_header_list_size = 0;

  // Decode Instructions
  while (pos < header_block + header_block_len) {
    uint32_t header_len = 0;

    if (pos[0] & 0x80) { // Index Header Field
      ret = this->_decode_indexed_header_field(base_index, pos, remain_len, hdr, header_len);
    } else if (pos[0] & 0x40) { // Literal Header Field With Name Reference
      ret = this->_decode_literal_header_field_with_name_ref(base_index, pos, remain_len, hdr, header_len);
    } else if (pos[0] & 0x20) { // Literal Header Field Without Name Reference
      ret = this->_decode_literal_header_field_without_name_ref(pos, remain_len, hdr, header_len);
    } else if (pos[0] & 0x10) { // Indexed Header Field With Post-Base Index
      ret = this->_decode_indexed_header_field_with_postbase_index(base_index, pos, remain_len, hdr, header_len);
    } else { // Literal Header Field With Post-Base Name Reference
      ret = this->_decode_literal_header_field_with_postbase_name_ref(base_index, pos, remain_len, hdr, header_len);
    }

    if (ret < 0) {
      break;
    }

    decoded_header_list_size += header_len;
    if (decoded_header_list_size > this->_max_field_section_size) {
      ret = -2;
      break;
    }

    pos += ret;
  }

  return ret;
}

void
QPACK::_decode(EThread *ethread, Continuation *cont, uint64_t stream_id, const uint8_t *header_block, size_t header_block_len,
               HTTPHdr &hdr)
{
  int event;
  int res = this->_decode_header(header_block, header_block_len, hdr);
  if (res < 0) {
    event = QPACK_EVENT_DECODE_FAILED;
    QPACKDebug("decoding header failed (%d)", res);
  } else {
    event = QPACK_EVENT_DECODE_COMPLETE;
    this->_write_header_acknowledgement(stream_id);
  }
  ethread->schedule_imm(cont, event, &hdr);
}

bool
QPACK::_add_to_blocked_list(DecodeRequest *decode_request)
{
  if (this->_blocked_list.count() >= this->_max_blocking_streams) {
    return false;
  }

  this->_blocked_list.append(decode_request);
  return true;
}

void
QPACK::_update_largest_known_received_index_by_insert_count(uint16_t insert_count)
{
  this->_largest_known_received_index += insert_count;
}

void
QPACK::_update_largest_known_received_index_by_stream_id(uint64_t stream_id)
{
  uint16_t largest_ref_index = this->_references[stream_id].largest;
  if (largest_ref_index > this->_largest_known_received_index) {
    this->_largest_known_received_index = largest_ref_index;
  }
}

void
QPACK::_update_reference_counts(uint64_t stream_id)
{
  uint16_t smallest_ref_index = this->_references[stream_id].smallest;
  if (smallest_ref_index) {
    this->_dynamic_table.unref_entry(smallest_ref_index);
  }
}

void
QPACK::_resume_decode()
{
  DecodeRequest *r = this->_blocked_list.head();
  while (r) {
    if (this->_largest_known_received_index >= r->largest_reference()) {
      this->_decode(r->thread(), r->continuation(), r->stream_id(), r->header_block(), r->header_block_len(), r->hdr());
      DecodeRequest *tmp = r;
      r                  = DecodeRequest::Linkage::next_ptr(r);
      this->_blocked_list.erase(tmp);
      delete tmp;
    } else {
      r = DecodeRequest::Linkage::next_ptr(r);
    }
  }
}

void
QPACK::_abort_decode()
{
  this->_invalid = true;

  DecodeRequest *r = this->_blocked_list.head();
  while (r) {
    if (this->_largest_known_received_index >= r->largest_reference()) {
      r->thread()->schedule_imm(r->continuation(), QPACK_EVENT_DECODE_FAILED, nullptr);
      DecodeRequest *tmp = r;
      r                  = DecodeRequest::Linkage::next_ptr(r);
      this->_blocked_list.erase(tmp);
      delete tmp;
    } else {
      r = DecodeRequest::Linkage::next_ptr(r);
    }
  }
}

int
QPACK::_on_read_ready(VIO *vio)
{
  int          nread     = 0;
  QUICStreamId stream_id = static_cast<QUICStreamVCAdapter *>(vio->vc_server)->stream().id();

  if (stream_id == this->_decoder_stream_id) {
    nread = this->_on_decoder_stream_read_ready(*vio->get_reader());
  } else if (stream_id == this->_encoder_stream_id) {
    nread = this->_on_encoder_stream_read_ready(*vio->get_reader());
  } else {
    ink_assert(!"The stream ID must match either encoder stream id or decoder stream id");
  }

  vio->ndone += nread;
  return EVENT_DONE;
}

int
QPACK::_on_write_ready(VIO *vio)
{
  QUICStreamId stream_id = static_cast<QUICStreamVCAdapter *>(vio->vc_server)->stream().id();

  if (stream_id == this->_decoder_stream_id) {
    return this->_on_decoder_write_ready(*vio->get_writer());
  } else if (stream_id == this->_encoder_stream_id) {
    return this->_on_encoder_write_ready(*vio->get_writer());
  } else {
    ink_assert(!"The stream ID must match either decoder stream id or decoder stream id");
    return EVENT_DONE;
  }
}

int
QPACK::_on_decoder_stream_read_ready(IOBufferReader &reader)
{
  if (reader.is_read_avail_more_than(0)) {
    uint8_t buf;
    reader.memcpy(&buf, 1);
    if (buf & 0x80) { // Header Acknowledgement
      uint64_t stream_id;
      if (this->_read_header_acknowledgement(reader, stream_id) >= 0) {
        QPACKDebug("Received Header Acknowledgement: stream_id=%" PRIu64, stream_id);
        this->_update_largest_known_received_index_by_stream_id(stream_id);
        this->_update_reference_counts(stream_id);
        this->_references.erase(stream_id);
      }
    } else if (buf & 0x40) { // Stream Cancellation
      uint64_t stream_id;
      if (this->_read_stream_cancellation(reader, stream_id) >= 0) {
        QPACKDebug("Received Stream Cancellation: stream_id=%" PRIu64, stream_id);
        this->_update_reference_counts(stream_id);
        this->_references.erase(stream_id);
      }
    } else { // Table State Synchronize
      uint16_t insert_count;
      if (this->_read_table_state_synchronize(reader, insert_count) >= 0) {
        QPACKDebug("Received Table State Synchronize: inserted_count=%d", insert_count);
        this->_update_largest_known_received_index_by_insert_count(insert_count);
      }
    }
  }

  return EVENT_DONE;
}

int
QPACK::_on_encoder_stream_read_ready(IOBufferReader &reader)
{
  while (reader.is_read_avail_more_than(0)) {
    uint8_t buf;
    reader.memcpy(&buf, 1);
    if (buf & 0x80) { // Insert With Name Reference
      bool        is_static;
      uint16_t    index;
      const char *name;
      size_t      name_len;
      const char *dummy;
      size_t      dummy_len;
      char       *value;
      size_t      value_len;
      if (this->_read_insert_with_name_ref(reader, is_static, index, this->_arena, &value, value_len) < 0) {
        this->_abort_decode();
        return EVENT_DONE;
      }
      QPACKDebug("Received Insert With Name Ref: is_static=%d, index=%d, value=%.*s", is_static, index, static_cast<int>(value_len),
                 value);
      StaticTable::lookup(index, &name, &name_len, &dummy, &dummy_len);
      this->_dynamic_table.insert_entry(name, name_len, value, value_len);
      this->_arena.str_free(value);
    } else if (buf & 0x40) { // Insert Without Name Reference
      char  *name;
      size_t name_len;
      char  *value;
      size_t value_len;
      if (this->_read_insert_without_name_ref(reader, this->_arena, &name, name_len, &value, value_len) < 0) {
        this->_abort_decode();
        return EVENT_DONE;
      }
      QPACKDebug("Received Insert Without Name Ref: name=%.*s, value=%.*s", static_cast<int>(name_len), name,
                 static_cast<int>(value_len), value);
      this->_dynamic_table.insert_entry(name, name_len, value, value_len);
      this->_arena.str_free(name);
    } else if (buf & 0x20) { // Dynamic Table Size Update
      uint16_t max_size;
      if (this->_read_dynamic_table_size_update(reader, max_size) < 0) {
        this->_abort_decode();
        return EVENT_DONE;
      }
      QPACKDebug("Received Dynamic Table Size Update: max_size=%d", max_size);
      this->_dynamic_table.update_maximum_size(max_size);
    } else { // Duplicates
      uint16_t index;
      if (this->_read_duplicate(reader, index) < 0) {
        this->_abort_decode();
        return EVENT_DONE;
      }
      QPACKDebug("Received Duplicate: index=%d", index);
      this->_dynamic_table.duplicate_entry(index);
    }

    this->_resume_decode();
  }

  return EVENT_DONE;
}

int
QPACK::_on_decoder_write_ready(MIOBuffer &writer)
{
  int64_t written_len = writer.write(this->_decoder_stream_sending_instructions_reader, INT64_MAX);
  this->_decoder_stream_sending_instructions_reader->consume(written_len);
  return written_len;
}

int
QPACK::_on_encoder_write_ready(MIOBuffer &writer)
{
  int64_t written_len = writer.write(this->_encoder_stream_sending_instructions_reader, INT64_MAX);
  this->_encoder_stream_sending_instructions_reader->consume(written_len);
  return written_len;
}

size_t
QPACK::estimate_header_block_size(const HTTPHdr & /* hdr ATS_UNUSED */)
{
  // FIXME Estimate it
  return 128 * 1024 * 1024;
}

const XpackLookupResult
QPACK::StaticTable::lookup(uint16_t index, const char **name, size_t *name_len, const char **value, size_t *value_len)
{
  const Header &header = STATIC_HEADER_FIELDS[index];
  *name                = header.name;
  *name_len            = header.name_len;
  *value               = header.value;
  *value_len           = header.value_len;
  return {index, XpackLookupResult::MatchType::EXACT};
}

const XpackLookupResult
QPACK::StaticTable::lookup(const char *name, size_t name_len, const char *value, size_t value_len)
{
  XpackLookupResult::MatchType match_type      = XpackLookupResult::MatchType::NONE;
  uint16_t                     i               = 0;
  uint16_t                     candidate_index = 0;
  int                          n               = countof(STATIC_HEADER_FIELDS);

  for (; i < n; ++i) {
    const Header &h = STATIC_HEADER_FIELDS[i];
    if (h.name_len == name_len) {
      if (memcmp(name, h.name, name_len) == 0) {
        candidate_index = i;
        if (value_len == h.value_len && memcmp(value, h.value, value_len) == 0) {
          // Exact match
          match_type = XpackLookupResult::MatchType::EXACT;
          break;
        } else {
          // Name match -- Keep it for no exact matches
          match_type = XpackLookupResult::MatchType::NAME;
        }
      }
    }
  }
  return {candidate_index, match_type};
}

uint16_t
QPACK::_calc_absolute_index_from_relative_index(uint16_t base_index, uint16_t relative_index)
{
  return base_index - relative_index;
}

uint16_t
QPACK::_calc_absolute_index_from_postbase_index(uint16_t base_index, uint16_t postbase_index)
{
  return base_index + postbase_index + 1;
}

uint16_t
QPACK::_calc_relative_index_from_absolute_index(uint16_t base_index, uint16_t absolute_index)
{
  return base_index - absolute_index;
}

uint16_t
QPACK::_calc_postbase_index_from_absolute_index(uint16_t base_index, uint16_t absolute_index)
{
  return absolute_index - base_index - 1;
}

void
QPACK::_attach_header(HTTPHdr &hdr, const char *name, int name_len, const char *value, int value_len,
                      bool /* never_index ATS_UNUSED */)
{
  // TODO If never_index is true, we need to mark this header as sensitive to not index the header when passing it to the other side
  MIMEField *new_field = hdr.field_create(std::string_view{name, static_cast<std::string_view::size_type>(name_len)});
  new_field->value_set(hdr.m_heap, hdr.m_mime, std::string_view{value, static_cast<std::string_view::size_type>(value_len)});
  hdr.field_attach(new_field);
}

int
QPACK::_write_insert_with_name_ref(uint16_t index, bool dynamic, const char *value, uint16_t value_len)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_2K);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Insert With Name Reference
  buf[0] = 0x80;

  // References static table or not
  if (!dynamic) {
    buf[0] |= 0x40;
  }

  // Name Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), index, 6)) <
      0) {
    return ret;
  }
  written += ret;

  // Value
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), value, value_len,
                                 7)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_insert_without_name_ref(const char *name, int name_len, const char *value, uint16_t value_len)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_2K);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Insert Without Name Reference
  buf[0] = 0x40;

  // Name
  int ret;
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), name, name_len,
                                 5)) < 0) {
    return ret;
  }
  written += ret;

  // Value
  if ((ret = xpack_encode_string(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), value, value_len,
                                 7)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_duplicate(uint16_t index)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_2K);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Index
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), index, 5)) <
      0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_dynamic_table_size_update(uint16_t max_size)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_128);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Dynamic Table Size Update
  buf[0] = 0x20;

  // Max Size
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), max_size, 5)) <
      0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_table_state_synchronize(uint16_t insert_count)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_128);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Insert Count
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), insert_count,
                                  6)) < 0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_header_acknowledgement(uint64_t stream_id)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_128);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Header Acknowledgement
  buf[0] = 0x80;

  // Stream ID
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), stream_id, 7)) <
      0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_write_stream_cancellation(uint64_t stream_id)
{
  IOBufferBlock *instruction = new_IOBufferBlock();
  instruction->alloc(TS_IOBUFFER_SIZE_INDEX_128);

  char *buf     = instruction->end();
  char *buf_end = buf + instruction->write_avail();
  int   written = 0;

  // Stream Cancellation
  buf[0] = 0x40;

  // Stream ID
  int ret;
  if ((ret = xpack_encode_integer(reinterpret_cast<uint8_t *>(buf + written), reinterpret_cast<uint8_t *>(buf_end), stream_id, 7)) <
      0) {
    return ret;
  }
  written += ret;

  // Finalize and Schedule to send
  instruction->fill(written);
  this->_encoder_stream_sending_instructions->append_block(instruction);

  return 0;
}

int
QPACK::_read_insert_with_name_ref(IOBufferReader &reader, bool &is_static, uint16_t &index, Arena &arena, char **value,
                                  size_t &value_len)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16384];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;

  // S flag
  is_static = input[0] & 0x40;

  // Name Index
  uint64_t tmp;
  if ((ret = xpack_decode_integer(tmp, input, input + input_len, 6)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  index     = tmp;
  read_len += ret;

  // Value
  if ((ret = xpack_decode_string(arena, value, tmp, input + read_len, input + input_len, 7)) < 0 && tmp > 0xFF) {
    return -1;
  }
  value_len  = tmp;
  read_len  += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_insert_without_name_ref(IOBufferReader &reader, Arena &arena, char **name, size_t &name_len, char **value,
                                     size_t &value_len)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16384];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;

  // Name
  uint64_t tmp;
  if ((ret = xpack_decode_string(arena, name, tmp, input, input + input_len, 5)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  name_len  = tmp;
  read_len += ret;

  // Value
  if ((ret = xpack_decode_string(arena, value, tmp, input + read_len, input + input_len, 7)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  value_len  = tmp;
  read_len  += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_duplicate(IOBufferReader &reader, uint16_t &index)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;

  // Index
  uint64_t tmp;
  if ((ret = xpack_decode_integer(tmp, input, input + input_len, 5)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  index     = tmp;
  read_len += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_dynamic_table_size_update(IOBufferReader &reader, uint16_t &max_size)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;
  uint64_t tmp;

  // Max Size
  if ((ret = xpack_decode_integer(tmp, input, input + input_len, 5)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  max_size  = tmp;
  read_len += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_table_state_synchronize(IOBufferReader &reader, uint16_t &insert_count)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;
  uint64_t tmp;

  // Insert Count
  if ((ret = xpack_decode_integer(tmp, input, input + input_len, 6)) < 0 && tmp > 0xFFFF) {
    return -1;
  }
  insert_count  = tmp;
  read_len     += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_header_acknowledgement(IOBufferReader &reader, uint64_t &stream_id)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;

  // Stream ID
  // FIXME xpack_decode_integer does not support uint64_t
  if ((ret = xpack_decode_integer(stream_id, input, input + input_len, 7)) < 0) {
    return -1;
  }
  read_len += ret;

  reader.consume(read_len);

  return 0;
}

int
QPACK::_read_stream_cancellation(IOBufferReader &reader, uint64_t &stream_id)
{
  size_t   read_len = 0;
  int      ret;
  uint8_t  input[16];
  uint8_t *p         = reinterpret_cast<uint8_t *>(reader.memcpy(input, sizeof(input)));
  int      input_len = p - input;

  // Stream ID
  // FIXME xpack_decode_integer does not support uint64_t
  if ((ret = xpack_decode_integer(stream_id, input, input + input_len, 6)) < 0) {
    return -1;
  }
  read_len += ret;

  reader.consume(read_len);

  return 0;
}
