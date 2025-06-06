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

   HttpTunnel.cc

   Description:


****************************************************************************/

#include "iocore/cache/Cache.h"
#include "proxy/http/HttpConfig.h"
#include "proxy/http/HttpTunnel.h"
#include "proxy/http/HttpSM.h"
#include "proxy/http/HttpDebugNames.h"

// inkcache
#include "../../iocore/cache/P_CacheInternal.h"

#include "tscore/ParseRules.h"
#include "tscore/ink_memory.h"

#include <algorithm>
#include <cstdint>

namespace
{
DbgCtl dbg_ctl_http_chunk{"http_chunk"};
DbgCtl dbg_ctl_http_redirect{"http_redirect"};
DbgCtl dbg_ctl_http_tunnel{"http_tunnel"};

const int         min_block_transfer_bytes = 256;
const char *const CHUNK_HEADER_FMT         = "%" PRIx64 "\r\n";
// This should be as small as possible because it will only hold the
// header and trailer per chunk - the chunk body will be a reference to
// a block in the input stream.
int const CHUNK_IOBUFFER_SIZE_INDEX = MIN_IOBUFFER_SIZE;

} // end anonymous namespace

ChunkedHandler::ChunkedHandler() : max_chunk_size(DEFAULT_MAX_CHUNK_SIZE) {}

void
ChunkedHandler::init(IOBufferReader *buffer_in, HttpTunnelProducer *p, bool drop_chunked_trailers, bool parse_chunk_strictly)
{
  if (p->do_chunking) {
    init_by_action(buffer_in, Action::DOCHUNK, drop_chunked_trailers, parse_chunk_strictly);
  } else if (p->do_dechunking) {
    init_by_action(buffer_in, Action::DECHUNK, drop_chunked_trailers, parse_chunk_strictly);
  } else {
    init_by_action(buffer_in, Action::PASSTHRU, drop_chunked_trailers, parse_chunk_strictly);
  }
  return;
}

void
ChunkedHandler::init_by_action(IOBufferReader *buffer_in, Action action, bool drop_chunked_trailers, bool parse_chunk_strictly)
{
  running_sum                = 0;
  num_digits                 = 0;
  cur_chunk_size             = 0;
  cur_chunk_bytes_left       = 0;
  truncation                 = false;
  this->action               = action;
  this->strict_chunk_parsing = parse_chunk_strictly;

  switch (action) {
  case Action::DOCHUNK:
    dechunked_reader                   = buffer_in->mbuf->clone_reader(buffer_in);
    dechunked_reader->mbuf->water_mark = min_block_transfer_bytes;
    chunked_buffer                     = new_MIOBuffer(CHUNK_IOBUFFER_SIZE_INDEX);
    chunked_size                       = 0;
    break;
  case Action::DECHUNK:
    chunked_reader   = buffer_in->mbuf->clone_reader(buffer_in);
    dechunked_buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_256);
    dechunked_size   = 0;
    break;
  case Action::PASSTHRU:
    chunked_reader = buffer_in->mbuf->clone_reader(buffer_in);
    if (drop_chunked_trailers) {
      // Note that dropping chunked trailers only applies in the passthrough
      // case in which we are filtering out chunked trailers as we proxy.
      this->drop_chunked_trailers = drop_chunked_trailers;

      // We only need an intermediate buffer when modifying the chunks by
      // filtering out the trailers. Otherwise, a simple passthrough needs no
      // intermediary buffer as consumers will simply read directly from
      // chunked_reader.
      chunked_buffer = new_MIOBuffer(CHUNK_IOBUFFER_SIZE_INDEX);
      chunked_size   = 0;
    }
    break;
  default:
    ink_release_assert(!"Unknown action");
  }

  return;
}

void
ChunkedHandler::clear()
{
  switch (action) {
  case Action::DOCHUNK:
  case Action::PASSTHRU:
    if (chunked_buffer) {
      free_MIOBuffer(chunked_buffer);
    }
    break;
  case Action::DECHUNK:
    free_MIOBuffer(dechunked_buffer);
    break;
  default:
    break;
  }

  return;
}

void
ChunkedHandler::set_max_chunk_size(int64_t size)
{
  max_chunk_size       = size ? size : DEFAULT_MAX_CHUNK_SIZE;
  max_chunk_header_len = snprintf(max_chunk_header, sizeof(max_chunk_header), CHUNK_HEADER_FMT, max_chunk_size);
}

int64_t
ChunkedHandler::read_size()
{
  int64_t bytes_consumed = 0;
  bool    done           = false;

  while (chunked_reader->is_read_avail_more_than(0) && !done) {
    const char *tmp       = chunked_reader->start();
    int64_t     data_size = chunked_reader->block_read_avail();

    ink_assert(data_size > 0);
    int64_t bytes_used = 0;

    while (data_size > 0) {
      bytes_used++;
      if (state == ChunkedState::READ_SIZE) {
        // The http spec says the chunked size is always in hex
        if (ParseRules::is_hex(*tmp)) {
          // Make sure we will not overflow running_sum with our shift.
          if (!can_safely_shift_left(running_sum, 4)) {
            // We have no more space in our variable for the shift.
            state = ChunkedState::READ_ERROR;
            done  = true;
            break;
          }
          num_digits++;
          // Shift over one hex value.
          running_sum <<= 4;

          if (ParseRules::is_digit(*tmp)) {
            running_sum += *tmp - '0';
          } else {
            running_sum += ParseRules::ink_tolower(*tmp) - 'a' + 10;
          }
        } else {
          // We are done parsing size
          const auto is_bogus_chunk_size   = (num_digits == 0 || running_sum < 0);
          const auto is_rfc_compliant_char = (ParseRules::is_ws(*tmp) || ParseRules::is_cr(*tmp) || *tmp == ';');
          const auto is_acceptable_lf      = (ParseRules::is_lf(*tmp) && !strict_chunk_parsing);
          if (is_bogus_chunk_size || (!is_rfc_compliant_char && !is_acceptable_lf)) {
            state = ChunkedState::READ_ERROR;
            done  = true;
            break;
          } else {
            if ((prev_is_cr = ParseRules::is_cr(*tmp)) == true) {
              ++num_cr;
            }
            state = ChunkedState::READ_SIZE_CRLF; // now look for CRLF
          }
        }
      } else if (state == ChunkedState::READ_SIZE_CRLF) { // Scan for a linefeed
        if (ParseRules::is_lf(*tmp)) {
          if (!prev_is_cr) {
            Dbg(dbg_ctl_http_chunk, "Found an LF without a preceding CR (protocol violation)");
            if (strict_chunk_parsing) {
              state = ChunkedState::READ_ERROR;
              done  = true;
              break;
            }
          }
          Dbg(dbg_ctl_http_chunk, "read chunk size of %d bytes", running_sum);
          cur_chunk_bytes_left = (cur_chunk_size = running_sum);
          state                = (running_sum == 0) ? ChunkedState::READ_TRAILER_BLANK : ChunkedState::READ_CHUNK;
          done                 = true;
          num_cr               = 0;
          break;
        } else if ((prev_is_cr = ParseRules::is_cr(*tmp)) == true) {
          if (num_cr != 0) {
            state = ChunkedState::READ_ERROR;
            done  = true;
            break;
          }
          ++num_cr;
        }
      } else if (state == ChunkedState::READ_SIZE_START) {
        Dbg(dbg_ctl_http_chunk, "ChunkedState::READ_SIZE_START 0x%02x", *tmp);
        if (ParseRules::is_lf(*tmp)) {
          if (!prev_is_cr) {
            Dbg(dbg_ctl_http_chunk, "Found an LF without a preceding CR (protocol violation) before chunk size");
            if (strict_chunk_parsing) {
              state = ChunkedState::READ_ERROR;
              done  = true;
              break;
            }
          }
          running_sum = 0;
          num_digits  = 0;
          num_cr      = 0;
          state       = ChunkedState::READ_SIZE;
        } else if ((prev_is_cr = ParseRules::is_cr(*tmp)) == true) {
          if (num_cr != 0) {
            Dbg(dbg_ctl_http_chunk, "Found multiple CRs before chunk size");
            state = ChunkedState::READ_ERROR;
            done  = true;
            break;
          }
          ++num_cr;
        } else { // Unexpected character
          state = ChunkedState::READ_ERROR;
          done  = true;
        }
      }
      tmp++;
      data_size--;
    }
    if (drop_chunked_trailers) {
      chunked_buffer->write(chunked_reader, bytes_used);
      chunked_size += bytes_used;
    }
    chunked_reader->consume(bytes_used);
    bytes_consumed += bytes_used;
  }
  return bytes_consumed;
}

// int ChunkedHandler::transfer_bytes()
//
//   Transfer bytes from chunked_reader to dechunked buffer.
//   Use block reference method when there is a sufficient
//   size to move.  Otherwise, uses memcpy method.
//
int64_t
ChunkedHandler::transfer_bytes()
{
  int64_t block_read_avail, moved, to_move, total_moved = 0;

  // Handle the case where we are doing chunked passthrough.
  if (!dechunked_buffer) {
    moved = std::min(cur_chunk_bytes_left, chunked_reader->read_avail());
    if (drop_chunked_trailers) {
      chunked_buffer->write(chunked_reader, moved);
      chunked_size += moved;
    }
    chunked_reader->consume(moved);
    cur_chunk_bytes_left -= moved;
    return moved;
  }

  while (cur_chunk_bytes_left > 0) {
    block_read_avail = chunked_reader->block_read_avail();

    to_move = std::min(cur_chunk_bytes_left, block_read_avail);
    if (to_move <= 0) {
      break;
    }

    if (to_move >= min_block_transfer_bytes) {
      moved = dechunked_buffer->write(chunked_reader, cur_chunk_bytes_left);
    } else {
      // Small amount of data available.  We want to copy the
      // data rather than block reference to prevent the buildup
      // of too many small blocks which leads to stack overflow
      // on deallocation
      moved = dechunked_buffer->write(chunked_reader->start(), to_move);
    }

    if (moved > 0) {
      chunked_reader->consume(moved);
      cur_chunk_bytes_left  = cur_chunk_bytes_left - moved;
      dechunked_size       += moved;
      total_moved          += moved;
    } else {
      break;
    }
  }
  return total_moved;
}

int64_t
ChunkedHandler::read_chunk()
{
  int64_t transferred_bytes = transfer_bytes();

  ink_assert(cur_chunk_bytes_left >= 0);
  if (cur_chunk_bytes_left == 0) {
    Dbg(dbg_ctl_http_chunk, "completed read of chunk of %" PRId64 " bytes", cur_chunk_size);

    state = ChunkedState::READ_SIZE_START;
  } else if (cur_chunk_bytes_left > 0) {
    Dbg(dbg_ctl_http_chunk, "read %" PRId64 " bytes of an %" PRId64 " chunk", transferred_bytes, cur_chunk_size);
  }
  return transferred_bytes;
}

int64_t
ChunkedHandler::read_trailer()
{
  int64_t bytes_consumed = 0;
  bool    done           = false;

  while (chunked_reader->is_read_avail_more_than(0) && !done) {
    const char *tmp       = chunked_reader->start();
    int64_t     data_size = chunked_reader->block_read_avail();

    ink_assert(data_size > 0);
    int64_t bytes_used = 0;
    for (bytes_used = 0; data_size > 0; data_size--) {
      bytes_used++;

      if (ParseRules::is_cr(*tmp)) {
        // For a CR to signal we are almost done, the preceding
        //  part of the line must be blank and next character
        //  must a LF
        state = (state == ChunkedState::READ_TRAILER_BLANK) ? ChunkedState::READ_TRAILER_CR : ChunkedState::READ_TRAILER_LINE;
      } else if (ParseRules::is_lf(*tmp)) {
        // For a LF to signal we are done reading the
        //   trailer, the line must have either been blank
        //   or must have only had a CR on it
        if (state == ChunkedState::READ_TRAILER_CR || state == ChunkedState::READ_TRAILER_BLANK) {
          state = ChunkedState::READ_DONE;
          Dbg(dbg_ctl_http_chunk, "completed read of trailers");

          if (this->drop_chunked_trailers) {
            // We skip passing through chunked trailers to the peer and only write
            // the final CRLF that ends all chunked content.
            chunked_buffer->write(FINAL_CRLF.data(), FINAL_CRLF.size());
            chunked_size += FINAL_CRLF.size();
          }
          done = true;
          break;
        } else {
          // A LF that does not terminate the trailer
          //  indicates a new line
          state = ChunkedState::READ_TRAILER_BLANK;
        }
      } else {
        // A character that is not a CR or LF indicates
        //  the we are parsing a line of the trailer
        state = ChunkedState::READ_TRAILER_LINE;
      }
      tmp++;
    }
    chunked_reader->consume(bytes_used);
    bytes_consumed += bytes_used;
  }
  return bytes_consumed;
}

std::pair<int64_t, bool>
ChunkedHandler::process_chunked_content()
{
  int64_t bytes_read = 0;
  while (chunked_reader->is_read_avail_more_than(0) && state != ChunkedState::READ_DONE && state != ChunkedState::READ_ERROR) {
    switch (state) {
    case ChunkedState::READ_SIZE:
    case ChunkedState::READ_SIZE_CRLF:
    case ChunkedState::READ_SIZE_START:
      bytes_read += read_size();
      break;
    case ChunkedState::READ_CHUNK:
      bytes_read += read_chunk();
      break;
    case ChunkedState::READ_TRAILER_BLANK:
    case ChunkedState::READ_TRAILER_CR:
    case ChunkedState::READ_TRAILER_LINE:
      bytes_read += read_trailer();
      break;
    case ChunkedState::FLOW_CONTROL:
      return std::make_pair(bytes_read, false);
    default:
      ink_release_assert(0);
      break;
    }
  }
  auto const done = (state == ChunkedState::READ_DONE || state == ChunkedState::READ_ERROR);
  return std::make_pair(bytes_read, done);
}

std::pair<int64_t, bool>
ChunkedHandler::generate_chunked_content()
{
  char    tmp[16];
  bool    server_done = false;
  int64_t r_avail;
  int64_t consumed_bytes = 0;

  ink_assert(max_chunk_header_len);

  switch (last_server_event) {
  case VC_EVENT_EOS:
  case VC_EVENT_READ_COMPLETE:
  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
    server_done = true;
    break;
  }

  while ((r_avail = dechunked_reader->read_avail()) > 0 && state != ChunkedState::WRITE_DONE) {
    int64_t write_val = std::min(max_chunk_size, r_avail);

    state = ChunkedState::WRITE_CHUNK;
    Dbg(dbg_ctl_http_chunk, "creating a chunk of size %" PRId64 " bytes", write_val);

    // Output the chunk size.
    if (write_val != max_chunk_size) {
      int len = snprintf(tmp, sizeof(tmp), CHUNK_HEADER_FMT, write_val);
      chunked_buffer->write(tmp, len);
      chunked_size += len;
    } else {
      chunked_buffer->write(max_chunk_header, max_chunk_header_len);
      chunked_size += max_chunk_header_len;
    }

    // Output the chunk itself.
    //
    // BZ# 54395 Note - we really should only do a
    //   block transfer if there is sizable amount of
    //   data (like we do for the case where we are
    //   removing chunked encoding in ChunkedHandler::transfer_bytes()
    //   However, I want to do this fix with as small a risk
    //   as possible so I'm leaving this issue alone for
    //   now
    //
    chunked_buffer->write(dechunked_reader, write_val);
    chunked_size += write_val;
    dechunked_reader->consume(write_val);
    consumed_bytes += write_val;

    // Output the trailing CRLF.
    chunked_buffer->write("\r\n", 2);
    chunked_size += 2;
  }

  if (server_done) {
    state = ChunkedState::WRITE_DONE;

    // Add the chunked transfer coding trailer.
    chunked_buffer->write("0\r\n\r\n", 5);
    chunked_size += 5;
    return std::make_pair(consumed_bytes, true);
  }
  return std::make_pair(consumed_bytes, false);
}

HttpTunnelProducer::HttpTunnelProducer() : consumer_list() {}

uint64_t
HttpTunnelProducer::backlog(uint64_t limit)
{
  uint64_t zret = 0;
  // Calculate the total backlog, the # of bytes inside ATS for this producer.
  // We go all the way through each chain to the ending sink and take the maximum
  // over those paths. Do need to be careful about loops which can occur.
  for (HttpTunnelConsumer *c = consumer_list.head; c; c = c->link.next) {
    if (c->alive && c->write_vio) {
      uint64_t n = 0;
      if (HttpTunnelType_t::TRANSFORM == c->vc_type) {
        n += static_cast<TransformVCChain *>(c->vc)->backlog(limit);
      } else {
        IOBufferReader *r = c->write_vio->get_reader();
        if (r) {
          n += static_cast<uint64_t>(r->read_avail());
        }
      }
      if (n >= limit) {
        return n;
      }

      if (!c->is_sink()) {
        HttpTunnelProducer *dsp = c->self_producer;
        if (dsp) {
          n += dsp->backlog();
        }
      }
      if (n >= limit) {
        return n;
      }
      if (n > zret) {
        zret = n;
      }
    }
  }

  if (chunked_handler.chunked_reader) {
    zret += static_cast<uint64_t>(chunked_handler.chunked_reader->read_avail());
  }

  return zret;
}

/*  We set the producers in a flow chain specifically rather than
    using a tunnel level variable in order to handle bi-directional
    tunnels correctly. In such a case the flow control on producers is
    not related so a single value for the tunnel won't work.
*/
void
HttpTunnelProducer::set_throttle_src(HttpTunnelProducer *srcp)
{
  HttpTunnelProducer *p  = this;
  p->flow_control_source = srcp;
  for (HttpTunnelConsumer *c = consumer_list.head; c; c = c->link.next) {
    if (!c->is_sink()) {
      p = c->self_producer;
      if (p) {
        p->set_throttle_src(srcp);
      }
    }
  }
}

HttpTunnelConsumer::HttpTunnelConsumer() : link() {}

HttpTunnel::HttpTunnel() : Continuation(nullptr) {}

void
HttpTunnel::init(HttpSM *sm_arg, Ptr<ProxyMutex> &amutex)
{
  HttpConfigParams *params = sm_arg->t_state.http_config_param;
  sm                       = sm_arg;
  active                   = false;
  mutex                    = amutex;
  ink_release_assert(reentrancy_count == 0);
  SET_HANDLER(&HttpTunnel::main_handler);
  flow_state.enabled_p = params->oride.flow_control_enabled;
  if (params->oride.flow_low_water_mark > 0) {
    flow_state.low_water = params->oride.flow_low_water_mark;
  }
  if (params->oride.flow_high_water_mark > 0) {
    flow_state.high_water = params->oride.flow_high_water_mark;
  }
  // This should always be true, we handled default cases back in HttpConfig::reconfigure()
  ink_assert(flow_state.low_water <= flow_state.high_water);
}

void
HttpTunnel::reset()
{
  ink_assert(active == false);
#ifdef DEBUG
  for (auto &producer : producers) {
    ink_assert(producer.alive == false);
  }
  for (auto &consumer : consumers) {
    ink_assert(consumer.alive == false);
  }
#endif

  call_sm       = false;
  num_producers = 0;
  num_consumers = 0;
  ink_zero(consumers);
  ink_zero(producers);
}

void
HttpTunnel::kill_tunnel()
{
  for (auto &producer : producers) {
    if (producer.vc != nullptr) {
      chain_abort_all(&producer);
    }
    ink_assert(producer.alive == false);
  }
  active = false;
  this->mark_tls_tunnel_inactive();
  this->deallocate_buffers();
  this->reset();
}

void
HttpTunnel::abort_tunnel()
{
  active = false;
  deallocate_buffers();
  for (auto &producer : producers) {
    if (producer.alive && producer.vc) {
      producer.vc->do_io_read(this, 0, nullptr);
    }
    producer.alive = false;
  }
  for (auto &consumer : consumers) {
    if (consumer.alive && consumer.vc) {
      consumer.vc->do_io_write(this, 0, nullptr);
    }
    consumer.alive = false;
  }
  reset();
}

HttpTunnelProducer *
HttpTunnel::alloc_producer()
{
  for (int i = 0; i < MAX_PRODUCERS; ++i) {
    if (producers[i].vc == nullptr) {
      num_producers++;
      ink_assert(num_producers <= MAX_PRODUCERS);
      return producers + i;
    }
  }
  ink_release_assert(0);
  return nullptr;
}

HttpTunnelConsumer *
HttpTunnel::alloc_consumer()
{
  for (int i = 0; i < MAX_CONSUMERS; i++) {
    if (consumers[i].vc == nullptr) {
      num_consumers++;
      ink_assert(num_consumers <= MAX_CONSUMERS);
      return consumers + i;
    }
  }
  ink_release_assert(0);
  return nullptr;
}

int
HttpTunnel::deallocate_buffers()
{
  int num = 0;
  ink_release_assert(active == false);
  for (auto &producer : producers) {
    if (producer.read_buffer != nullptr) {
      ink_assert(producer.vc != nullptr);
      free_MIOBuffer(producer.read_buffer);
      producer.read_buffer  = nullptr;
      producer.buffer_start = nullptr;
      num++;
    }

    if (producer.chunked_handler.dechunked_buffer != nullptr) {
      ink_assert(producer.vc != nullptr);
      free_MIOBuffer(producer.chunked_handler.dechunked_buffer);
      producer.chunked_handler.dechunked_buffer = nullptr;
      num++;
    }

    if (producer.chunked_handler.chunked_buffer != nullptr) {
      ink_assert(producer.vc != nullptr);
      free_MIOBuffer(producer.chunked_handler.chunked_buffer);
      producer.chunked_handler.chunked_buffer = nullptr;
      num++;
    }
    producer.chunked_handler.max_chunk_header_len = 0;
  }
  return num;
}

void
HttpTunnel::set_producer_chunking_action(HttpTunnelProducer *p, int64_t skip_bytes, TunnelChunkingAction_t action,
                                         bool drop_chunked_trailers, bool parse_chunk_strictly)
{
  this->http_drop_chunked_trailers = drop_chunked_trailers;
  this->http_strict_chunk_parsing  = parse_chunk_strictly;
  p->chunked_handler.skip_bytes    = skip_bytes;
  p->chunking_action               = action;

  switch (action) {
  case TunnelChunkingAction_t::CHUNK_CONTENT:
    p->chunked_handler.state = ChunkedHandler::ChunkedState::WRITE_CHUNK;
    break;
  case TunnelChunkingAction_t::DECHUNK_CONTENT:
  case TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT:
    p->chunked_handler.state = ChunkedHandler::ChunkedState::READ_SIZE;
    break;
  default:
    break;
  };
}

void
HttpTunnel::set_producer_chunking_size(HttpTunnelProducer *p, int64_t size)
{
  p->chunked_handler.set_max_chunk_size(size);
}

// HttpTunnelProducer* HttpTunnel::add_producer
//
//   Adds a new producer to the tunnel
//
HttpTunnelProducer *
HttpTunnel::add_producer(VConnection *vc, int64_t nbytes_arg, IOBufferReader *reader_start, HttpProducerHandler sm_handler,
                         HttpTunnelType_t vc_type, const char *name_arg)
{
  HttpTunnelProducer *p;

  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] adding producer '%s'", sm->sm_id, name_arg);

  ink_assert(reader_start->mbuf);
  if ((p = alloc_producer()) != nullptr) {
    p->vc              = vc;
    p->total_bytes     = nbytes_arg;
    p->buffer_start    = reader_start;
    p->read_buffer     = reader_start->mbuf;
    p->vc_handler      = sm_handler;
    p->vc_type         = vc_type;
    p->name            = name_arg;
    p->chunking_action = TunnelChunkingAction_t::PASSTHRU_DECHUNKED_CONTENT;

    p->do_chunking         = false;
    p->do_dechunking       = false;
    p->do_chunked_passthru = false;

    p->init_bytes_done = p->buffer_start->read_avail();
    if (p->total_bytes < 0 || p->total_bytes == INT64_MAX) {
      p->total_bytes = INT64_MAX; // A negative nbytes_arg is a synonym for INT64_MAX.
      p->ntodo       = INT64_MAX;
    } else { // The byte count given us includes bytes
      //  that already may be in the buffer.
      //  ntodo represents the number of bytes
      //  the tunneling mechanism needs to read
      //  for the producer
      p->ntodo = std::max(p->total_bytes - p->init_bytes_done, INT64_C(0));
      ink_assert(p->ntodo >= 0);
    }

    // We are static, the producer is never "alive"
    //   It just has data in the buffer
    if (vc == HTTP_TUNNEL_STATIC_PRODUCER) {
      ink_assert(p->ntodo >= 0);
      p->alive        = false;
      p->read_success = true;
    } else {
      p->alive = true;
    }
  }
  return p;
}

// void HttpTunnel::add_consumer
//
//    Adds a new consumer to the tunnel.  The producer must
//    be specified and already added to the tunnel.  Attaches
//    the new consumer to the entry for the existing producer
//
//    Returns true if the consumer successfully added.  Returns
//    false if the consumer was not added because the source failed
//
HttpTunnelConsumer *
HttpTunnel::add_consumer(VConnection *vc, VConnection *producer, HttpConsumerHandler sm_handler, HttpTunnelType_t vc_type,
                         const char *name_arg, int64_t skip_bytes)
{
  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] adding consumer '%s'", sm->sm_id, name_arg);

  // Find the producer entry
  HttpTunnelProducer *p = get_producer(producer);
  ink_release_assert(p);

  // Check to see if the producer terminated
  //  without sending all of its data
  if (p->alive == false && p->read_success == false) {
    Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] consumer '%s' not added due to producer failure", sm->sm_id, name_arg);
    return nullptr;
  }
  // Initialize the consumer structure
  HttpTunnelConsumer *c = alloc_consumer();
  c->producer           = p;
  c->vc                 = vc;
  c->alive              = true;
  c->skip_bytes         = skip_bytes;
  c->vc_handler         = sm_handler;
  c->vc_type            = vc_type;
  c->name               = name_arg;

  // Register the consumer with the producer
  p->consumer_list.push(c);
  p->num_consumers++;

  return c;
}

void
HttpTunnel::chain(HttpTunnelConsumer *c, HttpTunnelProducer *p)
{
  p->self_consumer = c;
  c->self_producer = p;
  // If the flow is already throttled update the chained producer.
  if (c->producer->is_throttled()) {
    p->set_throttle_src(c->producer->flow_control_source);
  }
}

// void HttpTunnel::tunnel_run()
//
//    Makes the tunnel go
//
void
HttpTunnel::tunnel_run(HttpTunnelProducer *p_arg)
{
  ++reentrancy_count;
  Dbg(dbg_ctl_http_tunnel, "tunnel_run started, p_arg is %s", p_arg ? "provided" : "NULL");
  if (p_arg) {
    producer_run(p_arg);
  } else {
    HttpTunnelProducer *p;

    ink_assert(active == false);

    for (int i = 0; i < MAX_PRODUCERS; ++i) {
      p = producers + i;
      if (p->vc != nullptr && (p->alive || (p->vc_type == HttpTunnelType_t::STATIC && p->buffer_start != nullptr))) {
        producer_run(p);
      }
    }
  }
  --reentrancy_count;

  // It is possible that there was nothing to do
  //   due to a all transfers being zero length
  //   If that is the case, call the state machine
  //   back to say we are done
  if (!is_tunnel_alive()) {
    active = false;
    sm->handleEvent(HTTP_TUNNEL_EVENT_DONE, this);
  }
}

void
HttpTunnel::producer_run(HttpTunnelProducer *p)
{
  // Determine whether the producer has a cache-write consumer,
  // since all chunked content read by the producer gets dechunked
  // prior to being written into the cache.
  HttpTunnelConsumer *c, *cache_write_consumer = nullptr;
  bool                transform_consumer = false;

  for (c = p->consumer_list.head; c; c = c->link.next) {
    if (c->vc_type == HttpTunnelType_t::CACHE_WRITE) {
      cache_write_consumer = c;
      break;
    }
  }

  // bz57413
  for (c = p->consumer_list.head; c; c = c->link.next) {
    if (c->vc_type == HttpTunnelType_t::TRANSFORM) {
      transform_consumer = true;
      break;
    }
  }

  // Determine whether the producer is to perform chunking,
  // dechunking, or chunked-passthough of the incoming response.
  TunnelChunkingAction_t action = p->chunking_action;

  // [bug 2579251] static producers won't have handler set
  if (p->vc != HTTP_TUNNEL_STATIC_PRODUCER) {
    if (action == TunnelChunkingAction_t::CHUNK_CONTENT) {
      p->do_chunking = true;
    } else if (action == TunnelChunkingAction_t::DECHUNK_CONTENT) {
      p->do_dechunking = true;
    } else if (action == TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT) {
      p->do_chunked_passthru = true;

      // Dechunk the chunked content into the cache.
      if (cache_write_consumer != nullptr) {
        p->do_dechunking = true;
      }
    }
  }
  if (!p->is_handling_chunked_content()) {
    // If we are not handling chunked content, then we will be consuming all the
    // bytes available in the reader, up until the total bytes that the tunnel
    // will be processing.
    p->bytes_consumed += std::min(p->total_bytes, p->init_bytes_done);
  }

  int64_t consumer_n = 0;
  int64_t producer_n = 0;

  ink_assert(p->vc != nullptr);
  active = true;

  IOBufferReader *chunked_buffer_start     = nullptr;
  IOBufferReader *dechunked_buffer_start   = nullptr;
  IOBufferReader *passthrough_buffer_start = nullptr;
  if (p->is_handling_chunked_content()) {
    // For all the chunking cases, we must only copy bytes as we process them.
    body_bytes_to_copy = 0;

    p->chunked_handler.init(p->buffer_start, p, this->http_drop_chunked_trailers, this->http_strict_chunk_parsing);

    // Copy the header into the chunked/dechunked buffers.
    if (p->do_chunking) {
      // initialize a reader to chunked buffer start before writing to keep ref count
      chunked_buffer_start = p->chunked_handler.chunked_buffer->alloc_reader();
      p->chunked_handler.chunked_buffer->write(p->buffer_start, p->chunked_handler.skip_bytes);
    }
    if (p->do_dechunking) {
      // bz57413
      Dbg(dbg_ctl_http_tunnel, "[producer_run] do_dechunking p->chunked_handler.chunked_reader->read_avail() = %" PRId64 "",
          p->chunked_handler.chunked_reader->read_avail());

      // initialize a reader to dechunked buffer start before writing to keep ref count
      dechunked_buffer_start = p->chunked_handler.dechunked_buffer->alloc_reader();

      // If there is no transformation then add the header to the buffer, else the
      // client already has got the header from us, no need for it in the buffer.
      if (!transform_consumer) {
        p->chunked_handler.dechunked_buffer->write(p->buffer_start, p->chunked_handler.skip_bytes);

        Dbg(dbg_ctl_http_tunnel, "[producer_run] do_dechunking::Copied header of size %" PRId64 "", p->chunked_handler.skip_bytes);
      }
    }
    if (p->chunked_handler.drop_chunked_trailers) {
      // initialize a reader to passthrough buffer start before writing to keep ref count
      passthrough_buffer_start = p->chunked_handler.chunked_buffer->alloc_reader();
      p->chunked_handler.chunked_buffer->write(p->buffer_start, p->chunked_handler.skip_bytes);
    }
  }

  int64_t read_start_pos = 0;
  if (p->vc_type == HttpTunnelType_t::CACHE_READ &&
      sm->t_state.range_setup == HttpTransact::RangeSetup_t::NOT_TRANSFORM_REQUESTED) {
    ink_assert(sm->t_state.num_range_fields == 1); // we currently just support only one range entry
    read_start_pos = sm->t_state.ranges[0]._start;
    producer_n     = (sm->t_state.ranges[0]._end - sm->t_state.ranges[0]._start) + 1;
    consumer_n     = (producer_n + sm->client_response_hdr_bytes);
  } else if (p->total_bytes >= 0) {
    consumer_n = p->total_bytes;
    producer_n = p->ntodo;
  } else {
    consumer_n = (producer_n = INT64_MAX);
  }

  if (!p->is_handling_chunked_content()) {
    // No chunking being handled, so the user specified a number of bytes
    // described by Content-Length. Use that value.
    body_bytes_to_copy = producer_n - body_bytes_copied;
  }

  // At least set up the consumer readers first so the data
  // doesn't disappear out from under the tunnel
  for (c = p->consumer_list.head; c; c = c->link.next) {
    // Create a reader for each consumer.  The reader allows
    // us to implement skip bytes
    if (c->vc_type == HttpTunnelType_t::CACHE_WRITE) {
      switch (action) {
      case TunnelChunkingAction_t::CHUNK_CONTENT:
      case TunnelChunkingAction_t::PASSTHRU_DECHUNKED_CONTENT:
        c->buffer_reader = p->read_buffer->clone_reader(p->buffer_start);
        break;
      case TunnelChunkingAction_t::DECHUNK_CONTENT:
      case TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT:
        c->buffer_reader = p->chunked_handler.dechunked_buffer->clone_reader(dechunked_buffer_start);
        break;
      default:
        break;
      }
    }
    // Non-cache consumers.
    else if (action == TunnelChunkingAction_t::CHUNK_CONTENT) {
      c->buffer_reader = p->chunked_handler.chunked_buffer->clone_reader(chunked_buffer_start);
    } else if (action == TunnelChunkingAction_t::DECHUNK_CONTENT) {
      c->buffer_reader = p->chunked_handler.dechunked_buffer->clone_reader(dechunked_buffer_start);
    } else if (action == TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT) {
      if (p->chunked_handler.drop_chunked_trailers) {
        c->buffer_reader = p->chunked_handler.chunked_buffer->clone_reader(passthrough_buffer_start);
      } else {
        c->buffer_reader = p->read_buffer->clone_reader(p->buffer_start);
      }
    } else { // TunnelChunkingAction_t::PASSTHRU_DECHUNKED_CONTENT
      c->buffer_reader = p->read_buffer->clone_reader(p->buffer_start);
    }

    // Consume bytes from the reader if we are skipping bytes.
    if (c->skip_bytes > 0) {
      ink_release_assert(c->skip_bytes <= c->buffer_reader->read_avail());
      c->buffer_reader->consume(c->skip_bytes);
    }
  }

  // YTS Team, yamsat Plugin
  // Allocate and copy partial POST data to buffers. Check for the various parameters
  // including the maximum configured post data size
  if ((p->vc_type == HttpTunnelType_t::BUFFER_READ && sm->is_postbuf_valid()) ||
      (p->alive && sm->t_state.method == HTTP_WKSIDX_POST && sm->enable_redirection &&
       p->vc_type == HttpTunnelType_t::HTTP_CLIENT)) {
    Dbg(dbg_ctl_http_redirect, "[HttpTunnel::producer_run] client post: %" PRId64 " max size: %" PRId64 "",
        p->buffer_start->read_avail(), HttpConfig::m_master.post_copy_size);

    // (note that since we are not dechunking POST, this is the chunked size if chunked)
    if (p->buffer_start->read_avail() > HttpConfig::m_master.post_copy_size) {
      Warning("http_redirect, [HttpTunnel::producer_handler] post exceeds buffer limit, buffer_avail=%" PRId64 " limit=%" PRId64 "",
              p->buffer_start->read_avail(), HttpConfig::m_master.post_copy_size);
      sm->disable_redirect();
      if (p->vc_type == HttpTunnelType_t::BUFFER_READ) {
        producer_handler(VC_EVENT_ERROR, p);
        return;
      }
    } else {
      body_bytes_copied  += sm->postbuf_copy_partial_data(body_bytes_to_copy);
      body_bytes_to_copy  = 0;
    }
  } // end of added logic for partial POST

  if (p->do_chunking) {
    // remove the chunked reader marker so that it doesn't act like a buffer guard
    p->chunked_handler.chunked_buffer->dealloc_reader(chunked_buffer_start);
    p->chunked_handler.dechunked_reader->consume(p->chunked_handler.skip_bytes);
    p->bytes_consumed += p->chunked_handler.skip_bytes;

    // If there is data to process in the buffer, do it now
    producer_handler(VC_EVENT_READ_READY, p);
  } else if (p->do_dechunking || p->do_chunked_passthru) {
    // remove the dechunked reader marker so that it doesn't act like a buffer guard
    if (p->do_dechunking && dechunked_buffer_start) {
      p->chunked_handler.dechunked_buffer->dealloc_reader(dechunked_buffer_start);
    }
    if (p->do_chunked_passthru && passthrough_buffer_start) {
      p->chunked_handler.chunked_buffer->dealloc_reader(passthrough_buffer_start);
    }

    // bz57413
    // If there is no transformation plugin, then we didn't add the header, hence no need to consume it
    Dbg(dbg_ctl_http_tunnel, "[producer_run] do_dechunking p->chunked_handler.chunked_reader->read_avail() = %" PRId64 "",
        p->chunked_handler.chunked_reader->read_avail());
    if (!transform_consumer && (p->chunked_handler.chunked_reader->read_avail() >= p->chunked_handler.skip_bytes)) {
      p->chunked_handler.chunked_reader->consume(p->chunked_handler.skip_bytes);
      p->bytes_consumed += p->chunked_handler.skip_bytes;
      Dbg(dbg_ctl_http_tunnel, "[producer_run] do_dechunking p->chunked_handler.skip_bytes = %" PRId64 "",
          p->chunked_handler.skip_bytes);
    }

    producer_handler(VC_EVENT_READ_READY, p);
    if (sm->get_postbuf_done() && p->vc_type == HttpTunnelType_t::HTTP_CLIENT) { // read_avail() == 0
      // [bug 2579251]
      // Ugh, this is horrible but in the redirect case they are running a the tunnel again with the
      // now closed/empty producer to trigger PRECOMPLETE.  If the POST was chunked, producer_n is set
      // (incorrectly) to INT64_MAX.  It needs to be set to 0 to prevent triggering another read.
      producer_n = 0;
    }
  }
  for (c = p->consumer_list.head; c; c = c->link.next) {
    int64_t c_write = consumer_n;

    // Don't bother to set up the consumer if it is dead
    if (!c->alive) {
      continue;
    }

    if (!p->alive) {
      // Adjust the amount of chunked data to write if the only data was in the initial read
      // The amount to write in some cases is dependent on the type of the consumer, so this
      // value must be computed for each consumer
      c_write = final_consumer_bytes_to_write(p, c);
    } else {
      // INKqa05109 - if we don't know the length leave it at
      //  INT64_MAX or else the cache may bounce the write
      //  because it thinks the document is too big.  INT64_MAX
      //  is a special case for the max document size code
      //  in the cache
      if (c_write != INT64_MAX) {
        c_write -= c->skip_bytes;
      }
      // Fix for problems with not chunked content being chunked and
      // not sending the entire data.  The content length grows when
      // it is being chunked.
      if (p->do_chunking == true) {
        c_write = INT64_MAX;
      }
    }

    if (c_write == 0) {
      // Nothing to do, call back the cleanup handlers
      c->write_vio = nullptr;
      consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
    } else {
      // In the client half close case, all the data that will be sent
      // from the client is already in the buffer.  Go ahead and set
      // the amount to read since we know it.  We will forward the FIN
      // to the server on VC_EVENT_WRITE_COMPLETE.
      if (p->vc_type == HttpTunnelType_t::HTTP_CLIENT) {
        ProxyTransaction *ua_vc = static_cast<ProxyTransaction *>(p->vc);
        if (ua_vc->get_half_close_flag()) {
          int tmp = c->buffer_reader->read_avail();
          if (tmp < c_write) {
            c_write = tmp;
          }
          p->alive         = false;
          p->handler_state = static_cast<int>(HttpSmPost_t::SUCCESS);
        }
      }
      Dbg(dbg_ctl_http_tunnel, "Start write vio %" PRId64 " bytes", c_write);
      // Start the writes now that we know we will consume all the initial data
      c->write_vio = c->vc->do_io_write(this, c_write, c->buffer_reader);
      ink_assert(c_write > 0);
      if (c->write_vio == nullptr) {
        consumer_handler(VC_EVENT_ERROR, c);
      } else if (c->write_vio->ntodo() == 0 && c->alive) {
        consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
      }
    }
  }
  if (p->alive) {
    ink_assert(producer_n >= 0);

    if (producer_n == 0) {
      // Everything is already in the buffer so mark the producer as done.  We need to notify
      // state machine that everything is done.  We use a special event to say the producers is
      // done but we didn't do anything
      p->alive         = false;
      p->read_success  = true;
      p->handler_state = static_cast<int>(HttpSmPost_t::SUCCESS);
      Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] [tunnel_run] producer already done", sm->sm_id);
      producer_handler(HTTP_TUNNEL_EVENT_PRECOMPLETE, p);
    } else {
      if (read_start_pos > 0) {
        p->read_vio = static_cast<CacheVConnection *>(p->vc)->do_io_pread(this, producer_n, p->read_buffer, read_start_pos);
      } else {
        Dbg(dbg_ctl_http_tunnel, "Start read vio %" PRId64 " bytes", producer_n);
        p->read_vio = p->vc->do_io_read(this, producer_n, p->read_buffer);
        p->read_vio->reenable();
      }
    }
  } else {
    // If the producer is not alive (precomplete) make sure to kick the consumers
    for (c = p->consumer_list.head; c; c = c->link.next) {
      if (c->alive && c->write_vio) {
        c->write_vio->reenable();
      }
    }
  }

  // Now that the tunnel has started, we must remove producer's reader so
  // that it doesn't act like a buffer guard
  if (p->read_buffer && p->buffer_start) {
    p->read_buffer->dealloc_reader(p->buffer_start);
  }
  p->buffer_start = nullptr;
}

int
HttpTunnel::producer_handler_dechunked(int event, HttpTunnelProducer *p)
{
  ink_assert(p->do_chunking);

  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] producer_handler_dechunked [%s %s]", sm->sm_id, p->name,
      HttpDebugNames::get_event_name(event));

  // We only interested in translating certain events
  switch (event) {
  case VC_EVENT_READ_COMPLETE:
  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
  case VC_EVENT_EOS:
    p->alive = false; // Update the producer state for final_consumer_bytes_to_write
    /* fallthrough */
  case VC_EVENT_READ_READY:
    p->last_event = p->chunked_handler.last_server_event  = event;
    auto const [consumed_bytes, done]                     = p->chunked_handler.generate_chunked_content();
    p->bytes_consumed                                    += consumed_bytes;
    body_bytes_to_copy                                    = consumed_bytes;
    if (done) { // We are done, make sure the consumer is activated
      HttpTunnelConsumer *c;
      for (c = p->consumer_list.head; c; c = c->link.next) {
        if (c->alive) {
          c->write_vio->nbytes = final_consumer_bytes_to_write(p, c);
          // consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
        }
      }
    }
    break;
  };
  // Since we will consume all the data if the server is actually finished
  //   we don't have to translate events like we do in the
  //   case producer_handler_chunked()
  return event;
}

// int HttpTunnel::producer_handler_chunked(int event, HttpTunnelProducer* p)
//
//   Handles events from chunked producers.  It calls the chunking handlers
//    if appropriate and then translates the event we got into a suitable
//    event to represent the unchunked state, and does chunked bookkeeping
//
int
HttpTunnel::producer_handler_chunked(int event, HttpTunnelProducer *p)
{
  ink_assert(p->do_dechunking || p->do_chunked_passthru);

  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] producer_handler_chunked [%s %s]", sm->sm_id, p->name,
      HttpDebugNames::get_event_name(event));

  // We only interested in translating certain events
  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
  case VC_EVENT_EOS:
    break;
  default:
    return event;
  }

  p->last_event = p->chunked_handler.last_server_event  = event;
  auto const [bytes_consumed, done]                     = p->chunked_handler.process_chunked_content();
  p->bytes_consumed                                    += bytes_consumed;
  body_bytes_to_copy                                    = bytes_consumed;

  // If we couldn't understand the encoding, return
  //   an error
  if (p->chunked_handler.state == ChunkedHandler::ChunkedState::READ_ERROR) {
    Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] producer_handler_chunked [%s chunk decoding error]", sm->sm_id, p->name);
    p->chunked_handler.truncation = true;
    return HTTP_TUNNEL_EVENT_PARSE_ERROR;
  }

  switch (event) {
  case VC_EVENT_READ_READY:
    if (done) {
      return VC_EVENT_READ_COMPLETE;
    }
    break;
  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
  case VC_EVENT_EOS:
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    if (!done) {
      p->chunked_handler.truncation = true;
    }
    break;
  }

  return event;
}

//
// bool HttpTunnel::producer_handler(int event, HttpTunnelProducer* p)
//
//   Handles events from producers.
//
//   If the event is interesting only to the tunnel, this
//    handler takes all necessary actions and returns false
//    If the event is interesting to the state_machine,
//    it calls back the state machine and returns true
//
//
bool
HttpTunnel::producer_handler(int event, HttpTunnelProducer *p)
{
  HttpTunnelConsumer *c;
  HttpProducerHandler jump_point;
  bool                sm_callback = false;

  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] producer_handler [%s %s]", sm->sm_id, p->name, HttpDebugNames::get_event_name(event));

  // Handle chunking/dechunking/chunked-passthrough if necessary.
  if (p->do_chunking) {
    // This will update body_bytes_to_copy with the number of bytes copied.
    event = producer_handler_dechunked(event, p);
  } else if (p->do_dechunking || p->do_chunked_passthru) {
    // This will update body_bytes_to_copy with the number of bytes copied.
    event = producer_handler_chunked(event, p);
  } else {
    p->last_event = event;
  }

  // YTS Team, yamsat Plugin
  // Copy partial POST data to buffers. Check for the various parameters including
  // the maximum configured post data size
  if ((p->vc_type == HttpTunnelType_t::BUFFER_READ && sm->is_postbuf_valid()) ||
      (sm->t_state.method == HTTP_WKSIDX_POST && sm->enable_redirection &&
       (event == VC_EVENT_READ_READY || event == VC_EVENT_READ_COMPLETE) && p->vc_type == HttpTunnelType_t::HTTP_CLIENT)) {
    Dbg(dbg_ctl_http_redirect, "[HttpTunnel::producer_handler] [%s %s]", p->name, HttpDebugNames::get_event_name(event));

    if ((sm->postbuf_buffer_avail() + sm->postbuf_reader_avail()) > HttpConfig::m_master.post_copy_size) {
      Warning("http_redirect, [HttpTunnel::producer_handler] post exceeds buffer limit, buffer_avail=%" PRId64
              " reader_avail=%" PRId64 " limit=%" PRId64 "",
              sm->postbuf_buffer_avail(), sm->postbuf_reader_avail(), HttpConfig::m_master.post_copy_size);
      sm->disable_redirect();
      if (p->vc_type == HttpTunnelType_t::BUFFER_READ) {
        event = VC_EVENT_ERROR;
      }
    } else {
      if (!p->is_handling_chunked_content()) {
        // The chunk handlers didn't consume bytes. Pull bytes as needed.
        body_bytes_to_copy = p->total_bytes - body_bytes_copied;
      }
      body_bytes_copied  += sm->postbuf_copy_partial_data(body_bytes_to_copy);
      body_bytes_to_copy  = 0;
      if (event == VC_EVENT_READ_COMPLETE || event == HTTP_TUNNEL_EVENT_PRECOMPLETE || event == VC_EVENT_EOS) {
        sm->set_postbuf_done(true);
      }
    }
  } // end of added logic for partial copy of POST

  Dbg(dbg_ctl_http_redirect, "[%" PRId64 "] enable_redirection: [%d %d %d] event: %d, state: %d", sm->sm_id, p->alive == true,
      sm->enable_redirection, (p->self_consumer && p->self_consumer->alive == true), event,
      static_cast<int>(p->chunked_handler.state));

  switch (event) {
  case VC_EVENT_READ_READY:
    if (sm->get_tunnel_type() != SNIRoutingType::NONE) {
      mark_tls_tunnel_active();
    }

    // Data read from producer, reenable consumers
    for (c = p->consumer_list.head; c; c = c->link.next) {
      if (c->alive && c->write_vio) {
        Dbg(dbg_ctl_http_redirect, "Read ready alive");
        c->write_vio->reenable();
      }
    }
    break;

  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
    // If the write completes on the stack (as it can for http2), then
    // consumer could have called back by this point.  Must treat this as
    // a regular read complete (falling through to the following cases).
    [[fallthrough]];

  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_EOS:
    // The producer completed
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
      if (!p->is_handling_chunked_content()) {
        p->bytes_consumed += p->bytes_read;
      }
    } else {
      // If we are chunked, we can receive the whole document
      //   along with the header without knowing it (due to
      //   the message length being a property of the encoding)
      //   In that case, we won't have done a do_io so there
      //   will not be vio
    }

    // callback the SM to notify of completion
    //  Note: we need to callback the SM before
    //  reenabling the consumers as the reenable may
    //  make the data visible to the consumer and
    //  initiate async I/O operation.  The SM needs to
    //  set how much I/O to do before async I/O is
    //  initiated
    jump_point = p->vc_handler;
    (sm->*jump_point)(event, p);
    sm_callback = true;
    p->update_state_if_not_set(static_cast<int>(HttpSmPost_t::SUCCESS));

    // Kick off the consumers if appropriate
    for (c = p->consumer_list.head; c; c = c->link.next) {
      if (c->alive && c->write_vio) {
        if (c->write_vio->nbytes == INT64_MAX) {
          c->write_vio->nbytes = p->bytes_consumed - c->skip_bytes;
        }
        c->write_vio->reenable();
      }
    }
    break;

  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case HTTP_TUNNEL_EVENT_CONSUMER_DETACH:
  case HTTP_TUNNEL_EVENT_PARSE_ERROR:
    if (p->alive) {
      p->alive = false;
      if (p->read_vio) {
        p->bytes_read = p->read_vio->ndone;
        if (!p->is_handling_chunked_content()) {
          p->bytes_consumed += p->bytes_read;
        }
      } else {
        p->bytes_read = 0;
      }
      // Clear any outstanding reads so they don't
      // collide with future tunnel IO's
      p->vc->do_io_read(nullptr, 0, nullptr);
      // Interesting tunnel event, call SM
      jump_point = p->vc_handler;
      (sm->*jump_point)(event, p);
      sm_callback = true;
      // Failure case anyway
      p->update_state_if_not_set(static_cast<int>(HttpSmPost_t::UA_FAIL));
    }
    break;

  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
  default:
    // Producers should not get these events
    ink_release_assert(0);
    break;
  }

  return sm_callback;
}

void
HttpTunnel::consumer_reenable(HttpTunnelConsumer *c)
{
  HttpTunnelProducer *p = c->producer;

  if (p && p->alive) {
    // Only do flow control if enabled and the producer is an external
    // source.  Otherwise disable by making the backlog zero. Because
    // the backlog short cuts quit when the value is equal (or
    // greater) to the target, we use strict comparison only for
    // checking low water, otherwise the flow control can stall out.
    uint64_t            backlog = (flow_state.enabled_p && p->is_source()) ? p->backlog(flow_state.high_water) : 0;
    HttpTunnelProducer *srcp    = p->flow_control_source;

    if (backlog >= flow_state.high_water) {
      if (dbg_ctl_http_tunnel.on()) {
        Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] Throttle   %p %" PRId64 " / %" PRId64, sm->sm_id, p, backlog, p->backlog());
      }
      p->throttle(); // p becomes srcp for future calls to this method
    } else {
      if (srcp && srcp->alive && c->is_sink()) {
        // Check if backlog is below low water - note we need to check
        // against the source producer, not necessarily the producer
        // for this consumer. We don't have to recompute the backlog
        // if they are the same because we know low water <= high
        // water so the value is sufficiently accurate.
        if (srcp != p) {
          backlog = srcp->backlog(flow_state.low_water);
        }
        if (backlog < flow_state.low_water) {
          if (dbg_ctl_http_tunnel.on()) {
            Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] Unthrottle %p %" PRId64 " / %" PRId64, sm->sm_id, p, backlog, p->backlog());
          }
          srcp->unthrottle();
          if (srcp->read_vio) {
            srcp->read_vio->reenable();
          }
          // Kick source producer to get flow ... well, flowing.
          this->producer_handler(VC_EVENT_READ_READY, srcp);
        } else {
          // We can stall for small thresholds on network sinks because this event happens
          // before the actual socket write. So we trap for the buffer becoming empty to
          // make sure we get an event to unthrottle after the write.
          if (HttpTunnelType_t::HTTP_CLIENT == c->vc_type) {
            NetVConnection *netvc = dynamic_cast<NetVConnection *>(c->write_vio->vc_server);
            if (netvc) { // really, this should always be true.
              netvc->trapWriteBufferEmpty();
            }
          }
        }
      }
      if (p->read_vio) {
        p->read_vio->reenable();
      }
    }
  }
}

//
// bool HttpTunnel::consumer_handler(int event, HttpTunnelConsumer* p)
//
//   Handles events from consumers.
//
//   If the event is interesting only to the tunnel, this
//    handler takes all necessary actions and returns false
//    If the event is interesting to the state_machine,
//    it calls back the state machine and returns true
//
//
bool
HttpTunnel::consumer_handler(int event, HttpTunnelConsumer *c)
{
  bool                sm_callback = false;
  HttpConsumerHandler jump_point;
  HttpTunnelProducer *p = c->producer;

  Dbg(dbg_ctl_http_tunnel, "[%" PRId64 "] consumer_handler [%s %s]", sm->sm_id, c->name, HttpDebugNames::get_event_name(event));

  ink_assert(c->alive == true);

  switch (event) {
  case VC_EVENT_WRITE_READY:
    this->consumer_reenable(c);
    // Once we get a write ready from the origin, we can assume the connect to some degree succeeded
    if (c->vc_type == HttpTunnelType_t::HTTP_SERVER) {
      sm->t_state.current.server->clear_connect_fail();
    }
    break;

  case VC_EVENT_WRITE_COMPLETE:
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    ink_assert(c->alive);
    ink_assert(c->buffer_reader);
    if (c->write_vio) {
      c->write_vio->reenable();
    }
    c->alive = false;

    c->bytes_written = c->write_vio ? c->write_vio->ndone : 0;

    // Interesting tunnel event, call SM
    jump_point = c->vc_handler;
    (sm->*jump_point)(event, c);
    // Make sure the handler_state is set
    // Necessary for post tunnel end processing
    if (c->producer && c->producer->handler_state == 0) {
      if (event == VC_EVENT_WRITE_COMPLETE) {
        c->producer->handler_state = static_cast<int>(HttpSmPost_t::SUCCESS);
        // If the consumer completed, presumably the producer successfully read
        c->producer->read_success = true;
        // Go ahead and clean up the producer side
        if (p->alive) {
          producer_handler(VC_EVENT_READ_COMPLETE, p);
        }
      } else if (c->vc_type == HttpTunnelType_t::HTTP_SERVER) {
        c->producer->handler_state = static_cast<int>(HttpSmPost_t::UA_FAIL);
      } else if (c->vc_type == HttpTunnelType_t::HTTP_CLIENT) {
        c->producer->handler_state = static_cast<int>(HttpSmPost_t::SERVER_FAIL);
      }
    }
    sm_callback = true;

    // Deallocate the reader after calling back the sm
    //  because buffer problems are easier to debug
    //  in the sm when the reader is still valid
    if (c->buffer_reader) {
      c->buffer_reader->mbuf->dealloc_reader(c->buffer_reader);
      c->buffer_reader = nullptr;
    }

    // Since we removed a consumer, it may now be
    //   possible to put more stuff in the buffer
    // Note: we reenable only after calling back
    //    the SM since the reenabling has the side effect
    //    updating the buffer state for the VConnection
    //    that is being reenabled
    if (p->alive && p->read_vio) {
      if (p->is_throttled()) {
        this->consumer_reenable(c);
      } else {
        p->read_vio->reenable();
      }
    }
    // [amc] I don't think this happens but we'll leave a debug trap
    // here just in case.
    if (p->is_throttled()) {
      Dbg(dbg_ctl_http_tunnel, "Special event %s on %p with flow control on", HttpDebugNames::get_event_name(event), p);
    }
    break;

  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
  default:
    // Consumers should not get these events
    ink_release_assert(0);
    break;
  }

  return sm_callback;
}

// void HttpTunnel::chain_abort_all(HttpTunnelProducer* p)
//
//    Abort the producer and everyone still alive
//     downstream of the producer
//
void
HttpTunnel::chain_abort_all(HttpTunnelProducer *p)
{
  HttpTunnelConsumer *c = p->consumer_list.head;

  while (c) {
    if (c->alive) {
      c->alive     = false;
      c->write_vio = nullptr;
      c->vc->do_io_close(EHTTP_ERROR);
      update_stats_after_abort(c->vc_type);
    }

    if (c->self_producer) {
      // Must snip the link before recursively
      // freeing to avoid looks introduced by
      // blind tunneling
      HttpTunnelProducer *selfp = c->self_producer;
      c->self_producer          = nullptr;
      chain_abort_all(selfp);
    }

    c = c->link.next;
  }

  if (p->alive) {
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
      if (!p->is_handling_chunked_content()) {
        p->bytes_consumed += p->bytes_read;
      }
    }
    if (p->self_consumer) {
      p->self_consumer->alive = false;
    }
    p->read_vio = nullptr;
    p->vc->do_io_close(EHTTP_ERROR);
    Metrics::Counter::increment(http_rsb.origin_shutdown_tunnel_abort);
    update_stats_after_abort(p->vc_type);
  }
}

//
// Determine the number of bytes a consumer should read from a producer
//
int64_t
HttpTunnel::final_consumer_bytes_to_write(HttpTunnelProducer *p, HttpTunnelConsumer *c)
{
  int64_t bytes_to_write = 0;
  int64_t consumer_n     = 0;
  if (p->alive) {
    consumer_n = INT64_MAX;
  } else {
    TunnelChunkingAction_t action = p->chunking_action;
    if (c->alive) {
      if (c->vc_type == HttpTunnelType_t::CACHE_WRITE) {
        switch (action) {
        case TunnelChunkingAction_t::CHUNK_CONTENT:
        case TunnelChunkingAction_t::PASSTHRU_DECHUNKED_CONTENT:
          bytes_to_write = p->bytes_consumed;
          break;
        case TunnelChunkingAction_t::DECHUNK_CONTENT:
        case TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT:
          bytes_to_write = p->chunked_handler.skip_bytes + p->chunked_handler.dechunked_size;
          break;
        default:
          break;
        }
      } else if (action == TunnelChunkingAction_t::CHUNK_CONTENT) {
        bytes_to_write = p->chunked_handler.skip_bytes + p->chunked_handler.chunked_size;
      } else if (action == TunnelChunkingAction_t::DECHUNK_CONTENT) {
        bytes_to_write = p->chunked_handler.skip_bytes + p->chunked_handler.dechunked_size;
      } else if (action == TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT) {
        bytes_to_write = p->bytes_consumed;
      } else {
        bytes_to_write = p->bytes_consumed;
      }
      consumer_n = bytes_to_write - c->skip_bytes;
    }
  }
  return consumer_n;
}

//
// void HttpTunnel::finish_all_internal(HttpTunnelProducer* p)
//
//    Internal function for finishing all consumers.  Takes
//       chain argument about where to finish just immediate
//       consumer or all those downstream
//
void
HttpTunnel::finish_all_internal(HttpTunnelProducer *p, bool chain)
{
  ink_assert(p->alive == false);
  HttpTunnelConsumer    *c           = p->consumer_list.head;
  int64_t                total_bytes = 0;
  TunnelChunkingAction_t action      = p->chunking_action;

  if (action == TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT) {
    // Verify that we consumed the number of bytes we accounted for via p->bytes_consumed.
    if (p->bytes_read == 0 && p->buffer_start != nullptr) {
      int num_read = p->buffer_start->read_avail() - p->chunked_handler.chunked_reader->read_avail();
      ink_release_assert(num_read == p->bytes_consumed);
    }
  }

  while (c) {
    if (c->alive) {
      if (c->write_vio) {
        // Adjust the number of bytes to write in the case of
        // a completed unlimited producer
        c->write_vio->nbytes = final_consumer_bytes_to_write(p, c);
        ink_assert(c->write_vio->nbytes >= 0);

        if (c->write_vio->nbytes < 0) {
          Error("Incorrect total_bytes - c->skip_bytes = %" PRId64 "\n", total_bytes - c->skip_bytes);
        }
      }

      if (chain == true && c->self_producer) {
        chain_finish_all(c->self_producer);
      }
      // The IO Core will not call us back if there
      //   is nothing to do.  Check to see if there is
      //   nothing to do and take the appropriate
      //   action
      if (c->write_vio && c->alive && c->write_vio->nbytes == c->write_vio->ndone) {
        consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
      }
    }

    c = c->link.next;
  }
}

// void HttpTunnel::chain_abort_cache_write(HttpProducer* p)
//
//    Terminates all cache writes.  Used to prevent truncated
//     documents from being stored in the cache
//
void
HttpTunnel::chain_abort_cache_write(HttpTunnelProducer *p)
{
  HttpTunnelConsumer *c = p->consumer_list.head;

  while (c) {
    if (c->alive) {
      if (c->vc_type == HttpTunnelType_t::CACHE_WRITE) {
        ink_assert(c->self_producer == nullptr);
        c->write_vio = nullptr;
        c->vc->do_io_close(EHTTP_ERROR);
        c->alive = false;
        Metrics::Gauge::decrement(http_rsb.current_cache_connections);
      } else if (c->self_producer) {
        chain_abort_cache_write(c->self_producer);
      }
    }
    c = c->link.next;
  }
}

// void HttpTunnel::close_vc(HttpTunnelProducer* p)
//
//    Closes the vc associated with the producer and
//      updates the state of the self_consumer
//
void
HttpTunnel::close_vc(HttpTunnelProducer *p)
{
  ink_assert(p->alive == false);
  HttpTunnelConsumer *c = p->self_consumer;

  if (c && c->alive) {
    c->alive = false;
    if (c->write_vio) {
      c->bytes_written = c->write_vio->ndone;
    }
  }

  p->vc->do_io_close();
}

// void HttpTunnel::close_vc(HttpTunnelConsumer* c)
//
//    Closes the vc associated with the consumer and
//      updates the state of the self_producer
//
void
HttpTunnel::close_vc(HttpTunnelConsumer *c)
{
  ink_assert(c->alive == false);
  HttpTunnelProducer *p = c->self_producer;

  if (p && p->alive) {
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
      if (!p->is_handling_chunked_content()) {
        p->bytes_consumed += p->bytes_read;
      }
    }
  }

  c->vc->do_io_close();
}

// int HttpTunnel::main_handler(int event, void* data)
//
//   Main handler for the tunnel.  Vectors events
//   based on whether they are from consumers or
//   producers
//
int
HttpTunnel::main_handler(int event, void *data)
{
  if (event == HTTP_TUNNEL_EVENT_ACTIVITY_CHECK) {
    if (!_is_tls_tunnel_active()) {
      mark_tls_tunnel_inactive();
    }

    return EVENT_DONE;
  }

  HttpTunnelProducer *p           = nullptr;
  HttpTunnelConsumer *c           = nullptr;
  bool                sm_callback = false;

  ++reentrancy_count;

  ink_assert(sm->magic == HttpSmMagic_t::ALIVE);

  // Find the appropriate entry
  if ((p = get_producer(static_cast<VIO *>(data))) != nullptr) {
    sm_callback = producer_handler(event, p);
  } else {
    if ((c = get_consumer(static_cast<VIO *>(data))) != nullptr) {
      ink_assert(c->write_vio == (VIO *)data || c->vc == ((VIO *)data)->vc_server);
      sm_callback = consumer_handler(event, c);
    } else {
      // Presumably a delayed event we can ignore now
      internal_error(); // do nothing
    }
  }

  // We called a vc handler, the tunnel might be
  //  finished.  Check to see if there are any remaining
  //  VConnections alive.  If not, notify the state machine
  //
  // Don't call out if we are nested
  if (call_sm || (sm_callback && !is_tunnel_alive())) {
    if (reentrancy_count == 1) {
      reentrancy_count = 0;
      active           = false;
      sm->handleEvent(HTTP_TUNNEL_EVENT_DONE, this);
      return EVENT_DONE;
    } else {
      call_sm = true;
    }
  }
  --reentrancy_count;
  return EVENT_CONT;
}

void
HttpTunnel::update_stats_after_abort(HttpTunnelType_t t)
{
  switch (t) {
  case HttpTunnelType_t::CACHE_READ:
  case HttpTunnelType_t::CACHE_WRITE:
    Metrics::Gauge::decrement(http_rsb.current_cache_connections);
    break;
  default:
    // Handled here:
    // HttpTunnelType_t::HTTP_SERVER, HttpTunnelType_t::HTTP_CLIENT,
    // HttpTunnelType_t::TRANSFORM, HttpTunnelType_t::STATIC
    break;
  };
}

void
HttpTunnel::internal_error()
{
}

void
HttpTunnel::mark_tls_tunnel_active()
{
  _tls_tunnel_last_update = ink_get_hrtime();

  if (_tls_tunnel_active) {
    return;
  }

  _tls_tunnel_active = true;
  Metrics::Gauge::increment(http_rsb.tunnel_current_active_connections);

  _schedule_tls_tunnel_activity_check_event();
}

void
HttpTunnel::mark_tls_tunnel_inactive()
{
  if (!_tls_tunnel_active) {
    return;
  }

  _tls_tunnel_active = false;
  Metrics::Gauge::decrement(http_rsb.tunnel_current_active_connections);

  if (_tls_tunnel_activity_check_event) {
    _tls_tunnel_activity_check_event->cancel();
    _tls_tunnel_activity_check_event = nullptr;
  }
}

void
HttpTunnel::_schedule_tls_tunnel_activity_check_event()
{
  if (_tls_tunnel_activity_check_event) {
    return;
  }

  ink_hrtime period = HRTIME_SECONDS(sm->t_state.txn_conf->tunnel_activity_check_period);

  if (period > 0) {
    EThread *ethread                 = this_ethread();
    _tls_tunnel_activity_check_event = ethread->schedule_every_local(this, period, HTTP_TUNNEL_EVENT_ACTIVITY_CHECK);
  }
}

bool
HttpTunnel::_is_tls_tunnel_active() const
{
  ink_hrtime period = HRTIME_SECONDS(sm->t_state.txn_conf->tunnel_activity_check_period);

  // This should not be called if period is 0
  ink_release_assert(period > 0);

  ink_hrtime now = ink_get_hrtime();

  Dbg(dbg_ctl_http_tunnel, "now=%" PRId64 " last_update=%" PRId64, now, _tls_tunnel_last_update);

  // In some cases, m_tls_tunnel_last_update could be larger than now, because it's using cached current time.
  // - e.g. comparing Thread::cur_time of different threads.
  if (_tls_tunnel_last_update >= now || now - _tls_tunnel_last_update <= period) {
    return true;
  }

  return false;
}
