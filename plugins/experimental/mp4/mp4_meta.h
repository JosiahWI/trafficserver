/*
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

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstddef>
#include <unistd.h>
#include <getopt.h>
#include <cinttypes>

#include <ts/ts.h>

#define MP4_MAX_TRAK_NUM    6
#define MP4_MAX_BUFFER_SIZE (10 * 1024 * 1024)
#define MP4_MIN_BUFFER_SIZE 1024

#define DEBUG_TAG "ts_mp4"

#define mp4_set_atom_name(p, n1, n2, n3, n4) \
  ((u_char *)(p))[4] = n1;                   \
  ((u_char *)(p))[5] = n2;                   \
  ((u_char *)(p))[6] = n3;                   \
  ((u_char *)(p))[7] = n4

#define mp4_get_32value(p) \
  (((uint32_t)((u_char *)(p))[0] << 24) + (((u_char *)(p))[1] << 16) + (((u_char *)(p))[2] << 8) + (((u_char *)(p))[3]))

#define mp4_set_32value(p, n)               \
  ((u_char *)(p))[0] = (u_char)((n) >> 24); \
  ((u_char *)(p))[1] = (u_char)((n) >> 16); \
  ((u_char *)(p))[2] = (u_char)((n) >> 8);  \
  ((u_char *)(p))[3] = (u_char)(n)

#define mp4_get_64value(p)                                                                                              \
  (((uint64_t)((u_char *)(p))[0] << 56) + ((uint64_t)((u_char *)(p))[1] << 48) + ((uint64_t)((u_char *)(p))[2] << 40) + \
   ((uint64_t)((u_char *)(p))[3] << 32) + ((uint64_t)((u_char *)(p))[4] << 24) + (((u_char *)(p))[5] << 16) +           \
   (((u_char *)(p))[6] << 8) + (((u_char *)(p))[7]))

#define mp4_set_64value(p, n)                         \
  ((u_char *)(p))[0] = (u_char)((uint64_t)(n) >> 56); \
  ((u_char *)(p))[1] = (u_char)((uint64_t)(n) >> 48); \
  ((u_char *)(p))[2] = (u_char)((uint64_t)(n) >> 40); \
  ((u_char *)(p))[3] = (u_char)((uint64_t)(n) >> 32); \
  ((u_char *)(p))[4] = (u_char)((n) >> 24);           \
  ((u_char *)(p))[5] = (u_char)((n) >> 16);           \
  ((u_char *)(p))[6] = (u_char)((n) >> 8);            \
  ((u_char *)(p))[7] = (u_char)(n)

enum TSMp4AtomID {
  MP4_TRAK_ATOM = 0,
  MP4_TKHD_ATOM,
  MP4_MDIA_ATOM,
  MP4_MDHD_ATOM,
  MP4_HDLR_ATOM,
  MP4_MINF_ATOM,
  MP4_VMHD_ATOM,
  MP4_SMHD_ATOM,
  MP4_DINF_ATOM,
  MP4_STBL_ATOM,
  MP4_STSD_ATOM,
  MP4_STTS_ATOM,
  MP4_STTS_DATA,
  MP4_STSS_ATOM,
  MP4_STSS_DATA,
  MP4_CTTS_ATOM,
  MP4_CTTS_DATA,
  MP4_STSC_ATOM,
  MP4_STSC_CHUNK,
  MP4_STSC_DATA,
  MP4_STSZ_ATOM,
  MP4_STSZ_DATA,
  MP4_STCO_ATOM,
  MP4_STCO_DATA,
  MP4_CO64_ATOM,
  MP4_CO64_DATA,
  MP4_LAST_ATOM = MP4_CO64_DATA
};

struct mp4_atom_header {
  u_char size[4];
  u_char name[4];
};

struct mp4_atom_header64 {
  u_char size[4];
  u_char name[4];
  u_char size64[8];
};

struct mp4_mvhd_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[4];
  u_char modification_time[4];
  u_char timescale[4];
  u_char duration[4];
  u_char rate[4];
  u_char volume[2];
  u_char reserved[10];
  u_char matrix[36];
  u_char preview_time[4];
  u_char preview_duration[4];
  u_char poster_time[4];
  u_char selection_time[4];
  u_char selection_duration[4];
  u_char current_time[4];
  u_char next_track_id[4];
};

struct mp4_mvhd64_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[8];
  u_char modification_time[8];
  u_char timescale[4];
  u_char duration[8];
  u_char rate[4];
  u_char volume[2];
  u_char reserved[10];
  u_char matrix[36];
  u_char preview_time[4];
  u_char preview_duration[4];
  u_char poster_time[4];
  u_char selection_time[4];
  u_char selection_duration[4];
  u_char current_time[4];
  u_char next_track_id[4];
};

struct mp4_tkhd_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[4];
  u_char modification_time[4];
  u_char track_id[4];
  u_char reserved1[4];
  u_char duration[4];
  u_char reserved2[8];
  u_char layer[2];
  u_char group[2];
  u_char volume[2];
  u_char reverved3[2];
  u_char matrix[36];
  u_char width[4];
  u_char height[4];
};

struct mp4_tkhd64_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[8];
  u_char modification_time[8];
  u_char track_id[4];
  u_char reserved1[4];
  u_char duration[8];
  u_char reserved2[8];
  u_char layer[2];
  u_char group[2];
  u_char volume[2];
  u_char reverved3[2];
  u_char matrix[36];
  u_char width[4];
  u_char height[4];
};

struct mp4_mdhd_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[4];
  u_char modification_time[4];
  u_char timescale[4];
  u_char duration[4];
  u_char language[2];
  u_char quality[2];
};

struct mp4_mdhd64_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char creation_time[8];
  u_char modification_time[8];
  u_char timescale[4];
  u_char duration[8];
  u_char language[2];
  u_char quality[2];
};

struct mp4_stsd_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];

  u_char media_size[4];
  u_char media_name[4];
};

struct mp4_stts_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

struct mp4_stts_entry {
  u_char count[4];
  u_char duration[4];
};

struct mp4_stss_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

struct mp4_ctts_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

struct mp4_ctts_entry {
  u_char count[4];
  u_char offset[4];
};

struct mp4_stsc_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

struct mp4_stsc_entry {
  u_char chunk[4];
  u_char samples[4];
  u_char id[4];
};

struct mp4_stsz_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char uniform_size[4];
  u_char entries[4];
};

struct mp4_stco_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

struct mp4_co64_atom {
  u_char size[4];
  u_char name[4];
  u_char version[1];
  u_char flags[3];
  u_char entries[4];
};

class Mp4Meta;
using Mp4AtomHandler = int (Mp4Meta::*)(int64_t, int64_t);

struct mp4_atom_handler {
  const char    *name;
  Mp4AtomHandler handler;
};

class BufferHandle
{
public:
  BufferHandle(){};

  ~BufferHandle()
  {
    if (reader) {
      TSIOBufferReaderFree(reader);
      reader = nullptr;
    }

    if (buffer) {
      TSIOBufferDestroy(buffer);
      buffer = nullptr;
    }
  }

public:
  TSIOBuffer       buffer = nullptr;
  TSIOBufferReader reader = nullptr;
};

class Mp4Trak
{
public:
  Mp4Trak() { memset(&stsc_chunk_entry, 0, sizeof(mp4_stsc_entry)); }

  ~Mp4Trak() {}

public:
  uint32_t timescale = 0;
  int64_t  duration  = 0;

  uint32_t time_to_sample_entries     = 0; // stsc
  uint32_t sample_to_chunk_entries    = 0; // stsc
  uint32_t sync_samples_entries       = 0; // stss
  uint32_t composition_offset_entries = 0; // ctts
  uint32_t sample_sizes_entries       = 0; // stsz
  uint32_t chunks                     = 0; // stco, co64

  uint32_t start_sample       = 0;
  uint32_t start_chunk        = 0;
  uint32_t chunk_samples      = 0;
  uint64_t chunk_samples_size = 0;
  off_t    start_offset       = 0;

  size_t tkhd_size = 0;
  size_t mdhd_size = 0;
  size_t hdlr_size = 0;
  size_t vmhd_size = 0;
  size_t smhd_size = 0;
  size_t dinf_size = 0;
  size_t size      = 0;

  BufferHandle atoms[MP4_LAST_ATOM + 1];

  mp4_stsc_entry stsc_chunk_entry;
};

class Mp4Meta
{
public:
  Mp4Meta()
  {
    meta_buffer = TSIOBufferCreate();
    meta_reader = TSIOBufferReaderAlloc(meta_buffer);
  }

  ~Mp4Meta()
  {
    if (meta_reader) {
      TSIOBufferReaderFree(meta_reader);
      meta_reader = nullptr;
    }

    if (meta_buffer) {
      TSIOBufferDestroy(meta_buffer);
      meta_buffer = nullptr;
    }
  }

  int parse_meta(bool body_complete);

  int  post_process_meta();
  void mp4_meta_consume(int64_t size);
  int  mp4_atom_next(int64_t atom_size, bool wait = false);

  int mp4_read_atom(mp4_atom_handler *atom, int64_t size);
  int parse_root_atoms();

  int mp4_read_ftyp_atom(int64_t header_size, int64_t data_size);
  int mp4_read_moov_atom(int64_t header_size, int64_t data_size);
  int mp4_read_mdat_atom(int64_t header_size, int64_t data_size);

  int mp4_read_mvhd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_trak_atom(int64_t header_size, int64_t data_size);
  int mp4_read_cmov_atom(int64_t header_size, int64_t data_size);

  int mp4_read_tkhd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_mdia_atom(int64_t header_size, int64_t data_size);

  int mp4_read_mdhd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_hdlr_atom(int64_t header_size, int64_t data_size);
  int mp4_read_minf_atom(int64_t header_size, int64_t data_size);

  int mp4_read_vmhd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_smhd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_dinf_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stbl_atom(int64_t header_size, int64_t data_size);

  int mp4_read_stsd_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stts_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stss_atom(int64_t header_size, int64_t data_size);
  int mp4_read_ctts_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stsc_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stsz_atom(int64_t header_size, int64_t data_size);
  int mp4_read_stco_atom(int64_t header_size, int64_t data_size);
  int mp4_read_co64_atom(int64_t header_size, int64_t data_size);

  int mp4_update_stts_atom(Mp4Trak *trak);
  int mp4_update_stss_atom(Mp4Trak *trak);
  int mp4_update_ctts_atom(Mp4Trak *trak);
  int mp4_update_stsc_atom(Mp4Trak *trak);
  int mp4_update_stsz_atom(Mp4Trak *trak);
  int mp4_update_co64_atom(Mp4Trak *trak);
  int mp4_update_stco_atom(Mp4Trak *trak);
  int mp4_update_stbl_atom(Mp4Trak *trak);
  int mp4_update_minf_atom(Mp4Trak *trak);
  int mp4_update_mdia_atom(Mp4Trak *trak);
  int mp4_update_trak_atom(Mp4Trak *trak);

  int64_t mp4_update_mdat_atom(int64_t start_offset);
  int     mp4_adjust_co64_atom(Mp4Trak *trak, off_t adjustment);
  int     mp4_adjust_stco_atom(Mp4Trak *trak, int32_t adjustment);

  uint32_t mp4_find_key_sample(uint32_t start_sample, Mp4Trak *trak);
  void     mp4_update_mvhd_duration();
  void     mp4_update_tkhd_duration(Mp4Trak *trak);
  void     mp4_update_mdhd_duration(Mp4Trak *trak);

public:
  int64_t start          = 0; // requested start time, measured in milliseconds.
  int64_t cl             = 0; // the total size of the mp4 file
  int64_t content_length = 0; // the size of the new mp4 file
  int64_t meta_atom_size = 0;

  TSIOBuffer       meta_buffer; // meta data to be parsed
  TSIOBufferReader meta_reader;

  int64_t meta_avail = 0;
  int64_t wait_next  = 0;
  int64_t need_size  = 0;

  BufferHandle meta_atom;
  BufferHandle ftyp_atom;
  BufferHandle moov_atom;
  BufferHandle mvhd_atom;
  BufferHandle mdat_atom;
  BufferHandle mdat_data;
  BufferHandle out_handle;

  std::array<std::unique_ptr<Mp4Trak>, MP4_MAX_TRAK_NUM> trak_vec;

  double rs   = 0;
  double rate = 0;

  int64_t  ftyp_size = 0;
  int64_t  moov_size = 0;
  int64_t  start_pos = 0; // start position of the new mp4 file
  uint32_t timescale = 0;
  uint32_t trak_num  = 0;
  int64_t  passed    = 0;

  u_char mdat_atom_header[16];
  bool   meta_complete = false;
};
