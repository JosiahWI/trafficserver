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
//////////////////////////////////////////////////////////////////////////////////////////////
//
// Implement the classes for the various types of hash keys we support.
//
#pragma once

#include <string>

#include "ts/ts.h"
#include "ts/remap.h"

#include "lulu.h"

enum ResourceIDs {
  RSRC_NONE                    = 0,
  RSRC_SERVER_RESPONSE_HEADERS = 1,
  RSRC_SERVER_REQUEST_HEADERS  = 2,
  RSRC_CLIENT_REQUEST_HEADERS  = 4,
  RSRC_CLIENT_RESPONSE_HEADERS = 8,
  RSRC_RESPONSE_STATUS         = 16,
};

///////////////////////////////////////////////////////////////////////////////
// Resources holds the minimum resources required to process a request.
//
class Resources
{
public:
  explicit Resources(TSHttpTxn txnptr, TSCont contptr) : txnp(txnptr), contp(contptr)
  {
    Dbg(dbg_ctl, "Calling CTOR for Resources (InkAPI)");
  }

  Resources(TSHttpTxn txnptr, TSRemapRequestInfo *rri) : txnp(txnptr), _rri(rri)
  {
    Dbg(dbg_ctl, "Calling CTOR for Resources (RemapAPI)");
  }

  ~Resources() { destroy(); }

  // noncopyable
  Resources(const Resources &)      = delete;
  void operator=(const Resources &) = delete;

  void gather(const ResourceIDs ids, TSHttpHookID hook);
  bool
  ready() const
  {
    return _ready;
  }

  TSHttpTxn           txnp;
  TSCont              contp          = nullptr;
  TSRemapRequestInfo *_rri           = nullptr;
  TSMBuffer           bufp           = nullptr;
  TSMLoc              hdr_loc        = nullptr;
  TSMBuffer           client_bufp    = nullptr;
  TSMLoc              client_hdr_loc = nullptr;
  TSHttpStatus        resp_status    = TS_HTTP_STATUS_NONE;
  const char         *ovector_ptr    = nullptr;
  int                 ovector[OVECCOUNT];
  int                 ovector_count = 0;
  bool                changed_url   = false;

private:
  void destroy();

  bool _ready = false;
};
