/** @file

  Http1Transaction.h - The Transaction class for Http1*

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

#include <string_view>

using namespace std::literals;

#include "proxy/ProxyTransaction.h"

class Continuation;

class Http1Transaction : public ProxyTransaction
{
public:
  using super_type = ProxyTransaction;

  Http1Transaction(ProxySession *session) : super_type(session) {}
  ~Http1Transaction() = default;

  Http1Transaction() {}

  void reset();

  ////////////////////
  // Methods
  int  get_transaction_id() const override;
  void set_reader(IOBufferReader *reader);
  void set_close_connection(HTTPHdr &hdr) const override;

  ////////////////////
  // Variables

protected:
};

inline int
Http1Transaction::get_transaction_id() const
{
  // For HTTP/1 there is only one on-going transaction at a time per session/connection.  Therefore, the transaction count can be
  // presumed not to increase during the lifetime of a transaction, thus this function will return a consistent unique transaction
  // identifier.
  //
  return _proxy_ssn->get_transact_count();
}

inline void
Http1Transaction::reset()
{
  _sm = nullptr;
}

inline void
Http1Transaction::set_reader(IOBufferReader *reader)
{
  _reader = reader;
}

inline void
Http1Transaction::set_close_connection(HTTPHdr &hdr) const
{
  hdr.value_set(static_cast<std::string_view>(MIME_FIELD_CONNECTION), "close"sv);
}
