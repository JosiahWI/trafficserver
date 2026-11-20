.. Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed
   with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache
   License, Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain a copy of
   the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied.  See the License for the specific language governing
   permissions and limitations under the License.

.. include:: ../../../common.defs

.. default-domain:: cpp

TSNetConnect
************

Synopsis
========

.. code-block:: cpp

    #include <ts/ts.h>

.. function:: TSAction TSNetConnect(TSCont contp, sockaddr const * destination)
.. function:: TSAction TSNetConnect(TSCont contp, sockaddr const * destination, TSNetConnectOptions * net_options)

Description
===========

Open an outbound connection to :arg:`destination`. Both overloads apply the
``proxy.config.net.sock_*_out`` socket options.

:arg:`contp` is the continuation to call back with the result.
:arg:`destination` is the address to connect to. It is not retained after the
call returns.

The two-argument overload opens a plain TCP connection, and the operating
system chooses the source address and port. Use the overload that takes
:arg:`net_options` to bind a source address or to connect with TLS. Nothing in
:arg:`net_options` is retained after the call returns.

On success, :arg:`contp` receives ``TS_EVENT_NET_CONNECT`` with the new
:type:`TSVConn` as event data, which the plugin must eventually close. That
event means the connect was started, not that the TCP connection or the TLS
handshake completed. Later connect, handshake, and certificate failures arrive
as ``TS_EVENT_ERROR`` on the continuation of a VIO started with
:func:`TSVConnRead` or :func:`TSVConnWrite`. Otherwise, :arg:`contp` receives
``TS_EVENT_NET_CONNECT_FAILED`` with a negative ``errno`` value as event data.

Connecting With Options
-----------------------

If ``use_tls`` is false, every field of :arg:`net_options` except ``source`` and
``use_source_port`` is ignored. If ``use_tls`` is true:

*  An empty ``sni_host_name`` is the same as ``NULL``, and an IP literal is not
   sent as SNI.
*  If ``verify_origin_cert`` is false, the origin certificate is not verified,
   whatever :file:`records.yaml` and :file:`sni.yaml` say.
*  If ``verify_origin_cert`` is true, the policy is
   :ts:cv:`proxy.config.ssl.client.verify.server.policy`, and
   ``verify_origin_cert_fields`` selects what is checked.
   ``TS_VERIFY_ORIGIN_CERT_INHERIT`` takes that selection from
   :ts:cv:`proxy.config.ssl.client.verify.server.properties`.

Return Value
============

An action for the pending connect, valid until :arg:`contp` is called back. If
:arg:`contp` was already called back, the value is one for which
:func:`TSActionDone` returns nonzero, and passing it to :func:`TSActionCancel`
is undefined. Returns ``NULL`` during shutdown, and :arg:`contp` is then never
called back.

Preconditions
=============

*  :arg:`contp` was created with a non-null mutex.
*  :arg:`destination` is an IPv4 or IPv6 address.

For the overload that takes :arg:`net_options`:

*  :arg:`net_options` is non-null and every field is initialized; zero the
   struct before setting fields.
*  ``source`` is ``NULL`` or an address of the same family as
   :arg:`destination`.

Thread Safety
=============

Call only from an ``ET_NET`` thread; this rules out ``TSPluginInit``. The call
blocks to acquire :arg:`contp`'s mutex. :arg:`contp` may be called back before
the call returns, and is always called back holding that mutex. Hold
:arg:`contp`'s mutex across the call if you will use the returned action.
Otherwise the callback can run on another thread as soon as the call returns.

Notes
=====

These notes apply to the overload that takes :arg:`net_options`.

.. note::

   ``alpn_protocol_group`` is ignored. ALPN comes from
   :ts:cv:`proxy.config.ssl.client.alpn_protocols`, which by default offers
   none.

.. note::

   Name verification checks the certificate against the IP address in
   :arg:`destination`, not against ``sni_host_name``.

.. note::

   A non-null ``source`` may require ``CAP_NET_ADMIN``. If binding it fails, the
   result is ``TS_EVENT_NET_CONNECT_FAILED``.

See Also
========

:manpage:`TSAPI(3ts)`,
:func:`TSActionDone`,
:func:`TSActionCancel`
