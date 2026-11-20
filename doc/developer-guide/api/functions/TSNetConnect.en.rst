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
.. function:: TSAction TSNetConnect(TSCont contp, sockaddr const * destination, TSNetConnectOptions const * net_options)

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
:arg:`net_options` is retained after the call returns. If :arg:`net_options` is
``NULL``, the call behaves exactly like the two-argument overload.

On success, :arg:`contp` receives ``TS_EVENT_NET_CONNECT`` with the new
:type:`TSVConn` as event data, which the plugin must eventually close. That
event means the connect was started, not that the TCP connection or the TLS
handshake completed. Later connect, handshake, and certificate failures arrive
as ``TS_EVENT_ERROR`` on the continuation of a VIO started with
:func:`TSVConnRead` or :func:`TSVConnWrite`. Otherwise, :arg:`contp` receives
``TS_EVENT_NET_CONNECT_FAILED`` with a negative ``errno`` value as event data.

Connecting With Options
-----------------------

If ``source`` is ``NULL``, the operating system chooses the source address and
port. Otherwise, the connection is bound on the host to ``source``, including
its port, as if by :manpage:`bind(2)`. A port of 0 lets the operating system
choose an unused local port. On builds with TPROXY support, ``IP_TRANSPARENT``
is set on the socket before it is bound, so ``source`` need not be an address
of the host. Setting ``IP_TRANSPARENT`` may require ``CAP_NET_ADMIN``. If the
socket cannot be bound, :arg:`contp` receives ``TS_EVENT_NET_CONNECT_FAILED``.

If ``use_tls`` is false, every field of :arg:`net_options` except ``source`` is
ignored. If ``use_tls`` is true:

*  ``sni_host_name`` is sent as SNI and is the name that name verification
   checks the certificate against. It also selects the :file:`sni.yaml`
   outbound settings, such as ``client_cert``. An empty ``sni_host_name`` is the
   same as ``NULL``. If it is ``NULL`` or an IP literal, no SNI is sent, and
   both name verification and the :file:`sni.yaml` lookup use the IP address in
   :arg:`destination`.
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

*  If :arg:`net_options` is non-null, every field is initialized; zero the
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

   The ALPN protocols offered come from
   :ts:cv:`proxy.config.ssl.client.alpn_protocols`, which by default offers
   none.

See Also
========

:manpage:`TSAPI(3ts)`,
:func:`TSActionDone`,
:func:`TSActionCancel`
