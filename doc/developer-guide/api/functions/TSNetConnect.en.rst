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
.. function:: TSAction TSNetConnect(TSCont contp, sockaddr const * destination, TSNetConnectOptions options)
.. function:: TSNetConnectOptions TSNetConnectOptionsCreate()
.. function:: void TSNetConnectOptionsDestroy(TSNetConnectOptions options) noexcept
.. function:: void TSNetConnectOptionsSourceSet(TSNetConnectOptions options, sockaddr const * source)
.. function:: void TSNetConnectOptionsSniHostnameSet(TSNetConnectOptions options, char const * sni_hostname)
.. function:: void TSNetConnectOptionsFlagsSet(TSNetConnectOptions options, uint32_t flags)
.. function:: void TSNetConnectOptionsVerifyOriginCertFieldsSet(TSNetConnectOptions options, TSVerifyOriginCertFields fields)

Description
===========

Open an outbound connection to :arg:`destination`. Both overloads apply the
``proxy.config.net.sock_*_out`` socket options.

:arg:`contp` is the continuation to call back with the result.
:arg:`destination` is the address to connect to. It is not retained after the
call returns.

The two-argument overload opens a plain TCP connection, and the operating
system chooses the source address and port. Use the overload that takes
:arg:`options` to bind a source address or to connect with TLS. If
:arg:`options` is ``NULL``, the call behaves exactly like the two-argument
overload.

On success, :arg:`contp` receives ``TS_EVENT_NET_CONNECT`` with the new
:type:`TSVConn` as event data, which the plugin must eventually close. That
event means the connect was started, not that the TCP connection or the TLS
handshake completed. Later connect, handshake, and certificate failures arrive
as ``TS_EVENT_ERROR`` on the continuation of a VIO started with
:func:`TSVConnRead` or :func:`TSVConnWrite`. Otherwise, :arg:`contp` receives
``TS_EVENT_NET_CONNECT_FAILED`` with a negative ``errno`` value as event data.

Connecting With Options
-----------------------

``TSNetConnectOptions`` is an opaque handle to a set of options.
:func:`TSNetConnectOptionsCreate` returns a new, non-null set with every option
at its default, which the caller must free with
:func:`TSNetConnectOptionsDestroy`. Destroying ``NULL`` does nothing. After a
set is destroyed, it must not be passed to any function. Each option has a
setter, and each setter replaces the option's previous value:

``source``
   Set by :func:`TSNetConnectOptionsSourceSet`. Default: unset.

``sni_hostname``
   Set by :func:`TSNetConnectOptionsSniHostnameSet` from a null-terminated
   string. Default: unset.

``flags``
   Set by :func:`TSNetConnectOptionsFlagsSet`, which replaces all previous
   flags rather than adding to them. Default ``TS_NET_CONNECT_FLAGS_NONE``.

``verify_origin_cert_fields``
   Set by :func:`TSNetConnectOptionsVerifyOriginCertFieldsSet`. Default
   ``TS_VERIFY_ORIGIN_CERT_INHERIT``.

The setters copy ``source`` and ``sni_hostname``, so the caller's buffers need
not outlive the call to the setter. Passing ``NULL`` for ``source``, or ``NULL``
or an empty string for ``sni_hostname``, unsets it. One set of options may be
passed to any number of :func:`TSNetConnect` calls. :func:`TSNetConnect` does
not retain :arg:`options`, so it may be destroyed as soon as the call returns,
before :arg:`contp` is called back.

``flags`` is a bitwise OR of ``TSNetConnectFlags`` values:

``TS_NET_CONNECT_FLAGS_USE_TLS``
   Connect with TLS.

``TS_NET_CONNECT_FLAGS_USE_TRANSPARENT_SOURCE``
   Bind ``source`` transparently, as described below.

If ``source`` is ``NULL``, the operating system chooses the source address and
port. Otherwise, the connection is bound on the host to ``source``, including
its port, as if by :manpage:`bind(2)`. A port of 0 lets the operating system
choose an unused local port. If the socket cannot be bound, :arg:`contp`
receives ``TS_EVENT_NET_CONNECT_FAILED``.

With ``TS_NET_CONNECT_FLAGS_USE_TRANSPARENT_SOURCE``, on builds with TPROXY
support ``IP_TRANSPARENT`` is set on the socket before it is bound, so
``source`` need not be an address of the host. Setting ``IP_TRANSPARENT`` may
require ``CAP_NET_ADMIN``. On builds without TPROXY support, ``source`` is
bound as if the flag were not set. The flag is ignored if ``source`` is
``NULL``.

Without ``TS_NET_CONNECT_FLAGS_USE_TLS``, ``sni_hostname`` and
``verify_origin_cert_fields`` are ignored. With it:

*  ``sni_hostname`` is sent as SNI and is the name that name verification
   checks the certificate against. It also selects the :file:`sni.yaml`
   outbound settings, such as ``client_cert``. If it is unset or an IP literal,
   no SNI is sent, and both name verification and the :file:`sni.yaml` lookup
   use the IP address in :arg:`destination`.
*  ``verify_origin_cert_fields`` selects what is checked in the origin
   certificate:

   ``TS_VERIFY_ORIGIN_CERT_INHERIT``
      The default. Takes the selection from
      :ts:cv:`proxy.config.ssl.client.verify.server.properties`.

   ``TS_VERIFY_ORIGIN_CERT_SIGNATURE``
      Checks the certificate signature.

   ``TS_VERIFY_ORIGIN_CERT_NAME``
      Checks the certificate name against ``sni_hostname``.

   ``TS_VERIFY_ORIGIN_CERT_ALL``
      Checks both.

   ``TS_VERIFY_ORIGIN_CERT_NONE``
      Does not verify the certificate, whatever :file:`records.yaml` and
      :file:`sni.yaml` say, and does not call ``TS_SSL_VERIFY_SERVER_HOOK``.

   For every value other than ``TS_VERIFY_ORIGIN_CERT_NONE``, the failure
   policy is :ts:cv:`proxy.config.ssl.client.verify.server.policy`, and the
   :file:`sni.yaml` settings ``verify_server_policy`` and
   ``verify_server_properties`` do not apply. Both records are read when
   :func:`TSNetConnect` is called, not when the option is set.

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

For the overload that takes :arg:`options`:

*  :arg:`options` is ``NULL`` or was returned by
   :func:`TSNetConnectOptionsCreate` and not yet destroyed.
*  ``source`` is ``NULL`` or an address of the same family as
   :arg:`destination`.
*  If ``TS_NET_CONNECT_FLAGS_USE_TLS`` is set,
   ``TS_LIFECYCLE_PORTS_INITIALIZED_HOOK`` has already been invoked. TLS is not
   initialized before then.

For the setters and :func:`TSNetConnectOptionsDestroy`:

*  :arg:`options` was returned by :func:`TSNetConnectOptionsCreate` and not yet
   destroyed. :func:`TSNetConnectOptionsDestroy` also accepts ``NULL``.
*  :arg:`source` is ``NULL`` or points to a complete ``sockaddr_in`` or
   ``sockaddr_in6``.
*  :arg:`flags` has no bits set other than ``TSNetConnectFlags`` values.
*  :arg:`fields` is a ``TSVerifyOriginCertFields`` enumerator.

Thread Safety
=============

Call :func:`TSNetConnect` only from an ``ET_NET`` thread; this rules out
``TSPluginInit``. The call blocks to acquire :arg:`contp`'s mutex.
:arg:`contp` may be called back before the call returns, and is always called
back holding that mutex. Hold :arg:`contp`'s mutex across the call if you will
use the returned action. Otherwise the callback can run on another thread as
soon as the call returns.

:func:`TSNetConnectOptionsCreate` may be called from any thread, including
during ``TSPluginInit``. A set of options has no internal locking: no two
functions, including :func:`TSNetConnect`, may run concurrently on the same
:arg:`options`. Calls on distinct sets of options are independent.

Notes
=====

These notes apply to the overload that takes :arg:`options`.

.. note::

   The ALPN protocols offered come from
   :ts:cv:`proxy.config.ssl.client.alpn_protocols`, which by default offers
   none.

See Also
========

:manpage:`TSAPI(3ts)`,
:func:`TSActionDone`,
:func:`TSActionCancel`
