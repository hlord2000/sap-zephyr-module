SAP Flow And Recovery
#####################

This note explains how the SAP sample behaves on the wire and how it recovers
from disconnects and one-sided resets.

Design goals
************

SAP adds an application-layer trust check on top of BLE:

* BLE provides transport, discovery, and optional link encryption.
* SAP proves that both applications hold credentials signed by the same SAP CA.
* SAP derives a fresh per-connection session key and uses it to protect SAP
  payloads with AES-CCM.
* The protected GATT service is hidden until SAP succeeds.

Provisioning model
******************

The sample uses static credentials compiled into the image:

* one SAP CA public key
* one device certificate and ECDSA signing key per logical device ID
* one compile-time policy describing the expected fleet/group and allowed
  central ID

The certificate body contains:

* protocol version
* role mask
* group ID
* device ID
* device signing public key

The CA signs that body. During the handshake, each side verifies the peer
certificate against the embedded CA public key before accepting any SAP
transcript signatures.

Connection lifecycle
********************

1. Startup
==========

At boot the sample:

* initializes PSA crypto
* enables Bluetooth
* loads settings from NVS so bonded keys survive resets
* selects the local SAP credential and policy

The central then starts scanning. The peripheral starts connectable
advertising with only the SAP service UUID exposed.

2. BLE discovery and connect
============================

The central ignores advertisements that do not contain the SAP 128-bit service
UUID. That keeps it from connecting to unrelated BLE devices on a busy bench.

On connect:

* the peripheral allocates one SAP session
* the central allocates one SAP session and one peer slot
* if ``CONFIG_SAP_REQUIRE_BLE_ENCRYPTION=y``, the central requests
  ``BT_SECURITY_L2``

3. BLE security
===============

If BLE security is required, SAP waits until the link reaches at least
``BT_SECURITY_L2``. If security fails:

* the sample logs the Zephyr security error
* stale bond data for that peer is removed when the error is consistent with a
  key mismatch or authentication mismatch
* the connection is disconnected and later retried

This is the key reset-recovery path for the case where one side rebooted and
the other side still had old pairing state.

4. SAP mutual authentication
============================

Once ATT is ready, the central starts the SAP handshake.

The messages are:

1. ``HELLO`` from the central
   Contains a fresh central nonce.
2. ``PERIPHERAL_CHALLENGE`` from the peripheral
   Contains the peripheral certificate, a fresh peripheral nonce, and a
   signature over the challenge transcript.
3. ``CENTRAL_AUTH`` from the central
   Contains the central certificate, the central ephemeral ECDH public key,
   and a signature over the canonical transcript.
4. ``PERIPHERAL_AUTH`` from the peripheral
   Contains the peripheral ephemeral ECDH public key and a signature over the
   canonical transcript including both ephemeral keys.
5. ``SECURE_CONFIRM`` and ``SECURE_ACK``
   Both sides prove they derived the same SAP session keys by exchanging
   AES-CCM protected messages.

Transcript ordering is canonical:

* central nonce first
* peripheral nonce second
* central certificate body first
* peripheral certificate body second
* central ephemeral public key first
* peripheral ephemeral public key second

That keeps both roles signing and verifying the exact same byte sequence.

5. Session key derivation
=========================

After the ECDH exchange, both sides derive session material from:

* the ephemeral ECDH shared secret
* both nonces as HKDF salt
* a hash of the full transcript as HKDF ``info``

The derived output is split into:

* one AES-CCM key
* one TX nonce base
* one RX nonce base

The transcript is hashed before HKDF because the nRF54L15 CRACEN backend
limits HKDF ``info`` to 128 bytes.

6. Protected service gating
===========================

The sample exposes two layers of GATT:

* the always-present SAP control service
* the protected example service

The protected example service is intentionally global and dynamic. On the
peripheral it is:

* not registered before SAP authentication
* registered only after the authenticated callback fires
* unregistered again on auth failure or disconnect

The read callback also checks ``sap_is_authenticated()`` for the active
connection. That means new unauthenticated connections do not see or use the
protected endpoint.

7. Application traffic after SAP
================================

Once SAP reaches the authenticated state, application traffic stays inside the
SAP AES-CCM envelope.

The sample demonstrates two post-auth paths:

* secure text payloads sent from the UART shell
* secure button-state events from the peripheral

Those application message IDs and the protected-service UUIDs are defined in
the demo application, not in the reusable SAP module. Consumer applications are
expected to define their own application payload types and their own protected
services on top of the SAP session callbacks.

On ``nrf54l15dk``:

* the peripheral's DK Button 1 sends ``BUTTON_STATE`` events
* the central maps peripheral IDs ``1`` through ``4`` onto LEDs ``1`` through
  ``4``
* peripherals above ID ``4`` remain authenticated and usable, but they do not
  get a local LED assignment on the central

For scripted demos, the peripheral shell also exposes ``sap button
pressed|released|toggle``. That helper emits the same secure application event
as the physical button path, so shell-driven tests and real button presses
exercise the same central-side logic.

Why the peripheral stays single-connection
******************************************

The protected service is a global GATT registration, not a per-connection GATT
view. Because of that, the peripheral sample keeps ``CONFIG_BT_MAX_CONN=1``.

Adding a second peripheral connection object would make reconnect timing a bit
more forgiving, but it would also allow a second central to connect while the
first connection is still alive or tearing down. That would break the sample's
main guarantee that hidden services are not exposed to unauthenticated peers.

Instead, the sample uses Zephyr's recommended restart path:

* wait for ``bt_conn_cb.recycled`` before trying to restart connectable
  advertising or before aggressively creating a fresh connection
* use delayed work to retry scan/advertising start if resources are still busy

Reset and reconnect behavior
****************************

There are three pieces to the reconnect path:

1. Persistent bonds
===================

``CONFIG_BT_SETTINGS`` stores Bluetooth bonding state in NVS. ``settings_load()``
restores that state on boot, so a board reset does not automatically destroy
the BLE relationship.

2. Stale-bond cleanup
=====================

If BLE security fails with errors such as:

* authentication failure
* missing key
* authentication requirement not met
* key rejected

the sample calls ``bt_unpair()`` for that peer before retrying. That clears the
bad bond so the next reconnect can pair from scratch.

3. Resource-safe restart
========================

The sample does not restart advertising or reconnection directly inside
``disconnected()``. Zephyr documents that this can fail because the stack still
holds one reference to the old connection object at that point.

Instead the sample:

* marks scan or advertising restart as pending
* waits for ``bt_conn_cb.recycled`` to indicate that a connection object has
  returned to the pool
* kicks delayed work to start scanning or advertising again

That is why the peripheral no longer needs an extra connection object just to
recover from a reset race.

Practical sequence when one side resets
***************************************

If the peripheral resets while the central stays up:

1. The peripheral reboots and reloads bonds from settings.
2. The central sees the disconnect and schedules a scan restart.
3. If the old bond is still valid, BLE security succeeds and SAP runs again
   with fresh nonces and fresh ephemeral keys.
4. If the bond is stale, BLE security fails once, the old bond is cleared, and
   the next reconnect pairs cleanly.
5. The peripheral re-registers the protected service only after the fresh SAP
   handshake succeeds.

If the central resets while the peripheral stays up, the same logic applies in
the opposite direction.

Demo logging
************

Enable ``CONFIG_SAP_DEMO_LOGGING=y`` to get a customer-facing trace of the full
flow. The sample also provides ``demo_logging.conf`` as a ready-to-use overlay.

With demo logging enabled, each trace line carries a colored ``[SAP FLOW]``
prefix so the protocol steps stand out from normal informational logs and the
shell prompt during customer presentations.

The default demo trace now stays focused on the numbered handshake and visible
application effects. It intentionally does not print every encrypted SAP frame
any more, because that made frequent button traffic noisy.

Typical central-side trace:

.. code-block:: text

   FLOW 0/8 local policy: group=0x2a allowed_central=0 ble_encryption=1
   FLOW BLE: central scanning for SAP peripherals
   FLOW BLE: central found SAP UUID in advertisement from XX:XX:XX:XX:XX:XX
   FLOW 1/8 central BLE link established
   FLOW 2/8 central BLE security satisfied
   FLOW 3/8 central -> peripheral: HELLO (fresh central nonce)
   FLOW 4/8 central verified peripheral certificate and challenge signature: device_id=1 group=0x2a
   FLOW 5/8 central 0 -> peripheral: CENTRAL_AUTH (certificate + ephemeral ECDH key + transcript signature)
   FLOW 6/8 central verified peripheral transcript signature
   FLOW 6/8 central derived SAP session material with peer 1 using ECDH + HKDF
   FLOW 7/8 central -> peripheral: CONFIRM (encrypted proof of shared session key)
   FLOW 8/8 central accepted CONFIRM_ACK and marked SAP session authenticated
   FLOW app-io: central mapped peripheral 1 button state 0 onto LED1
   FLOW post-auth: central discovered the protected service on peer 1
   FLOW post-auth: central successfully read the gated protected characteristic

Typical peripheral-side trace:

.. code-block:: text

   FLOW BLE: peripheral advertising SAP service UUID only
   FLOW 1/8 peripheral BLE link established
   FLOW 2/8 peripheral BLE security satisfied
   FLOW 3/8 peripheral received HELLO and accepted central nonce
   FLOW 4/8 peripheral 1 -> central: PERIPHERAL_CHALLENGE (cert role=peripheral group=0x2a, signed challenge)
   FLOW 5/8 peripheral verified central certificate and transcript signature: device_id=0 group=0x2a
   FLOW 6/8 peripheral derived SAP session material with peer 0 using ECDH + HKDF
   FLOW 6/8 peripheral 1 -> central: PERIPHERAL_AUTH (ephemeral ECDH key + transcript signature)
   FLOW 7/8 peripheral accepted CONFIRM and proved key agreement
   FLOW 8/8 peripheral -> central: CONFIRM_ACK and SAP session authenticated
   FLOW app-io: peripheral sent button 1 state 0 to the central
   FLOW post-auth: peripheral exposed the protected service after SAP success

These logs are intentionally descriptive enough to map directly to the protocol
steps in this document.

Raw packet logging
******************

Enable ``CONFIG_SAP_PACKET_LOGGING=y`` to dump the actual SAP bytes sent over
GATT. The sample also provides ``packet_logging.conf`` as a helper overlay.

When packet logging is enabled:

* each raw dump line carries a colored ``[SAP PACKET]`` prefix
* auth messages are dumped before they are sent and when they are received
* secure SAP frames are dumped in their encrypted on-wire form

This is intended for protocol debugging rather than customer-facing demos.

Shell usage
***********

On ``nrf54l15dk`` builds, the UART shell is enabled by default.

Central shell:

.. code-block:: text

   sap peers
   sap send 1 hello from central shell
   sap send all fleet-wide message

Peripheral shell:

.. code-block:: text

   sap status
   sap send hello from peripheral shell
   sap button pressed
   sap button released
