.. _secure_application_pairing_sample:

Secure Application Pairing (SAP)
################################

.. contents::
   :local:
   :depth: 2

This sample demonstrates the standalone SAP Zephyr module on
``nrf54l15bsim/nrf54l15/cpuapp``, ``nrf54l15dk/nrf54l15/cpuapp``,
``nrf54l15dk/nrf54l15/cpuapp/ns``, ``xiao_nrf54l15/nrf54l15/cpuapp``, and
``xiao_nrf54l15/nrf54l15/cpuapp/ns``. SAP is implemented as an
application-layer service on top of BLE. Devices first establish a BLE link
and, when enabled, upgrade it with BLE security before they perform a mutual
certificate-based challenge/response handshake. Application traffic is
accepted only after SAP authentication succeeds.

For a full protocol walkthrough, see ``doc/flow.rst``.

The sample uses:

* A shared SAP root CA public key compiled into the image.
* Per-device ``secp256r1`` ECDSA identity keys and compact SAP certificates.
* Ephemeral ECDH over ``secp256r1`` to derive per-connection session keys.
* HKDF-SHA256 to derive an AES-CCM key and per-direction nonce bases.
* Two gated GATT services that are registered only after SAP succeeds:

  * a protected demo status service
  * the standard Bluetooth MCUmgr SMP transport used for DFU

Hardware notes
**************

Local validation on March 24, 2026 using two ``nrf54l15dk/nrf54l15/cpuapp``
boards confirmed the full real-target path:

* BLE pairing reached ``BT_SECURITY_L2`` on both boards.
* Mutual SAP authentication completed in both directions.
* The peripheral registered the protected demo service only after SAP success.
* The peripheral registered the MCUmgr DFU SMP service only after SAP success.
* The central discovered and read the protected service only after SAP auth.
* The central discovered the gated DFU SMP service only after SAP auth.
* The central completed an MCUmgr OS echo request only after SAP auth.
* Secure shell traffic worked in both directions on the UART shell.
* A peripheral button event drove the assigned LED on the central.
* Resetting one side forced BLE reconnect, reran SAP, and re-verified both
  gated services on the next link.

Local build validation on March 24, 2026 also confirmed that the sample builds
cleanly for the TF-M-backed non-secure targets
``nrf54l15dk/nrf54l15/cpuapp/ns`` and ``xiao_nrf54l15/nrf54l15/cpuapp/ns`` in
both central and peripheral roles. On those targets, TF-M protects the
temporary KMU push area used by CRACEN-backed PSA operations.

The real target uses the CRACEN PSA backend. Its HKDF implementation limits
the ``info`` field to 128 bytes, so the sample hashes the ECDH transcript
before feeding it into HKDF.

Simulator notes
***************

This sample is shaped around BabbleSim limitations for native/POSIX targets:

* No TF-M, SPU, or KMU-backed isolation is assumed.
* Public-key operations are performed through the PSA software backend on the
  simulated board.
* ``PSA_ALG_PURE_EDDSA`` / Ed25519 is not used here because the current
  simulator-backed Mbed TLS configuration does not implement it.
* The sample is fully event-driven and avoids busy waits.
* ``CONFIG_BT_PRIVACY=y`` is enabled so the sample follows the same privacy
  assumptions as Zephyr's bsim security tests.
* ``CONFIG_SAP_REQUIRE_BLE_ENCRYPTION`` defaults to ``n`` on
  ``nrf54l15bsim``. On March 24, 2026, local runtime validation on
  ``nrf54l15bsim/nrf54l15/cpuapp`` showed the same BLE security failure in
  both this sample and Zephyr's
  ``tests/bsim/bluetooth/host/adv/periodic:per_adv_conn_privacy_sync``:
  the peripheral disconnected with reason ``0x3d`` and the central reported
  a security failure before the link reached ``BT_SECURITY_L2``. The sample
  therefore exercises SAP mutual authentication and SAP-level AES-CCM
  transport protection directly on this simulator target. Real targets should
  keep BLE link encryption enabled.
* Dynamic GATT registration is used only on the single-connection peripheral
  sample path because the GATT database is global, not per connection.
  Per-connection authorization is still enforced in callbacks.

Building
********

Use the environment helper before building:

.. code-block:: console

   source activate-nrf.sh

Set the module root before building:

.. code-block:: console

   source /opt/ncs/sdks/ncs-main/activate-nrf.sh
   export SAP_MODULE_ROOT=/home/h/Documents/Nordic/sap-zephyr-module

If the repository is already part of your west workspace, you can omit
``-DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT`` from the commands below.

Build the BabbleSim central:

.. code-block:: console

   west build -p -d build-sap-central -b nrf54l15bsim/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE=central.conf

Build the BabbleSim peripheral:

.. code-block:: console

   west build -p -d build-sap-peripheral -b nrf54l15bsim/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE=peripheral.conf

Build the hardware central:

.. code-block:: console

   west build -p -d build-central-module -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="central.conf;demo_logging.conf"

Build the hardware peripheral:

.. code-block:: console

   west build -p -d build-peripheral-module -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;demo_logging.conf"

Build the TF-M-backed non-secure hardware central:

.. code-block:: console

   west build -p -d build-central-module-tfm -b nrf54l15dk/nrf54l15/cpuapp/ns \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="central.conf;demo_logging.conf"

Build the TF-M-backed non-secure hardware peripheral:

.. code-block:: console

   west build -p -d build-peripheral-module-tfm -b nrf54l15dk/nrf54l15/cpuapp/ns \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;demo_logging.conf"

Build the XIAO peripheral:

.. code-block:: console

   west build -p -d build-xiao-peripheral -b xiao_nrf54l15/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;peripheral_id2.conf;demo_logging.conf"

Build the TF-M-backed non-secure XIAO peripheral:

.. code-block:: console

   west build -p -d build-xiao-peripheral-tfm -b xiao_nrf54l15/nrf54l15/cpuapp/ns \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;peripheral_id2.conf;demo_logging.conf"

For nRF54L15 TF-M builds, use the ``/ns`` board qualifier instead of forcing
``CONFIG_BUILD_WITH_TFM=y`` onto ``nrf54l15dk/nrf54l15/cpuapp``. The non-secure
board variant enables the correct TF-M/sysbuild path automatically.

Build with the customer-demo flow trace enabled:

.. code-block:: console

   west build -p -d build-peripheral-demo -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;demo_logging.conf"

   west build -p -d build-central-demo -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="central.conf;demo_logging.conf"

Build with raw SAP packet hexdumps enabled:

.. code-block:: console

   west build -p -d build-peripheral-packets -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;demo_logging.conf;packet_logging.conf"

   west build -p -d build-central-packets -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="central.conf;demo_logging.conf;packet_logging.conf"

Running
*******

The sample expects multiple simulated instances. For a basic run:

* one central instance with device number ``0``
* one or more peripheral instances with device numbers ``1..4``

The sample credential table maps those BabbleSim device numbers to static SAP
certificates and private keys.

One-central/one-peripheral smoke test:

.. code-block:: console

   tools/bsim/bin/bs_2G4_phy_v1 -s=sap_smoke -D=2 -sim_length=20e6
   build-sap-central/sap_demo/zephyr/zephyr.exe -s=sap_smoke -d=0
   build-sap-peripheral/sap_demo/zephyr/zephyr.exe -s=sap_smoke -d=1

One-central/three-peripheral topology:

.. code-block:: console

   tools/bsim/bin/bs_2G4_phy_v1 -s=sap_multi -D=4 -sim_length=30e6
   build-sap-central/sap_demo/zephyr/zephyr.exe -s=sap_multi -d=0
   build-sap-peripheral/sap_demo/zephyr/zephyr.exe -s=sap_multi -d=1
   build-sap-peripheral/sap_demo/zephyr/zephyr.exe -s=sap_multi -d=2
   build-sap-peripheral/sap_demo/zephyr/zephyr.exe -s=sap_multi -d=3

For interactive debugging, ``west debug -d build-sap-central`` and
``west debug -d build-sap-peripheral`` use the ``native`` runner and attach
``gdb`` to ``zephyr.exe``.

For hardware flashing:

.. code-block:: console

   west flash -d build-central-module --dev-id <central-probe-serial>
   west flash -d build-peripheral-module --dev-id <peripheral-probe-serial>

UART shell commands
*******************

On boards that provide a non-secure ``zephyr,shell-uart`` chosen node, such as
``nrf54l15dk``, the sample enables a serial shell by default. Boards such as
``xiao_nrf54l15/.../cpuapp/ns`` intentionally ship without a non-secure UART,
so the sample disables the shell there and still runs the BLE/SAP demo.

Central role:

.. code-block:: text

   sap peers
   sap send 1 hello from central shell
   sap dfu_echo 1 hello through gated dfu
   sap send all fleet-wide test message

Peripheral role:

.. code-block:: text

   sap status
   sap send hello from peripheral shell
   sap button pressed
   sap button released

``sap button`` uses the same secure application message as the physical DK
Button 1 path, which is useful for scripted demos.

Behavior
********

1. The central connects and upgrades BLE security when
   ``CONFIG_SAP_REQUIRE_BLE_ENCRYPTION=y``.
2. The peripheral answers a SAP hello with its certificate, a challenge nonce,
   and a signature proving possession of its ECDSA identity key.
3. The central validates the certificate against the SAP CA, signs the
   transcript, and sends its own certificate plus an ephemeral ECDH public key.
4. The peripheral validates the central, replies with its own ephemeral key,
   and both sides derive the same SAP session material.
5. Both directions then use AES-CCM protected SAP frames.
6. After authentication, the peripheral dynamically registers a protected
   status service and the DFU SMP service. The central discovers the protected
   service and reads a status characteristic.
7. The application demo path then stays behind SAP:

   * arbitrary shell text is sent inside encrypted SAP frames
   * the peripheral's DK Button 1 sends a secure button-state event
   * the central maps peripheral IDs ``1..4`` onto LEDs ``1..4``
   * peripherals above ID ``4`` stay authenticated but have no LED assignment
   * the central probes the gated DFU SMP service with an MCUmgr OS echo
     request and gets the response only after SAP succeeds

Verbose demo logs
*****************

Set ``CONFIG_SAP_DEMO_LOGGING=y`` to emit a step-by-step flow trace. A helper
overlay is provided as ``demo_logging.conf``.

The trace is designed to be presentation-friendly:

* each line is prefixed with a colored ``[SAP FLOW]`` marker
* it prints numbered phases such as ``FLOW 3/8`` and ``FLOW 6/8``
* it explains which side sent which SAP message
* it shows when certificates and transcript signatures were verified
* it shows when session keys were derived and when protected services became
  visible
* it does not print private keys, session keys, or raw nonce material

Raw packet logging
******************

Set ``CONFIG_SAP_PACKET_LOGGING=y`` to emit hexdumps of the exact SAP packets
that cross the wire:

* auth messages such as ``HELLO`` and ``CENTRAL_AUTH``
* encrypted secure SAP frames such as ``CONFIRM`` and app-defined secure
  payload frames

The sample also provides ``packet_logging.conf`` as a ready-to-use overlay.

When enabled, those lines carry a colored ``[SAP PACKET]`` prefix so they are
easy to distinguish from the higher-level ``[SAP FLOW]`` trace.

Limitations
***********

* v1 uses compile-time credential blobs instead of provisioning.
* ``nrf54l15bsim`` currently does not provide a reliable BLE encryption path
  for this sample or the matching Zephyr privacy+bonding bsim test, so SAP
  transport encryption is the simulator-facing coverage mechanism there.
* The sample peripheral is intentionally single-connection so protected
  services can be hidden with dynamic registration and not be exposed to new
  unauthenticated connections.
* The sample peripheral uses
  ``CONFIG_MCUMGR_TRANSPORT_BT_PERM_RW_ENCRYPT=y`` in ``peripheral.conf`` so
  the gated DFU SMP service matches the sample's ``BT_SECURITY_L2`` BLE
  security level. If an application needs authenticated MCUmgr permissions, it
  should also raise the BLE security requirement accordingly.
* The transport is custom GATT; production systems may prefer a more structured
  application protocol on top.
