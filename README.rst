SAP Zephyr Module
#################

This repository packages Secure Application Pairing (SAP) as a standalone
Zephyr module. The reusable library lives under ``include/sap`` and
``subsys/bluetooth/sap``. The demo application that exercises the module lives
under ``samples/bluetooth/sap_demo``.

What the module provides
***********************

The module owns the SAP control-plane protocol:

* mutual certificate-based authentication over BLE
* per-connection ECDH + HKDF session derivation
* AES-CCM protection for post-auth SAP frames
* session state tracking and authenticated callbacks

The consuming application owns the application plane:

* device credentials and policy
* BLE transport wiring to the SAP auth and secure characteristics
* application message IDs carried inside SAP secure frames
* any protected GATT services or other functionality gated behind SAP auth

Repository layout
*****************

* ``include/sap``: public headers for consumers
* ``subsys/bluetooth/sap``: reusable SAP library implementation
* ``samples/bluetooth/sap_demo``: hardware and BabbleSim demo application
* ``zephyr/module.yml``: module metadata for west and external-module loading

Quick start with ``EXTRA_ZEPHYR_MODULES``
*****************************************

Use this path when you want to try the module from an arbitrary application
without editing a west manifest.

.. code-block:: console

   source /opt/ncs/sdks/ncs-main/activate-nrf.sh
   export SAP_MODULE_ROOT=/home/h/Documents/Nordic/sap-zephyr-module

   west build -p -d build-central-module \
     -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo \
     -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="central.conf;demo_logging.conf"

   west build -p -d build-peripheral-module \
     -b nrf54l15dk/nrf54l15/cpuapp \
     $SAP_MODULE_ROOT/samples/bluetooth/sap_demo \
     -- \
     -DEXTRA_ZEPHYR_MODULES=$SAP_MODULE_ROOT \
     -DEXTRA_CONF_FILE="peripheral.conf;demo_logging.conf"

Adding SAP to a west workspace
******************************

If your application already uses west, add this repository to the workspace
manifest or a submanifest and run ``west update``. Once the module is part of
the workspace, Zephyr discovers it automatically through ``zephyr/module.yml``
and you can build applications without passing ``EXTRA_ZEPHYR_MODULES``.

Example submanifest:

.. code-block:: yaml

   manifest:
     projects:
       - name: sap
         path: modules/lib/sap
         url: <your-sap-repo-url>
         revision: <branch-or-commit>

Using SAP from your own application
***********************************

1. Add the module via west or ``EXTRA_ZEPHYR_MODULES``.
2. Enable at least ``CONFIG_BT=y`` and ``CONFIG_SAP=y`` in the application.
3. Include ``<sap/sap_service.h>`` in the application code.
4. Provide:

   * a ``struct sap_policy`` with your credential and CA material
   * transport callbacks for auth and secure SAP frames
   * application-specific gating once ``authenticated()`` fires

For BLE transports, size the ATT/L2CAP path so the SAP auth packets fit in a
single write or notification. The demo sample uses ``CONFIG_BT_L2CAP_TX_MTU=300``.

The minimal public entry points are:

* ``sap_init()``
* ``sap_on_connected()``
* ``sap_on_disconnected()``
* ``sap_on_security_changed()``
* ``sap_start()``
* ``sap_handle_auth_rx()``
* ``sap_handle_secure_rx()``
* ``sap_send_secure()``

Demo sample
***********

The demo sample still shows the full end-to-end flow, including:

* dynamic registration of a protected GATT service after SAP success
* shell-driven secure text exchange
* peripheral button to central LED mapping on ``nrf54l15dk``

For the full walkthrough and sample-specific behavior, see
``samples/bluetooth/sap_demo/README.rst``.

KMU planning helper
*******************

To print the recommended nRF54L15 KMU migration plan for the SAP identity key,
including the PSA attributes and ``nrfutil`` provisioning command template,
run:

.. code-block:: console

   /home/h/Documents/Nordic/sap-zephyr-module/scripts/explain_sap_kmu.sh
