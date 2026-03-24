SAP sample implementation plan
==============================

Intent
------

Build a simulation-first BLE sample that demonstrates Secure Application
Pairing as a reusable application-layer service on
``nrf54l15bsim/nrf54l15/cpuapp``.

Security model
--------------

* SAP root CA public key embedded in firmware
* Per-device ``secp256r1`` ECDSA identity keys with compact CA-signed certificates
* BLE link encryption required before SAP can progress on real targets
* ``nrf54l15bsim`` defaults to SAP-only link protection for simulator coverage
* local validation on March 24, 2026 showed BLE encryption failing on
  ``nrf54l15bsim`` in both SAP and
  ``tests/bsim/bluetooth/host/adv/periodic:per_adv_conn_privacy_sync``
* local validation on March 24, 2026 with two ``nrf54l15dk`` boards confirmed
  BLE encryption plus full SAP auth on real silicon
* CRACEN-backed HKDF on ``nrf54l15`` limits the info field to 128 bytes, so
  the session derivation path hashes the full ECDH transcript before HKDF
* Ephemeral ECDH plus HKDF-SHA256 for per-session AES-CCM keys
* One central authenticates many peripherals

Sample shape
------------

* ``sap_service`` holds the reusable state machine, policy, and crypto flow
* role-specific files adapt SAP to BLE central and peripheral transports
* peripheral registers a second protected service only after SAP succeeds
* dynamic service visibility is paired with per-connection auth checks
* peripheral stays single-connection because dynamic GATT visibility is global

Deferred hardening
------------------

* KMU-backed provisioning
* hardware-backed key isolation on real silicon
* certificate lifecycle tooling
