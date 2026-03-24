#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_NCS_ROOT="/opt/ncs/sdks/ncs-main"

ROLE="peripheral"
SLOT="32"
SCHEME="RAW"
PERSISTENCE="PERSISTENCE_DEFAULT"
SERIAL=""
KEY_HEX=""
KEY_FILE="sap-kmu-keys.json"
NCS_ROOT="${NCS_ROOT:-${DEFAULT_NCS_ROOT}}"

usage() {
	cat <<'EOF'
Usage:
  explain_sap_kmu.sh [options]

This script does not provision anything. It prints the recommended way to move
the SAP long-term identity signing key into the nRF54L15 KMU and shows the
exact PSA / nrfutil commands to use.

Options:
  --role central|peripheral
      Label used in the printed examples.

  --slot <0-255>
      KMU slot number for the SAP identity key. Default: 32

  --scheme RAW|ENCRYPTED
      CRACEN KMU usage scheme. Default: RAW
      RAW is the simplest development path for SAP asymmetric identity keys.
      ENCRYPTED provides better at-rest handling but needs extra KMU slots.

  --persistence PERSISTENCE_DEFAULT|PERSISTENCE_REVOKABLE|PERSISTENCE_READ_ONLY
      PSA persistence setting for the KMU key. Default: PERSISTENCE_DEFAULT

  --serial <probe-serial>
      Optional probe serial for the final nrfutil provisioning command.

  --key-hex 0x<32-byte-secp256r1-private-scalar>
      Optional raw private key for the example provisioning command.
      If omitted, the script prints a placeholder.

  --key-file <path>
      Output JSON path used in the example command. Default: sap-kmu-keys.json

  --ncs-root <path>
      Override the NCS root used in the printed commands.

  -h, --help
      Show this help.

Examples:
  ./scripts/explain_sap_kmu.sh --role central --slot 40 --serial 1057759260
  ./scripts/explain_sap_kmu.sh --role peripheral --slot 42 --scheme ENCRYPTED \\
      --persistence PERSISTENCE_REVOKABLE \\
      --key-hex 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--role)
			ROLE="$2"
			shift 2
			;;
		--slot)
			SLOT="$2"
			shift 2
			;;
		--scheme)
			SCHEME="$2"
			shift 2
			;;
		--persistence)
			PERSISTENCE="$2"
			shift 2
			;;
		--serial)
			SERIAL="$2"
			shift 2
			;;
		--key-hex)
			KEY_HEX="$2"
			shift 2
			;;
		--key-file)
			KEY_FILE="$2"
			shift 2
			;;
		--ncs-root)
			NCS_ROOT="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

case "${ROLE}" in
	central|peripheral) ;;
	*)
		echo "Invalid role: ${ROLE}" >&2
		exit 1
		;;
esac

case "${SCHEME}" in
	RAW)
		SCHEME_MACRO="CRACEN_KMU_KEY_USAGE_SCHEME_RAW"
		SCHEME_NOTES="Simplest asymmetric-key path. The key is pushed through the KMU RAM push area during use."
		;;
	ENCRYPTED)
		SCHEME_MACRO="CRACEN_KMU_KEY_USAGE_SCHEME_ENCRYPTED"
		SCHEME_NOTES="Better at-rest handling, but asymmetric keys still decrypt into the KMU push area during use and consume extra KMU slots."
		;;
	*)
		echo "Invalid scheme: ${SCHEME}" >&2
		exit 1
		;;
esac

case "${PERSISTENCE}" in
	PERSISTENCE_DEFAULT|PERSISTENCE_REVOKABLE|PERSISTENCE_READ_ONLY) ;;
	*)
		echo "Invalid persistence: ${PERSISTENCE}" >&2
		exit 1
		;;
esac

if [[ -z "${KEY_HEX}" ]]; then
	KEY_HEX="0x<32-byte-secp256r1-private-scalar>"
fi

cat <<EOF
SAP KMU migration guide for nRF54L15
===================================

Module root:
  ${MODULE_ROOT}

NCS root used in examples:
  ${NCS_ROOT}

What should go into KMU
-----------------------
- Put the long-term SAP identity private key in KMU.
- Keep the certificate, CA public key, and policy data outside KMU.
- Keep the ephemeral SAP ECDH key and the per-session AES-CCM key volatile.

Why
---
- SAP's long-term secret is the identity signing key used by sap_init() and
  sap_crypto_sign_identity().
- The session ECDH key and session AES key are per-connection state and are
  already destroyed on disconnect. Moving those into KMU would complicate slot
  management without improving the useful trust boundary.

Recommended PSA attributes for the SAP identity key
---------------------------------------------------
- role label: ${ROLE}
- KMU slot: ${SLOT}
- key type: ECC_KEY_PAIR_SECP_R1
- key bits: 256
- usage: SIGN
- algorithm: ECDSA_SHA256
- location: LOCATION_CRACEN_KMU
- cracen usage: ${SCHEME}
- persistence: ${PERSISTENCE}
- key handle in code:
    PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(${SCHEME_MACRO}, ${SLOT})

Usage scheme notes
------------------
- ${SCHEME}: ${SCHEME_NOTES}
- Protected is not the right scheme for the SAP identity key because Nordic's
  KMU/CRACEN model only supports symmetric AES keys as Protected.

Provisioning command template
-----------------------------
1. Generate or append the KMU key description JSON:

   source "${NCS_ROOT}/activate-nrf.sh"
   python3 "${NCS_ROOT}/nrf/scripts/generate_psa_key_attributes.py" \\
     --usage SIGN \\
     --id ${SLOT} \\
     --type ECC_KEY_PAIR_SECP_R1 \\
     --key-bits 256 \\
     --algorithm ECDSA_SHA256 \\
     --location LOCATION_CRACEN_KMU \\
     --persistence ${PERSISTENCE} \\
     --cracen-usage ${SCHEME} \\
     --key ${KEY_HEX} \\
     --file ${KEY_FILE}

2. Provision the JSON to the device:

   source "${NCS_ROOT}/activate-nrf.sh"
   nrfutil device x-provision-keys --key-file ${KEY_FILE}$( [[ -n "${SERIAL}" ]] && printf ' --serial-number %s' "${SERIAL}" )

How SAP should consume the KMU key
----------------------------------
Library changes:
- Add an optional persistent PSA key id to struct sap_policy.
- In sap_init(), if that key id is nonzero, use it directly as ctx->local_sign_key_id.
- If SAP imported the key from a raw blob, keep destroying it on sap_uninit().
- If SAP was given a persistent KMU key id, do not call psa_destroy_key() on uninit.
- Export the public key from the configured key id once at init and compare it to
  policy.local_credential->cert.body.public_key. Fail early if they do not match.

Demo/sample changes:
- Keep using the existing certificate table.
- Stop embedding the long-term private key bytes when KMU mode is enabled.
- Provide the KMU-backed PSA key id through the sample policy instead.

Exact files to change in this repo
----------------------------------
- ${MODULE_ROOT}/include/sap/sap_service.h
- ${MODULE_ROOT}/subsys/bluetooth/sap/sap_service.c
- ${MODULE_ROOT}/subsys/bluetooth/sap/sap_crypto.h
- ${MODULE_ROOT}/subsys/bluetooth/sap/sap_crypto.c
- ${MODULE_ROOT}/samples/bluetooth/sap_demo/Kconfig
- ${MODULE_ROOT}/samples/bluetooth/sap_demo/src/demo_credentials.h
- ${MODULE_ROOT}/samples/bluetooth/sap_demo/src/demo_credentials.c
- ${MODULE_ROOT}/samples/bluetooth/sap_demo/src/main.c

Relevant Nordic references
--------------------------
- ${NCS_ROOT}/nrf/doc/nrf/app_dev/device_guides/kmu_guides/kmu_psa_crypto_api_prog_model.rst
- ${NCS_ROOT}/nrf/doc/nrf/app_dev/device_guides/kmu_guides/kmu_provisioning_overview.rst
- ${NCS_ROOT}/nrf/samples/crypto/kmu_cracen_usage/README.rst
- ${NCS_ROOT}/nrf/subsys/nrf_security/src/drivers/cracen/cracenpsa/include/cracen_psa_kmu.h

Practical recommendation
------------------------
- First implementation: use RAW + PERSISTENCE_DEFAULT for development.
- Hardening step: move to ENCRYPTED or use TF-M if you need the temporary KMU
  push area shielded from non-secure application code.
- Keep KMU for the long-term identity key only. Leave SAP's ephemeral handshake
  and session keys volatile.
EOF
