#!/usr/bin/env python3
#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


CURVE_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
GROUP_ID = 0x2A
ROOT_ID = 0
HOST_ID = 42
SAP_VERSION = 1
SAP_ROLE_MASK_CENTRAL = 0x01
SAP_ROLE_MASK_PERIPHERAL = 0x02
SAP_ROLE_MASK_ROOT = SAP_ROLE_MASK_CENTRAL | SAP_ROLE_MASK_PERIPHERAL

REPO_ROOT = Path(__file__).resolve().parent.parent
CREDENTIALS_C = REPO_ROOT / "samples/bluetooth/sap_demo/src/demo_credentials.c"
PYTHON_CREDS = REPO_ROOT / "scripts/root_demo_credentials.py"


def derive_private_key(label: str) -> ec.EllipticCurvePrivateKey:
    digest = hashlib.sha256(f"sap-demo:{label}".encode("utf-8")).digest()
    value = (int.from_bytes(digest, "big") % (CURVE_ORDER - 1)) + 1
    return ec.derive_private_key(value, ec.SECP256R1())


def export_public_uncompressed(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def export_private_raw(key: ec.EllipticCurvePrivateKey) -> bytes:
    value = key.private_numbers().private_value
    return value.to_bytes(32, "big")


def sign_raw(key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    der = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def format_c_bytes(data: bytes, indent: int = 3) -> str:
    prefix = "\t" * indent
    rows = []
    for offset in range(0, len(data), 8):
        chunk = data[offset : offset + 8]
        rows.append(prefix + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    return "\n".join(rows)


def format_python_bytes(data: bytes) -> str:
    return "".join(f"\\x{byte:02x}" for byte in data)


def cert_body(role_mask: int, device_id: int, public_key: bytes) -> bytes:
    return bytes([SAP_VERSION, role_mask, device_id, GROUP_ID]) + public_key


def make_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    role_mask: int,
    device_id: int,
    key: ec.EllipticCurvePrivateKey,
) -> tuple[bytes, bytes]:
    body = cert_body(role_mask, device_id, export_public_uncompressed(key))
    return body, sign_raw(ca_key, body)


def c_credential_entry(simulated_device_number: int, role_mask: int, device_id: int,
                       key: ec.EllipticCurvePrivateKey,
                       cert_sig: bytes) -> str:
    body = cert_body(role_mask, device_id, export_public_uncompressed(key))
    return f"""\
\t{{
\t\t.simulated_device_number = {simulated_device_number},
\t\t.private_key = {{
{format_c_bytes(export_private_raw(key))}
\t\t}},
\t\t.cert = {{
\t\t\t.body = {{
\t\t\t\t.version = SAP_VERSION,
\t\t\t\t.role_mask = {role_mask},
\t\t\t\t.device_id = {device_id},
\t\t\t\t.group_id = SAP_GROUP_ID,
\t\t\t\t.public_key = {{
{format_c_bytes(body[4:])}
\t\t\t\t}},
\t\t\t}},
\t\t\t.ca_signature = {{
{format_c_bytes(cert_sig)}
\t\t\t}},
\t\t}},
\t}}"""


def build_materials() -> dict[str, object]:
    ca_key = derive_private_key("ca")
    root_key = derive_private_key("root-central")
    host_key = derive_private_key("upstream-host")
    leaf_keys = [derive_private_key(f"leaf-{idx}") for idx in range(1, 5)]

    materials = {
        "ca_public": export_public_uncompressed(ca_key),
        "root_key": root_key,
        "host_key": host_key,
        "leaf_keys": leaf_keys,
    }

    materials["root_body"], materials["root_sig"] = make_cert(
        ca_key, SAP_ROLE_MASK_ROOT, ROOT_ID, root_key
    )
    materials["host_body"], materials["host_sig"] = make_cert(
        ca_key, SAP_ROLE_MASK_CENTRAL, HOST_ID, host_key
    )
    materials["leaf_sigs"] = [
        make_cert(ca_key, SAP_ROLE_MASK_PERIPHERAL, idx, key)[1]
        for idx, key in enumerate(leaf_keys, start=1)
    ]

    return materials


def build_c_source(materials: dict[str, object]) -> str:
    leaf_entries = []
    leaf_keys = materials["leaf_keys"]
    leaf_sigs = materials["leaf_sigs"]
    for idx, (key, sig) in enumerate(zip(leaf_keys, leaf_sigs), start=1):
        leaf_entries.append(c_credential_entry(idx, SAP_ROLE_MASK_PERIPHERAL, idx, key, sig))

    root_entry = c_credential_entry(
        0,
        SAP_ROLE_MASK_ROOT,
        ROOT_ID,
        materials["root_key"],
        materials["root_sig"],
    )

    return f"""\
/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>

#include "demo_credentials.h"

#if defined(CONFIG_BOARD_NRF54L15BSIM)
extern unsigned int bsim_args_get_global_device_nbr(void);
#endif

static const uint8_t sap_ca_public_key[SAP_IDENTITY_PUBLIC_KEY_LEN] = {{
{format_c_bytes(materials["ca_public"], 1)}
}};

#define SAP_GROUP_ID 0x{GROUP_ID:02X}

static const struct sap_device_credential central_credentials[] = {{
{root_entry}
}};

static const struct sap_device_credential peripheral_credentials[] = {{
{",\n".join(leaf_entries)}
}};

static unsigned int simulated_device_number(void)
{{
#if defined(CONFIG_BOARD_NRF54L15BSIM)
\treturn bsim_args_get_global_device_nbr();
#elif defined(CONFIG_SAP_ROLE_PERIPHERAL)
\treturn CONFIG_SAP_DEMO_PERIPHERAL_ID;
#else
\treturn 0U;
#endif
}}

const struct sap_device_credential *demo_credentials_select(enum sap_role role)
{{
\tsize_t i;
\tunsigned int dev_num = simulated_device_number();

\t#if !defined(CONFIG_SAP_ROLE_PERIPHERAL)
\tARG_UNUSED(role);
\treturn &central_credentials[0];
\t#endif

\tif (role == SAP_ROLE_CENTRAL) {{
\t\treturn &central_credentials[0];
\t}}

\tfor (i = 0; i < ARRAY_SIZE(peripheral_credentials); i++) {{
\t\tif (peripheral_credentials[i].simulated_device_number == dev_num) {{
\t\t\treturn &peripheral_credentials[i];
\t\t}}
\t}}

\treturn &peripheral_credentials[0];
}}

const uint8_t *demo_credentials_ca_public_key(size_t *len)
{{
\tif (len != NULL) {{
\t\t*len = sizeof(sap_ca_public_key);
\t}}

\treturn sap_ca_public_key;
}}
"""


def build_python_credentials(materials: dict[str, object]) -> str:
    return f"""\
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

SAP_VERSION = {SAP_VERSION}
GROUP_ID = 0x{GROUP_ID:02X}
ROOT_ID = {ROOT_ID}
HOST_ID = {HOST_ID}
ROLE_MASK_CENTRAL = 0x{SAP_ROLE_MASK_CENTRAL:02x}
ROLE_MASK_PERIPHERAL = 0x{SAP_ROLE_MASK_PERIPHERAL:02x}
ROLE_MASK_ROOT = 0x{SAP_ROLE_MASK_ROOT:02x}

CA_PUBLIC_KEY = bytes.fromhex("{materials["ca_public"].hex()}")

ROOT_CERT_BODY = bytes.fromhex("{materials["root_body"].hex()}")
ROOT_CERT_SIGNATURE = bytes.fromhex("{materials["root_sig"].hex()}")

HOST_PRIVATE_KEY = bytes.fromhex("{export_private_raw(materials["host_key"]).hex()}")
HOST_CERT_BODY = bytes.fromhex("{materials["host_body"].hex()}")
HOST_CERT_SIGNATURE = bytes.fromhex("{materials["host_sig"].hex()}")
"""


def main() -> None:
    materials = build_materials()
    CREDENTIALS_C.write_text(build_c_source(materials), encoding="utf-8")
    PYTHON_CREDS.write_text(build_python_credentials(materials), encoding="utf-8")


if __name__ == "__main__":
    main()
