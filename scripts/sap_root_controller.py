#!/usr/bin/env python3
#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import root_demo_credentials as creds


SAP_SERVICE_UUID = "7a18e2d1-3bd2-4f31-8c4b-b6c5b8f7a001"
SAP_AUTH_UUID = "7a18e2d1-3bd2-4f31-8c4b-b6c5b8f7a002"
SAP_SECURE_TX_UUID = "7a18e2d1-3bd2-4f31-8c4b-b6c5b8f7a003"
SAP_SECURE_RX_UUID = "7a18e2d1-3bd2-4f31-8c4b-b6c5b8f7a004"

SAP_NONCE_LEN = 16
SAP_CERT_BODY_LEN = 1 + 1 + 1 + 1 + 65
SAP_CERT_LEN = SAP_CERT_BODY_LEN + 64
SAP_SECURE_HEADER_LEN = 14
SAP_AEAD_TAG_LEN = 16
SAP_AEAD_NONCE_BASE_LEN = 8
ATT_WRITE_OVERHEAD = 3

SAP_MSG_HELLO = 1
SAP_MSG_PERIPHERAL_CHALLENGE = 2
SAP_MSG_CENTRAL_AUTH = 3
SAP_MSG_PERIPHERAL_AUTH = 4
SAP_MSG_CONFIRM = 5

SAP_SIG_PERIPHERAL_CHALLENGE = 0xA1
SAP_SIG_CENTRAL_AUTH = 0xA2
SAP_SIG_PERIPHERAL_AUTH = 0xA3

SAP_CONFIRM_TEXT = b"SAP-OK"

SAP_APP_MSG_TYPE_MIN = 0x80
SAP_DEMO_MSG_TEXT = SAP_APP_MSG_TYPE_MIN
SAP_DEMO_MSG_ROOT_STATUS_REQ = SAP_APP_MSG_TYPE_MIN + 2
SAP_DEMO_MSG_ROOT_STATUS_RSP = SAP_APP_MSG_TYPE_MIN + 3
SAP_DEMO_MSG_ROOT_SELECT_LEAF = SAP_APP_MSG_TYPE_MIN + 4
SAP_DEMO_MSG_ROOT_SELECT_RSP = SAP_APP_MSG_TYPE_MIN + 5
SAP_DEMO_MSG_ROOT_DFU_BEGIN = SAP_APP_MSG_TYPE_MIN + 6
SAP_DEMO_MSG_ROOT_DFU_CHUNK = SAP_APP_MSG_TYPE_MIN + 7
SAP_DEMO_MSG_ROOT_DFU_PROGRESS = SAP_APP_MSG_TYPE_MIN + 8
SAP_DEMO_MSG_ROOT_DFU_FINISH = SAP_APP_MSG_TYPE_MIN + 9
SAP_DEMO_MSG_ROOT_DFU_RESULT = SAP_APP_MSG_TYPE_MIN + 10

SAP_ROLE_MASK_CENTRAL = 0x01
SAP_ROLE_MASK_PERIPHERAL = 0x02

ROOT_STATUS_OK = 0
ROOT_STATUS_INVALID = 1
ROOT_STATUS_NO_PEER = 2
ROOT_STATUS_BUSY = 3
ROOT_STATUS_BAD_STATE = 4
ROOT_STATUS_DFU_ERROR = 5

ROOT_PEER_AUTHENTICATED = 1 << 0
ROOT_PEER_PROTECTED_READY = 1 << 1
ROOT_PEER_DFU_READY = 1 << 2
ROOT_PEER_SELECTED = 1 << 3
ROOT_PEER_LED_ASSIGNED = 1 << 4

DEFAULT_CHUNK_SIZE = 240
PROGRESS_REPORT_STEP = 4096
DFU_FINISH_SETTLE_DELAY = 0.25
POST_DFU_SCAN_SETTLE_DELAY = 15.0
UPLOAD_PREPARE_TIMEOUT = 30.0
MCUBOOT_IMAGE_MAGIC = 0x96F3B83D
MCUBOOT_IMAGE_MAGIC_V1 = 0x96F3B83C
MCUBOOT_TLV_INFO_MAGIC = 0x6907
MCUBOOT_TLV_PROT_INFO_MAGIC = 0x6908
MCUBOOT_IMAGE_HEADER_FMT = "<IIHHIIBBHII"
MCUBOOT_IMAGE_HEADER_SIZE = struct.calcsize(MCUBOOT_IMAGE_HEADER_FMT)
MCUBOOT_TLV_INFO_FMT = "<HH"
MCUBOOT_TLV_INFO_SIZE = struct.calcsize(MCUBOOT_TLV_INFO_FMT)
MCUBOOT_TLV_FMT = "<HH"
MCUBOOT_TLV_SIZE = struct.calcsize(MCUBOOT_TLV_FMT)
MCUBOOT_HASH_TLV_LENGTHS = {
    0x10: 32,
    0x11: 48,
    0x12: 64,
}
ROOT_DFU_UPLOAD_HASH_LEN = 32
ROOT_DFU_BOOT_HASH_MAX_LEN = 64
DEBUG = os.environ.get("SAP_ROOT_DEBUG", "").lower() not in ("", "0", "false", "no")


def debug_log(message: str) -> None:
    if not DEBUG:
        return
    print(f"[sap-root-debug] {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class SapCertificate:
    body: bytes
    signature: bytes
    version: int
    role_mask: int
    device_id: int
    group_id: int
    public_key_bytes: bytes


@dataclass(frozen=True)
class SecureEvent:
    msg_type: int
    payload: bytes


@dataclass(frozen=True)
class RootPeerStatus:
    peer_id: int
    state: int
    flags: int
    led_index: int
    pattern_id: int
    dfu_chunk_limit: int


@dataclass(frozen=True)
class RootStatus:
    selected_peer_id: int
    peers: tuple[RootPeerStatus, ...]


@dataclass(frozen=True)
class LoadedImage:
    data: bytes
    source: str


class BluezAutoAgent:
    DEVICE_LINE_RE = re.compile(r"Device ([0-9A-F:]{17}) (.+)")

    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled
        self.proc: subprocess.Popen[bytes] | None = None
        self.master_fd: int | None = None
        self.reader_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.condition = threading.Condition()
        self._buffer = ""
        self._last_auto_yes = 0.0

    async def __aenter__(self) -> "BluezAutoAgent":
        if not self.enabled:
            return self

        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        self.proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self._write("agent NoInputNoOutput\n")
        self._write("default-agent\n")
        await asyncio.sleep(0.25)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.proc is None:
            return

        try:
            self._write("quit\n")
        except Exception:
            pass

        self.stop_event.set()
        if self.reader_thread is not None:
            self.reader_thread.join(timeout=1.0)

        try:
            await asyncio.wait_for(asyncio.to_thread(self.proc.wait, 2.0), timeout=3.0)
        except Exception:
            self.proc.kill()
            await asyncio.to_thread(self.proc.wait)

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    def _write(self, text: str) -> None:
        if self.master_fd is None:
            return
        os.write(self.master_fd, text.encode())

    def _reader_loop(self) -> None:
        if self.master_fd is None:
            return

        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.master_fd], [], [], 0.2)
            if not ready:
                continue

            try:
                chunk = os.read(self.master_fd, 256)
            except OSError:
                return

            if not chunk:
                return

            text = chunk.decode(errors="ignore")
            with self.condition:
                self._buffer += text
                self.condition.notify_all()

            if self._needs_auto_yes():
                now = time.monotonic()
                if (now - self._last_auto_yes) >= 0.2:
                    self._last_auto_yes = now
                    self._write("yes\n")

    def _needs_auto_yes(self) -> bool:
        prompts = (
            "accept pairing",
            "authorize service",
            "request confirmation",
            "confirm passkey",
        )
        return any(prompt in self._buffer.lower() for prompt in prompts)

    def _wait_for_tokens(
        self,
        *,
        start_idx: int,
        success_tokens: tuple[str, ...],
        failure_tokens: tuple[str, ...],
        timeout: float,
    ) -> str:
        deadline = time.monotonic() + timeout

        with self.condition:
            while True:
                window = self._buffer[start_idx:].lower()

                for token in success_tokens:
                    if token in window:
                        return token

                for token in failure_tokens:
                    if token in window:
                        raise RuntimeError(token)

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"timed out waiting for bluetoothctl tokens {success_tokens}"
                    )

                self.condition.wait(timeout=remaining)

    async def pair_device(self, address: str) -> None:
        if not self.enabled or self.master_fd is None:
            return

        with self.condition:
            start_idx = len(self._buffer)
        self._write(f"pair {address}\n")
        await asyncio.to_thread(
            self._wait_for_tokens,
            start_idx=start_idx,
            success_tokens=("pairing successful", "paired: yes", "alreadyexists", "already exists"),
            failure_tokens=(
                "failed to pair",
                "authenticationcanceled",
                "authentication canceled",
                "authenticationfailed",
                "authentication failed",
            ),
            timeout=30.0,
        )

        for command, success_tokens in (
            (f"trust {address}\n", ("trust succeeded", "trusted: yes")),
            (f"disconnect {address}\n", ("successful disconnected", "connected: no", "not connected")),
        ):
            with self.condition:
                start_idx = len(self._buffer)
            self._write(command)
            try:
                await asyncio.to_thread(
                    self._wait_for_tokens,
                    start_idx=start_idx,
                    success_tokens=success_tokens,
                    failure_tokens=("failed",),
                    timeout=10.0,
                )
            except Exception:
                pass

    def _wait_for_named_device(self, *, start_idx: int, name: str, timeout: float) -> str:
        deadline = time.monotonic() + timeout

        with self.condition:
            while True:
                window = self._buffer[start_idx:]
                matches = self.DEVICE_LINE_RE.findall(window)
                for address, found_name in reversed(matches):
                    if found_name.strip() == name:
                        return address

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting to discover {name}")

                self.condition.wait(timeout=remaining)

    async def discover_device_address(self, name: str, timeout: float) -> str:
        if not self.enabled or self.master_fd is None:
            raise RuntimeError("bluetoothctl agent is not available")

        with self.condition:
            start_idx = len(self._buffer)
        self._write("scan on\n")
        try:
            return await asyncio.to_thread(
                self._wait_for_named_device,
                start_idx=start_idx,
                name=name,
                timeout=timeout,
            )
        finally:
            self._write("scan off\n")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def extract_mcuboot_boot_hash(image: bytes) -> bytes:
    if len(image) < MCUBOOT_IMAGE_HEADER_SIZE:
        raise ValueError("signed image is too small to contain an MCUboot header")

    (
        magic,
        _load_addr,
        hdr_size,
        protect_tlv_size,
        img_size,
        _flags,
        _ver_major,
        _ver_minor,
        _ver_revision,
        _ver_build_num,
        _pad1,
    ) = struct.unpack_from(MCUBOOT_IMAGE_HEADER_FMT, image, 0)

    if magic not in (MCUBOOT_IMAGE_MAGIC, MCUBOOT_IMAGE_MAGIC_V1):
        raise ValueError(f"unexpected MCUboot magic 0x{magic:08x}")

    tlv_off = hdr_size + img_size
    if (tlv_off + MCUBOOT_TLV_INFO_SIZE) > len(image):
        raise ValueError("signed image is truncated before the TLV area")

    tlv_magic, tlv_total = struct.unpack_from(MCUBOOT_TLV_INFO_FMT, image, tlv_off)
    if tlv_magic == MCUBOOT_TLV_PROT_INFO_MAGIC:
        if tlv_total != protect_tlv_size:
            raise ValueError(
                f"protected TLV size mismatch: header={protect_tlv_size} actual={tlv_total}"
            )
        tlv_off += tlv_total
        if (tlv_off + MCUBOOT_TLV_INFO_SIZE) > len(image):
            raise ValueError("signed image is truncated before the unprotected TLV area")
        tlv_magic, tlv_total = struct.unpack_from(MCUBOOT_TLV_INFO_FMT, image, tlv_off)

    if tlv_magic != MCUBOOT_TLV_INFO_MAGIC:
        raise ValueError(f"unexpected TLV info magic 0x{tlv_magic:04x}")

    tlv_end = tlv_off + tlv_total
    if tlv_end > len(image):
        raise ValueError("signed image TLV area extends past the end of the file")

    cursor = tlv_off + MCUBOOT_TLV_INFO_SIZE
    while (cursor + MCUBOOT_TLV_SIZE) <= tlv_end:
        tlv_type, tlv_len = struct.unpack_from(MCUBOOT_TLV_FMT, image, cursor)
        cursor += MCUBOOT_TLV_SIZE
        value_end = cursor + tlv_len
        if value_end > tlv_end:
            raise ValueError("encountered a truncated MCUboot TLV entry")

        if tlv_type in MCUBOOT_HASH_TLV_LENGTHS:
            expected_len = MCUBOOT_HASH_TLV_LENGTHS[tlv_type]
            if tlv_len != expected_len:
                raise ValueError(
                    f"unexpected hash TLV length {tlv_len} for type 0x{tlv_type:02x}"
                )
            return image[cursor:value_end]

        cursor = value_end

    raise ValueError("signed image does not contain an MCUboot boot hash TLV")


def load_upload_image(path_str: str) -> LoadedImage:
    path = Path(path_str)
    if path.suffix.lower() == ".zip":
        return load_upload_image_from_zip(path)
    return LoadedImage(data=path.read_bytes(), source=str(path))


def load_upload_image_from_zip(path: Path) -> LoadedImage:
    with zipfile.ZipFile(path) as zf:
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except KeyError as exc:
            raise ValueError(f"{path} does not contain manifest.json") from exc

        files = manifest.get("files", [])
        if not isinstance(files, list) or not files:
            raise ValueError(f"{path} manifest does not describe any DFU images")

        selected = None
        for entry in files:
            if str(entry.get("image_index")) == "0" and str(entry.get("slot")) == "1":
                selected = entry
                break
        if selected is None:
            for entry in files:
                if str(entry.get("image_index")) == "0":
                    selected = entry
                    break
        if selected is None:
            raise ValueError(f"{path} manifest does not contain an application image")

        file_name = selected.get("file")
        if not isinstance(file_name, str) or not file_name:
            raise ValueError(f"{path} manifest selected entry has no file name")

        try:
            data = zf.read(file_name)
        except KeyError as exc:
            raise ValueError(f"{path} is missing payload {file_name}") from exc

        slot = selected.get("slot", "?")
        image_index = selected.get("image_index", "?")
        return LoadedImage(
            data=data,
            source=f"{path}:{file_name} (image {image_index}, slot {slot})",
        )


def load_public_key_uncompressed(encoded: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)


def private_key_from_bytes(raw: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def raw_signature_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError(f"expected 64-byte signature, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    return utils.encode_dss_signature(r, s)


def der_signature_to_raw(signature: bytes) -> bytes:
    r, s = utils.decode_dss_signature(signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_raw(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    digest = sha256(message)
    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return der_signature_to_raw(signature)


def verify_raw(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> None:
    digest = sha256(message)
    public_key.verify(
        raw_signature_to_der(signature),
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def parse_certificate(cert: bytes) -> SapCertificate:
    if len(cert) != SAP_CERT_LEN:
        raise ValueError(f"expected {SAP_CERT_LEN} cert bytes, got {len(cert)}")
    body = cert[:SAP_CERT_BODY_LEN]
    signature = cert[SAP_CERT_BODY_LEN:]
    return SapCertificate(
        body=body,
        signature=signature,
        version=body[0],
        role_mask=body[1],
        device_id=body[2],
        group_id=body[3],
        public_key_bytes=body[4:69],
    )


def verify_certificate(
    certificate: SapCertificate,
    *,
    expected_role_mask: int,
    expected_device_id: int | None = None,
) -> None:
    if certificate.version != creds.SAP_VERSION:
        raise ValueError(f"unsupported SAP version {certificate.version}")
    if (certificate.role_mask & expected_role_mask) == 0:
        raise ValueError(
            f"certificate role mask 0x{certificate.role_mask:02x} is not compatible"
        )
    if certificate.group_id != creds.GROUP_ID:
        raise ValueError(f"certificate group 0x{certificate.group_id:02x} is not allowed")
    if expected_device_id is not None and certificate.device_id != expected_device_id:
        raise ValueError(
            f"expected device id {expected_device_id}, got {certificate.device_id}"
        )

    ca_public = load_public_key_uncompressed(creds.CA_PUBLIC_KEY)
    verify_raw(ca_public, certificate.body, certificate.signature)


def make_peripheral_challenge_sig(central_nonce: bytes, peripheral_nonce: bytes, cert_body: bytes) -> bytes:
    return bytes([SAP_SIG_PERIPHERAL_CHALLENGE]) + central_nonce + peripheral_nonce + cert_body


def make_central_auth_sig(
    central_nonce: bytes,
    peripheral_nonce: bytes,
    central_cert_body: bytes,
    peripheral_cert_body: bytes,
    central_ecdh_public: bytes,
) -> bytes:
    return (
        bytes([SAP_SIG_CENTRAL_AUTH])
        + central_nonce
        + peripheral_nonce
        + central_cert_body
        + peripheral_cert_body
        + central_ecdh_public
    )


def make_peripheral_auth_sig(
    central_nonce: bytes,
    peripheral_nonce: bytes,
    central_cert_body: bytes,
    peripheral_cert_body: bytes,
    central_ecdh_public: bytes,
    peripheral_ecdh_public: bytes,
) -> bytes:
    return (
        bytes([SAP_SIG_PERIPHERAL_AUTH])
        + central_nonce
        + peripheral_nonce
        + central_cert_body
        + peripheral_cert_body
        + central_ecdh_public
        + peripheral_ecdh_public
    )


def build_nonce(base: bytes, counter: int, msg_type: int) -> bytes:
    return base + struct.pack("<I", counter) + bytes([msg_type])


class SapRootClient:
    def __init__(
        self,
        *,
        address: str | None,
        name: str | None,
        timeout: float,
        dfu_progress_timeout: float,
        adapter: str | None,
        use_linux_agent: bool,
        pre_pair: bool,
    ) -> None:
        self.address = address
        self.name = name or f"SAP-C-{creds.ROOT_ID}"
        self.timeout = timeout
        self.dfu_progress_timeout = max(timeout, dfu_progress_timeout)
        self.adapter = adapter
        self.loop: asyncio.AbstractEventLoop | None = None
        self.client: BleakClient | None = None
        self.auth_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.secure_queue: asyncio.Queue[SecureEvent] = asyncio.Queue()
        self.auth_backlog: list[bytes] = []
        self.secure_backlog: list[SecureEvent] = []
        self.central_nonce = b""
        self.peripheral_nonce = b""
        self.root_cert: SapCertificate | None = None
        self.host_private_key = private_key_from_bytes(creds.HOST_PRIVATE_KEY)
        self.host_cert = parse_certificate(creds.HOST_CERT_BODY + creds.HOST_CERT_SIGNATURE)
        self.local_ecdh_private: ec.EllipticCurvePrivateKey | None = None
        self.local_ecdh_public = b""
        self.remote_ecdh_public = b""
        self.aes_ccm: AESCCM | None = None
        self.tx_counter = 0
        self.rx_counter = 0
        self.session_key_ready = False
        self.authenticated = False
        self.waiting_for_confirm_tx = False
        self.last_reported_progress = 0
        self.agent = BluezAutoAgent(
            enabled=(
                use_linux_agent
                and sys.platform.startswith("linux")
                and shutil.which("bluetoothctl") is not None
            )
        )
        self.pre_pair = pre_pair and self.agent.enabled

    def _scanner_kwargs(self) -> dict[str, str]:
        return {"adapter": self.adapter} if self.adapter else {}

    def _scan_timeout(self) -> float:
        return min(self.timeout, 20.0)

    def _reset_session_state(self) -> None:
        self.auth_queue = asyncio.Queue()
        self.secure_queue = asyncio.Queue()
        self.auth_backlog.clear()
        self.secure_backlog.clear()
        self.central_nonce = b""
        self.peripheral_nonce = b""
        self.root_cert = None
        self.local_ecdh_private = None
        self.local_ecdh_public = b""
        self.remote_ecdh_public = b""
        self.aes_ccm = None
        self.tx_counter = 0
        self.rx_counter = 0
        self.session_key_ready = False
        self.authenticated = False
        self.waiting_for_confirm_tx = False

    async def _disconnect_client(self) -> None:
        if self.client is None:
            return

        try:
            await self.client.disconnect()
        except Exception:
            pass
        finally:
            self.client = None

    async def reconnect(self) -> None:
        await self._disconnect_client()
        self._reset_session_state()
        await self.connect()
        await self.authenticate()

    async def __aenter__(self) -> "SapRootClient":
        await self.agent.__aenter__()
        try:
            last_exc: Exception | None = None
            for attempt in range(3):
                try:
                    await self.connect()
                    await self.authenticate()
                    return self
                except Exception as exc:
                    last_exc = exc
                    await self._disconnect_client()
                    self._reset_session_state()
                    if attempt == 2 or not self._is_retryable_session_error(exc):
                        raise
                    await asyncio.sleep(1.0 + attempt)
            if last_exc is not None:
                raise last_exc
            raise RuntimeError("unreachable")
        except Exception:
            await self.agent.__aexit__(*sys.exc_info())
            raise

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            await self._disconnect_client()
        finally:
            await self.agent.__aexit__(exc_type, exc, tb)

    async def connect(self) -> None:
        device = await self._discover_root()
        if self.pre_pair:
            device_props = {}
            if hasattr(device, "details") and isinstance(device.details, dict):
                device_props = device.details.get("props", {})
            already_paired = bool(device_props.get("Paired") or device_props.get("Bonded"))
            if not already_paired:
                last_exc: Exception | None = None
                for attempt in range(3):
                    try:
                        await self.agent.pair_device(self._device_address(device))
                        last_exc = None
                        break
                    except Exception as exc:
                        last_exc = exc
                        if attempt == 2:
                            break
                        self._forget_known_root_devices(self._device_address(device))
                        await asyncio.sleep(2.0)
                        device = await self._discover_root()
                if last_exc is not None:
                    print(
                        f"warning: BLE pre-pair attempt failed ({last_exc}); continuing without an existing bond",
                        file=sys.stderr,
                        flush=True,
                    )
        elif self.agent.enabled:
            # For the upstream demo path, BLE encryption is optional. Make the
            # default Linux flow an explicitly unpaired GATT session so BlueZ
            # does not try to resume a stale bond and immediately tear the link
            # down before SAP runs.
            self._forget_known_root_devices(self._device_address(device))
            await asyncio.sleep(0.5)
            device = await self._discover_root()

        self.loop = asyncio.get_running_loop()
        last_exc: Exception | None = None
        for attempt in range(4):
            try:
                await self._connect_client(device)
                await self._acquire_mtu_if_supported()
                await self.client.start_notify(SAP_AUTH_UUID, self._auth_notification)
                await self.client.start_notify(SAP_SECURE_TX_UUID, self._secure_notification)
                last_exc = None
                break
            except TimeoutError as exc:
                last_exc = exc
            except BleakError as exc:
                last_exc = exc
                if not self._is_retryable_connect_error(exc):
                    raise
            finally:
                if last_exc is not None:
                    await self._disconnect_client()

            if attempt == 3:
                break

            self._forget_known_root_devices(self._device_address(device))
            await asyncio.sleep(1.0 + attempt)
            device = await self._discover_root()

        if last_exc is not None:
            raise last_exc

    async def _connect_client(self, device) -> None:
        self.client = BleakClient(
            device,
            timeout=self.timeout,
            pair=False,
            **({"adapter": self.adapter} if self.adapter else {}),
        )
        await self.client.connect()

    @staticmethod
    def _device_address(device) -> str:
        return device if isinstance(device, str) else device.address

    @staticmethod
    def _is_retryable_connect_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            "failed to discover services, device disconnected" in text
            or "org.bluez.error.inprogress" in text
            or "org.bluez.error.failed" in text and "connection-canceled" in text
            or "connection canceled" in text
            or "br-connection-canceled" in text
            or "org.bluez.error.notconnected" in text
            or "not connected" in text
            or "device disconnected" in text
        )

    @classmethod
    def _is_retryable_session_error(cls, exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            cls._is_retryable_connect_error(exc)
            or "timed out waiting for auth frame" in text
            or "timed out waiting for secure msg" in text
            or "timed out waiting for secure msgs" in text
        )

    def _forget_known_root_devices(self, discovered_address: str | None) -> bool:
        if not sys.platform.startswith("linux") or shutil.which("bluetoothctl") is None:
            return False

        addresses: set[str] = set()
        if discovered_address:
            addresses.add(discovered_address)
        if self.address:
            addresses.add(self.address)

        try:
            result = subprocess.run(
                ["bluetoothctl", "devices"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception:
            result = None

        if result is not None:
            for line in result.stdout.splitlines():
                if not line.startswith("Device "):
                    continue
                _, addr, *name_parts = line.split()
                if " ".join(name_parts) == self.name:
                    addresses.add(addr)

        if not addresses:
            return False

        for address in addresses:
            subprocess.run(
                ["bluetoothctl", "remove", address],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )

        return True

    async def _acquire_mtu_if_supported(self) -> None:
        if self.client is None:
            return

        backend = getattr(self.client, "_backend", None)
        acquire_mtu = getattr(backend, "_acquire_mtu", None)
        if acquire_mtu is None:
            return

        try:
            await acquire_mtu()
        except Exception:
            pass

    async def authenticate(self) -> None:
        if self.client is None:
            raise RuntimeError("client not connected")

        self.central_nonce = os.urandom(SAP_NONCE_LEN)
        hello = struct.pack("<BB", creds.SAP_VERSION, SAP_MSG_HELLO) + self.central_nonce
        await self.client.write_gatt_char(SAP_AUTH_UUID, hello, response=True)

        challenge_frame = await self._wait_for_auth_frame(self.timeout)
        if len(challenge_frame) != 2 + SAP_CERT_LEN + SAP_NONCE_LEN + 64:
            raise ValueError(f"unexpected peripheral challenge length {len(challenge_frame)}")
        if challenge_frame[0] != creds.SAP_VERSION or challenge_frame[1] != SAP_MSG_PERIPHERAL_CHALLENGE:
            raise ValueError("unexpected auth frame while waiting for challenge")

        cert_start = 2
        cert_end = cert_start + SAP_CERT_LEN
        self.root_cert = parse_certificate(challenge_frame[cert_start:cert_end])
        self.peripheral_nonce = challenge_frame[cert_end : cert_end + SAP_NONCE_LEN]
        challenge_sig = challenge_frame[cert_end + SAP_NONCE_LEN :]
        verify_certificate(
            self.root_cert,
            expected_role_mask=SAP_ROLE_MASK_PERIPHERAL,
            expected_device_id=creds.ROOT_ID,
        )
        verify_raw(
            load_public_key_uncompressed(self.root_cert.public_key_bytes),
            make_peripheral_challenge_sig(
                self.central_nonce, self.peripheral_nonce, self.root_cert.body
            ),
            challenge_sig,
        )

        self.local_ecdh_private = ec.generate_private_key(ec.SECP256R1())
        self.local_ecdh_public = self.local_ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        central_auth_sig = sign_raw(
            self.host_private_key,
            make_central_auth_sig(
                self.central_nonce,
                self.peripheral_nonce,
                self.host_cert.body,
                self.root_cert.body,
                self.local_ecdh_public,
            ),
        )
        central_auth = (
            struct.pack("<BB", creds.SAP_VERSION, SAP_MSG_CENTRAL_AUTH)
            + self.host_cert.body
            + self.host_cert.signature
            + self.local_ecdh_public
            + central_auth_sig
        )
        await self.client.write_gatt_char(SAP_AUTH_UUID, central_auth, response=True)

        peripheral_auth = await self._wait_for_auth_frame(self.timeout)
        if len(peripheral_auth) != 2 + 65 + 64:
            raise ValueError(f"unexpected peripheral auth length {len(peripheral_auth)}")
        if peripheral_auth[0] != creds.SAP_VERSION or peripheral_auth[1] != SAP_MSG_PERIPHERAL_AUTH:
            raise ValueError("unexpected auth frame while waiting for peripheral auth")

        self.remote_ecdh_public = peripheral_auth[2 : 2 + 65]
        peripheral_auth_sig = peripheral_auth[2 + 65 :]
        verify_raw(
            load_public_key_uncompressed(self.root_cert.public_key_bytes),
            make_peripheral_auth_sig(
                self.central_nonce,
                self.peripheral_nonce,
                self.host_cert.body,
                self.root_cert.body,
                self.local_ecdh_public,
                self.remote_ecdh_public,
            ),
            peripheral_auth_sig,
        )

        self._derive_session_keys()
        self.waiting_for_confirm_tx = True
        await self.send_secure(SAP_MSG_CONFIRM, SAP_CONFIRM_TEXT)
        self.authenticated = True
        self.waiting_for_confirm_tx = False

    async def request_status(self) -> bytes:
        return await self.request_response(SAP_DEMO_MSG_ROOT_STATUS_REQ, b"", SAP_DEMO_MSG_ROOT_STATUS_RSP)

    async def request_status_info(self) -> RootStatus:
        return parse_status(await self.request_status())

    async def select_leaf(self, peer_id: int) -> bytes:
        payload = struct.pack("<B", peer_id)
        return await self.request_response(
            SAP_DEMO_MSG_ROOT_SELECT_LEAF,
            payload,
            SAP_DEMO_MSG_ROOT_SELECT_RSP,
        )

    async def wait_for_peer_status(
        self,
        peer_id: int,
        *,
        timeout: float,
        expected_pattern: int | None = None,
        require_authenticated: bool = True,
        require_dfu: bool = True,
        require_protected: bool = True,
    ) -> RootPeerStatus:
        deadline = asyncio.get_running_loop().time() + timeout

        while True:
            try:
                status = await self.request_status_info()
            except (BleakError, RuntimeError) as exc:
                remaining = deadline - asyncio.get_running_loop().time()
                debug_log(
                    f"wait_for_peer_status peer={peer_id} request failed: {exc!r}; remaining={remaining:.1f}s"
                )

                if remaining <= 0:
                    raise TimeoutError(
                        f"timed out waiting for peer {peer_id} status"
                        + (
                            f" with pattern {expected_pattern}"
                            if expected_pattern is not None
                            else ""
                        )
                    ) from exc

                await self.reconnect()
                continue

            for peer in status.peers:
                if peer.peer_id != peer_id:
                    continue
                debug_log(
                    "wait_for_peer_status "
                    f"peer={peer.peer_id} state={peer.state} flags={format_peer_flags(peer.flags)} "
                    f"pattern={peer.pattern_id} chunk_limit={peer.dfu_chunk_limit}"
                )
                if require_authenticated and not (peer.flags & ROOT_PEER_AUTHENTICATED):
                    break
                if require_dfu and not (peer.flags & ROOT_PEER_DFU_READY):
                    break
                if require_protected and not (peer.flags & ROOT_PEER_PROTECTED_READY):
                    break
                if expected_pattern is not None and peer.pattern_id != expected_pattern:
                    break
                return peer

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timed out waiting for peer {peer_id} status"
                    + (
                        f" with pattern {expected_pattern}"
                        if expected_pattern is not None
                        else ""
                    )
                )

            await asyncio.sleep(min(1.0, remaining))

    async def wait_for_peer_status_via_reconnect(
        self,
        peer_id: int,
        *,
        timeout: float,
        expected_pattern: int | None = None,
        require_authenticated: bool = True,
        require_dfu: bool = True,
        require_protected: bool = True,
        settle_delay: float = POST_DFU_SCAN_SETTLE_DELAY,
    ) -> RootPeerStatus:
        deadline = asyncio.get_running_loop().time() + timeout

        await self._disconnect_client()
        self._reset_session_state()

        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timed out waiting for peer {peer_id} status"
                    + (
                        f" with pattern {expected_pattern}"
                        if expected_pattern is not None
                        else ""
                    )
                )

            await asyncio.sleep(min(settle_delay, remaining))

            try:
                await self.connect()
                await self.authenticate()
                status = await self.request_status_info()
            except Exception:
                await self._disconnect_client()
                self._reset_session_state()
                continue

            for peer in status.peers:
                if peer.peer_id != peer_id:
                    continue
                if require_authenticated and not (peer.flags & ROOT_PEER_AUTHENTICATED):
                    break
                if require_dfu and not (peer.flags & ROOT_PEER_DFU_READY):
                    break
                if require_protected and not (peer.flags & ROOT_PEER_PROTECTED_READY):
                    break
                if expected_pattern is not None and peer.pattern_id != expected_pattern:
                    break
                return peer

            await self._disconnect_client()
            self._reset_session_state()

    async def upload_image(
        self,
        peer_id: int,
        image: bytes,
        *,
        chunk_size: int,
        downstream_chunk_limit: int = 0,
        activate_only: bool = False,
        permanent: bool = False,
    ) -> None:
        if downstream_chunk_limit > 0:
            chunk_size = min(chunk_size, downstream_chunk_limit)
        chunk_size = min(chunk_size, self.max_upload_chunk_size())
        if chunk_size <= 0:
            raise RuntimeError(
                f"upstream ATT MTU {self.client.mtu_size if self.client else 0} is too small for DFU relay"
            )
        print(
            f"Upstream MTU {self.client.mtu_size}, using DFU chunk size {chunk_size}"
            + (
                f" (leaf relay limit {downstream_chunk_limit})"
                if downstream_chunk_limit > 0
                else ""
            ),
            flush=True,
        )

        upload_sha = sha256(image)
        boot_hash = extract_mcuboot_boot_hash(image)
        if len(upload_sha) != ROOT_DFU_UPLOAD_HASH_LEN:
            raise ValueError(f"unexpected upload SHA length {len(upload_sha)}")
        if len(boot_hash) > ROOT_DFU_BOOT_HASH_MAX_LEN:
            raise ValueError(f"unexpected MCUboot boot hash length {len(boot_hash)}")

        transfer_size = 0 if activate_only else len(image)
        self.last_reported_progress = 0
        begin = (
            struct.pack("<BBBBI", peer_id, 0, len(boot_hash), 0, transfer_size)
            + upload_sha
            + boot_hash.ljust(ROOT_DFU_BOOT_HASH_MAX_LEN, b"\0")
        )
        debug_log(
            f"upload_image begin peer={peer_id} image_size={transfer_size} chunk_size={chunk_size} "
            f"boot_hash_len={len(boot_hash)}"
        )
        await self.send_secure(SAP_DEMO_MSG_ROOT_DFU_BEGIN, begin)
        await self._expect_progress(peer_id, 0, transfer_size)

        if activate_only:
            print(
                f"Skipping image upload for peer {peer_id}; requesting activation of the image already in secondary",
                flush=True,
            )
        else:
            offset = 0
            while offset < len(image):
                chunk = image[offset : offset + chunk_size]
                payload = struct.pack("<I", offset) + chunk
                await self.send_secure(SAP_DEMO_MSG_ROOT_DFU_CHUNK, payload)
                offset = await self._expect_progress(peer_id, offset + len(chunk), len(image))

        await asyncio.sleep(DFU_FINISH_SETTLE_DELAY)
        finish = struct.pack("<BB", peer_id, 1 if permanent else 0)
        await self.send_secure(SAP_DEMO_MSG_ROOT_DFU_FINISH, finish)
        result_payload = await self.wait_for_secure(
            SAP_DEMO_MSG_ROOT_DFU_RESULT,
            timeout=self.dfu_progress_timeout,
        )
        status, result_peer_id, selected_peer_id, _, detail = struct.unpack("<BBBBI", result_payload)
        if status != ROOT_STATUS_OK:
            raise RuntimeError(
                f"DFU failed: status={status} peer={result_peer_id} selected={selected_peer_id} detail={detail}"
            )
        print(f"DFU complete for peer {result_peer_id}, detail={detail}", flush=True)

    def max_upload_chunk_size(self) -> int:
        if self.client is None:
            return 0

        mtu = self.client.mtu_size
        # ATT write payload budget minus the SAP secure frame overhead and
        # the DFU chunk's 4-byte offset prefix.
        return mtu - ATT_WRITE_OVERHEAD - SAP_SECURE_HEADER_LEN - SAP_AEAD_TAG_LEN - 4

    async def request_response(self, request_type: int, payload: bytes, response_type: int) -> bytes:
        await self.send_secure(request_type, payload)
        return await self.wait_for_secure(response_type, timeout=self.timeout)

    async def send_secure(self, msg_type: int, payload: bytes) -> None:
        if self.client is None:
            raise RuntimeError("client not connected")
        frame = self._encrypt_secure(msg_type, payload)
        await self.client.write_gatt_char(SAP_SECURE_RX_UUID, frame, response=True)
        if self.waiting_for_confirm_tx and msg_type == SAP_MSG_CONFIRM:
            self.authenticated = True

    async def wait_for_secure(self, msg_type: int, *, timeout: float) -> bytes:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            for index, event in enumerate(self.secure_backlog):
                if event.msg_type == msg_type:
                    self.secure_backlog.pop(index)
                    return event.payload

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for secure msg 0x{msg_type:02x}")

            event = await asyncio.wait_for(self.secure_queue.get(), remaining)
            if event.msg_type == msg_type:
                return event.payload
            self.secure_backlog.append(event)

    async def _wait_for_auth_frame(self, timeout: float) -> bytes:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if self.auth_backlog:
                return self.auth_backlog.pop(0)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for auth frame")
            return await asyncio.wait_for(self.auth_queue.get(), remaining)

    async def _expect_progress(self, peer_id: int, minimum_offset: int, image_size: int) -> int:
        while True:
            event = await self.wait_for_secure_any(
                {SAP_DEMO_MSG_ROOT_DFU_PROGRESS, SAP_DEMO_MSG_ROOT_DFU_RESULT},
                timeout=self.dfu_progress_timeout,
            )
            if event.msg_type == SAP_DEMO_MSG_ROOT_DFU_RESULT:
                status, result_peer_id, _, _, detail = struct.unpack("<BBBBI", event.payload)
                raise RuntimeError(
                    f"DFU failed early: status={status} peer={result_peer_id} detail={detail}"
                )

            status, result_peer_id, _, _, accepted_offset, reported_size = struct.unpack(
                "<BBBBII", event.payload
            )
            if status != ROOT_STATUS_OK:
                raise RuntimeError(
                    f"DFU progress error: status={status} peer={result_peer_id} offset={accepted_offset}"
                )
            if result_peer_id != peer_id:
                continue
            if reported_size != image_size:
                raise RuntimeError(
                    f"unexpected image size in progress: {reported_size} != {image_size}"
                )
            if (
                accepted_offset == 0
                or accepted_offset == reported_size
                or (accepted_offset - self.last_reported_progress) >= PROGRESS_REPORT_STEP
            ):
                print(
                    f"DFU progress peer={peer_id} accepted={accepted_offset}/{reported_size}",
                    flush=True,
                )
                self.last_reported_progress = accepted_offset
            if accepted_offset < minimum_offset:
                continue
            return accepted_offset

    async def wait_for_secure_any(self, msg_types: Iterable[int], *, timeout: float) -> SecureEvent:
        wanted = set(msg_types)
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            for index, event in enumerate(self.secure_backlog):
                if event.msg_type in wanted:
                    self.secure_backlog.pop(index)
                    return event

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                wanted_str = ", ".join(f"0x{msg_type:02x}" for msg_type in sorted(wanted))
                raise TimeoutError(f"timed out waiting for secure msgs {wanted_str}")

            event = await asyncio.wait_for(self.secure_queue.get(), remaining)
            if event.msg_type in wanted:
                return event
            self.secure_backlog.append(event)

    async def _discover_root(self):
        if self.address is not None:
            device = await BleakScanner.find_device_by_address(
                self.address,
                timeout=self._scan_timeout(),
                **self._scanner_kwargs(),
            )
            if device is None:
                raise RuntimeError(f"no SAP root node found at {self.address}")

            print(f"Using root node {self.name or '<unnamed>'} [{device.address}]", flush=True)
            return device

        def matches_root(device, adv) -> bool:
            uuids = [uuid.lower() for uuid in (adv.service_uuids or [])]
            if SAP_SERVICE_UUID not in uuids:
                return False

            local_name = adv.local_name or device.name
            if self.name and local_name != self.name:
                return False

            return True

        start = time.monotonic()
        candidates: dict[str, tuple[float, int, object]] = {}

        def on_detect(device, adv) -> None:
            if not matches_root(device, adv):
                return
            now = time.monotonic()
            rssi = getattr(adv, "rssi", None)
            candidates[device.address] = (now, int(rssi) if rssi is not None else -999, device)

        scanner = BleakScanner(
            detection_callback=on_detect,
            **self._scanner_kwargs(),
        )
        await scanner.start()
        try:
            deadline = start + self._scan_timeout()
            first_fresh_seen: float | None = None
            while True:
                now = time.monotonic()
                fresh = [
                    entry for entry in candidates.values() if (entry[0] - start) >= 0.5
                ]
                if fresh:
                    if first_fresh_seen is None:
                        first_fresh_seen = now
                    elif (now - first_fresh_seen) >= 1.0:
                        break

                if now >= deadline:
                    break

                await asyncio.sleep(0.2)
        finally:
            await scanner.stop()

        fresh_candidates = [
            entry for entry in candidates.values() if (entry[0] - start) >= 0.5
        ]
        ranked = fresh_candidates or list(candidates.values())

        if ranked:
            ranked.sort(key=lambda item: (item[0], item[1], item[2].address), reverse=True)
            seen_at, rssi, device = ranked[0]
            debug_log(
                f"_discover_root picked {device.address} rssi={rssi} fresh={bool(fresh_candidates)} "
                f"from {len(ranked)} candidates"
            )
            print(
                f"Using root node {device.name or self.name or '<unnamed>'} [{device.address}]",
                flush=True,
            )
            return device

        raise RuntimeError("no SAP root node found")

    def _auth_notification(self, _char, data: bytearray) -> None:
        if self.loop is None:
            return
        self.loop.call_soon_threadsafe(self.auth_queue.put_nowait, bytes(data))

    def _secure_notification(self, _char, data: bytearray) -> None:
        try:
            msg_type, payload = self._decrypt_secure(bytes(data))
            if self.waiting_for_confirm_tx and not self.authenticated:
                self.authenticated = True
                self.waiting_for_confirm_tx = False
            event = SecureEvent(msg_type=msg_type, payload=payload)
            if self.loop is not None:
                self.loop.call_soon_threadsafe(self.secure_queue.put_nowait, event)
        except Exception as exc:
            print(f"secure frame decode failed: {exc}", file=sys.stderr)

    def _derive_session_keys(self) -> None:
        if self.root_cert is None or self.local_ecdh_private is None:
            raise RuntimeError("handshake state incomplete")

        remote_public = load_public_key_uncompressed(self.remote_ecdh_public)
        shared_secret = self.local_ecdh_private.exchange(ec.ECDH(), remote_public)
        transcript = (
            bytes([creds.HOST_ID, self.root_cert.device_id])
            + self.local_ecdh_public
            + self.remote_ecdh_public
        )
        transcript_hash = sha256(transcript)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.central_nonce + self.peripheral_nonce,
            info=b"SAP session" + transcript_hash,
        )
        material = hkdf.derive(shared_secret)
        self.aes_ccm = AESCCM(material, tag_length=16)
        self.tx_counter = 0
        self.rx_counter = 0
        self.session_key_ready = True

    def _encrypt_secure(self, msg_type: int, payload: bytes) -> bytes:
        if self.aes_ccm is None or not self.session_key_ready:
            raise RuntimeError("secure context not ready")
        nonce_base = os.urandom(SAP_AEAD_NONCE_BASE_LEN)
        header = struct.pack("<BB8sI", creds.SAP_VERSION, msg_type, nonce_base, self.tx_counter)
        nonce = build_nonce(nonce_base, self.tx_counter, msg_type)
        ciphertext = self.aes_ccm.encrypt(nonce, payload, header)
        self.tx_counter += 1
        return header + ciphertext

    def _decrypt_secure(self, frame: bytes) -> tuple[int, bytes]:
        if self.aes_ccm is None or not self.session_key_ready:
            raise RuntimeError("secure context not ready")
        if len(frame) < SAP_SECURE_HEADER_LEN + SAP_AEAD_TAG_LEN:
            raise ValueError("secure frame too short")
        version, msg_type, nonce_base, counter = struct.unpack(
            "<BB8sI", frame[:SAP_SECURE_HEADER_LEN]
        )
        if version != creds.SAP_VERSION:
            raise ValueError(f"unexpected secure frame version {version}")
        if counter != self.rx_counter:
            raise ValueError(f"unexpected secure counter {counter} != {self.rx_counter}")
        nonce = build_nonce(nonce_base, counter, msg_type)
        payload = self.aes_ccm.decrypt(nonce, frame[SAP_SECURE_HEADER_LEN:], frame[:SAP_SECURE_HEADER_LEN])
        self.rx_counter += 1
        return msg_type, payload


def format_peer_flags(flags: int) -> str:
    names: list[str] = []
    if flags & ROOT_PEER_AUTHENTICATED:
        names.append("auth")
    if flags & ROOT_PEER_PROTECTED_READY:
        names.append("protected")
    if flags & ROOT_PEER_DFU_READY:
        names.append("dfu")
    if flags & ROOT_PEER_SELECTED:
        names.append("selected")
    if flags & ROOT_PEER_LED_ASSIGNED:
        names.append("led")
    return ",".join(names) if names else "-"


def print_status(payload: bytes) -> None:
    status = parse_status(payload)
    print(f"selected_peer_id={status.selected_peer_id}", flush=True)
    for peer in status.peers:
        print(
            f"peer_id={peer.peer_id} state={peer.state} flags={format_peer_flags(peer.flags)} "
            f"led_index={peer.led_index} pattern_id={peer.pattern_id} "
            f"dfu_chunk_limit={peer.dfu_chunk_limit}",
            flush=True,
        )


def parse_status(payload: bytes) -> RootStatus:
    if len(payload) < 2:
        raise ValueError("status payload too short")
    selected_peer_id, peer_count = struct.unpack_from("<BB", payload, 0)
    record_len = 7
    if len(payload) != 2 + (peer_count * record_len):
        raise ValueError(
            f"status payload length {len(payload)} does not match peer_count {peer_count}"
        )
    peers: list[RootPeerStatus] = []
    for index in range(peer_count):
        offset = 2 + (index * record_len)
        peer_id, state, flags, led_index, pattern_id, dfu_chunk_limit = struct.unpack_from(
            "<BBBBBH", payload, offset
        )
        peers.append(
            RootPeerStatus(
                peer_id=peer_id,
                state=state,
                flags=flags,
                led_index=led_index,
                pattern_id=pattern_id,
                dfu_chunk_limit=dfu_chunk_limit,
            )
        )
    return RootStatus(selected_peer_id=selected_peer_id, peers=tuple(peers))


async def cmd_status(args: argparse.Namespace) -> None:
    async with SapRootClient(
        address=args.address,
        name=args.name,
        timeout=args.timeout,
        dfu_progress_timeout=args.dfu_progress_timeout,
        adapter=args.adapter,
        use_linux_agent=args.linux_agent,
        pre_pair=args.pre_pair,
    ) as client:
        payload = await client.request_status()
        print_status(payload)


async def cmd_select(args: argparse.Namespace) -> None:
    async with SapRootClient(
        address=args.address,
        name=args.name,
        timeout=args.timeout,
        dfu_progress_timeout=args.dfu_progress_timeout,
        adapter=args.adapter,
        use_linux_agent=args.linux_agent,
        pre_pair=args.pre_pair,
    ) as client:
        payload = await client.select_leaf(args.peer_id)
        status, selected_peer_id = struct.unpack("<BB", payload)
        print(f"select_status={status} selected_peer_id={selected_peer_id}", flush=True)


async def cmd_upload(args: argparse.Namespace) -> None:
    loaded_image = load_upload_image(args.image)
    image = loaded_image.data
    print(f"Using DFU image {loaded_image.source}", flush=True)
    async with SapRootClient(
        address=args.address,
        name=args.name,
        timeout=args.timeout,
        dfu_progress_timeout=args.dfu_progress_timeout,
        adapter=args.adapter,
        use_linux_agent=args.linux_agent,
        pre_pair=args.pre_pair,
    ) as client:
        prepare_timeout = max(args.timeout, UPLOAD_PREPARE_TIMEOUT)
        deadline = asyncio.get_running_loop().time() + prepare_timeout

        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"timed out preparing peer {args.peer_id} for DFU")

            debug_log(f"cmd_upload waiting for peer {args.peer_id}; remaining={remaining:.1f}s")
            peer = await client.wait_for_peer_status(
                args.peer_id,
                timeout=remaining,
                expected_pattern=None,
            )
            debug_log(
                f"cmd_upload peer {peer.peer_id} ready state={peer.state} "
                f"flags={format_peer_flags(peer.flags)} pattern={peer.pattern_id} "
                f"chunk_limit={peer.dfu_chunk_limit}"
            )

            select_rsp = await client.select_leaf(args.peer_id)
            status, selected_peer_id = struct.unpack("<BB", select_rsp)
            debug_log(
                f"cmd_upload select response peer={args.peer_id} status={status} selected={selected_peer_id}"
            )
            if status == ROOT_STATUS_OK and selected_peer_id == args.peer_id:
                break

            if status not in (ROOT_STATUS_NO_PEER, ROOT_STATUS_BUSY, ROOT_STATUS_BAD_STATE):
                raise RuntimeError(
                    f"failed to select peer {args.peer_id}: status={status} selected={selected_peer_id}"
                )

            print(
                f"Leaf {args.peer_id} not ready for selection yet "
                f"(status={status} selected={selected_peer_id}); retrying",
                flush=True,
            )
            await asyncio.sleep(min(1.0, remaining))

        await client.upload_image(
            args.peer_id,
            image,
            chunk_size=args.chunk_size,
            downstream_chunk_limit=peer.dfu_chunk_limit,
            activate_only=args.activate_only,
            permanent=args.permanent,
        )
        if args.wait_reconnect:
            peer = await client.wait_for_peer_status_via_reconnect(
                args.peer_id,
                timeout=args.reconnect_timeout,
                expected_pattern=args.expect_pattern,
            )
            print(
                f"Leaf {peer.peer_id} reconnected with flags={format_peer_flags(peer.flags)} "
                f"led_index={peer.led_index} pattern_id={peer.pattern_id} "
                f"dfu_chunk_limit={peer.dfu_chunk_limit}",
                flush=True,
            )


async def cmd_discover(args: argparse.Namespace) -> None:
    devices = await BleakScanner.discover(
        timeout=args.timeout,
        return_adv=True,
        **({"adapter": args.adapter} if args.adapter else {}),
    )
    found = False
    for _, (device, adv) in devices.items():
        uuids = [uuid.lower() for uuid in (adv.service_uuids or [])]
        if SAP_SERVICE_UUID not in uuids:
            continue
        local_name = adv.local_name or device.name or "<unnamed>"
        if args.name and local_name != args.name:
            continue
        found = True
        print(f"{device.address} name={local_name}", flush=True)
    if not found:
        print("No SAP roots found", flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate to a SAP root node over BLE and drive the upstream demo path."
    )
    parser.add_argument("--address", help="BLE address of the root node")
    parser.add_argument("--name", help="expected BLE device name", default=f"SAP-C-{creds.ROOT_ID}")
    parser.add_argument("--timeout", type=float, default=10.0, help="BLE operation timeout in seconds")
    parser.add_argument(
        "--dfu-progress-timeout",
        type=float,
        default=60.0,
        help="time to wait for each relayed DFU progress/result event in seconds",
    )
    parser.add_argument("--adapter", help="Bleak adapter/backend hint when supported")
    parser.add_argument(
        "--linux-agent",
        dest="linux_agent",
        action="store_true",
        default=sys.platform.startswith("linux"),
        help="start a temporary bluetoothctl NoInputNoOutput agent on Linux",
    )
    parser.add_argument(
        "--no-linux-agent",
        dest="linux_agent",
        action="store_false",
        help="disable the temporary bluetoothctl pairing agent",
    )
    parser.add_argument(
        "--pre-pair",
        action="store_true",
        help="pair the host to the root with bluetoothctl before connecting",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="scan for SAP root nodes")
    discover.set_defaults(func=cmd_discover)

    status = subparsers.add_parser("status", help="connect, authenticate, and print root leaf status")
    status.set_defaults(func=cmd_status)

    select = subparsers.add_parser("select", help="select the target leaf for DFU")
    select.add_argument("peer_id", type=int, help="leaf device id")
    select.set_defaults(func=cmd_select)

    upload = subparsers.add_parser("upload", help="relay a signed image through the root into a leaf")
    upload.add_argument("peer_id", type=int, help="leaf device id")
    upload.add_argument(
        "image",
        help="path to a signed image binary or a dfu_application.zip package",
    )
    upload.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="SAP payload chunk size")
    upload.add_argument(
        "--activate-only",
        action="store_true",
        help="skip chunk upload and only activate the provided image if it is already present in secondary",
    )
    upload.add_argument(
        "--temporary",
        dest="permanent",
        action="store_false",
        help="request a test/pending boot instead of a permanent activation",
    )
    upload.add_argument(
        "--permanent",
        dest="permanent",
        action="store_true",
        help="request a permanent activation instead of the default test boot",
    )
    upload.add_argument(
        "--expect-pattern",
        type=int,
        help="wait until the selected leaf reports this pattern_id after reboot",
    )
    upload.add_argument(
        "--no-wait-reconnect",
        dest="wait_reconnect",
        action="store_false",
        help="return as soon as the root reports DFU completion instead of waiting for the leaf to reconnect",
    )
    upload.add_argument(
        "--reconnect-timeout",
        type=float,
        default=90.0,
        help="time to wait for the leaf to reconnect and report status after DFU",
    )
    upload.set_defaults(permanent=False)
    upload.set_defaults(wait_reconnect=True)
    upload.set_defaults(func=cmd_upload)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if DEBUG:
            traceback.print_exc()
        print(f"error: {exc!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
