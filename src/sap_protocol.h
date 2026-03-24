/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_PROTOCOL_H__
#define SAP_PROTOCOL_H__

#include <zephyr/types.h>
#include <zephyr/bluetooth/uuid.h>

#define SAP_VERSION 1U

#define SAP_NONCE_LEN 16U
#define SAP_IDENTITY_PRIVATE_KEY_LEN 32U
#define SAP_IDENTITY_PUBLIC_KEY_LEN 65U
#define SAP_IDENTITY_SIGNATURE_LEN 64U
#define SAP_ECDH_PUBLIC_KEY_LEN 65U
#define SAP_AEAD_KEY_LEN 16U
#define SAP_AEAD_NONCE_BASE_LEN 8U
#define SAP_AEAD_NONCE_LEN 13U
#define SAP_AEAD_TAG_LEN 16U
#define SAP_SECURE_HEADER_LEN 6U

#define SAP_ROLE_MASK_CENTRAL BIT(0)
#define SAP_ROLE_MASK_PERIPHERAL BIT(1)

#define SAP_CONFIRM_TEXT "SAP-OK"
#define SAP_CONFIRM_TEXT_LEN 6U

#define BT_UUID_SAP_SERVICE_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a001)
#define BT_UUID_SAP_AUTH_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a002)
#define BT_UUID_SAP_SECURE_TX_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a003)
#define BT_UUID_SAP_SECURE_RX_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a004)
#define BT_UUID_SAP_PROTECTED_SERVICE_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a101)
#define BT_UUID_SAP_PROTECTED_STATUS_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a102)

#define BT_UUID_SAP_SERVICE BT_UUID_DECLARE_128(BT_UUID_SAP_SERVICE_VAL)
#define BT_UUID_SAP_AUTH BT_UUID_DECLARE_128(BT_UUID_SAP_AUTH_VAL)
#define BT_UUID_SAP_SECURE_TX BT_UUID_DECLARE_128(BT_UUID_SAP_SECURE_TX_VAL)
#define BT_UUID_SAP_SECURE_RX BT_UUID_DECLARE_128(BT_UUID_SAP_SECURE_RX_VAL)
#define BT_UUID_SAP_PROTECTED_SERVICE BT_UUID_DECLARE_128(BT_UUID_SAP_PROTECTED_SERVICE_VAL)
#define BT_UUID_SAP_PROTECTED_STATUS BT_UUID_DECLARE_128(BT_UUID_SAP_PROTECTED_STATUS_VAL)

enum sap_role {
	SAP_ROLE_CENTRAL = 1,
	SAP_ROLE_PERIPHERAL = 2,
};

enum sap_message_type {
	SAP_MSG_HELLO = 1,
	SAP_MSG_PERIPHERAL_CHALLENGE = 2,
	SAP_MSG_CENTRAL_AUTH = 3,
	SAP_MSG_PERIPHERAL_AUTH = 4,
	SAP_MSG_CONFIRM = 5,
	SAP_MSG_CONFIRM_ACK = 6,
	SAP_MSG_SECURE_DATA = 7,
	SAP_MSG_SECURE_ACK = 8,
	SAP_MSG_BUTTON_STATE = 9,
};

enum sap_signature_purpose {
	SAP_SIG_PERIPHERAL_CHALLENGE = 0xA1,
	SAP_SIG_CENTRAL_AUTH = 0xA2,
	SAP_SIG_PERIPHERAL_AUTH = 0xA3,
};

struct sap_cert_body {
	uint8_t version;
	uint8_t role_mask;
	uint8_t device_id;
	uint8_t group_id;
	uint8_t public_key[SAP_IDENTITY_PUBLIC_KEY_LEN];
} __packed;

struct sap_certificate {
	struct sap_cert_body body;
	uint8_t ca_signature[SAP_IDENTITY_SIGNATURE_LEN];
} __packed;

struct sap_msg_hello {
	uint8_t version;
	uint8_t type;
	uint8_t central_nonce[SAP_NONCE_LEN];
} __packed;

struct sap_msg_peripheral_challenge {
	uint8_t version;
	uint8_t type;
	struct sap_certificate cert;
	uint8_t peripheral_nonce[SAP_NONCE_LEN];
	uint8_t signature[SAP_IDENTITY_SIGNATURE_LEN];
} __packed;

struct sap_msg_central_auth {
	uint8_t version;
	uint8_t type;
	struct sap_certificate cert;
	uint8_t ecdh_public_key[SAP_ECDH_PUBLIC_KEY_LEN];
	uint8_t signature[SAP_IDENTITY_SIGNATURE_LEN];
} __packed;

struct sap_msg_peripheral_auth {
	uint8_t version;
	uint8_t type;
	uint8_t ecdh_public_key[SAP_ECDH_PUBLIC_KEY_LEN];
	uint8_t signature[SAP_IDENTITY_SIGNATURE_LEN];
} __packed;

struct sap_secure_header {
	uint8_t version;
	uint8_t type;
	uint32_t counter_le;
} __packed;

#endif /* SAP_PROTOCOL_H__ */
