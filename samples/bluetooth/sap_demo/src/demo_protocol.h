/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_DEMO_PROTOCOL_H__
#define SAP_DEMO_PROTOCOL_H__

#include <zephyr/sys/util.h>

#include <sap/sap_protocol.h>

#define BT_UUID_SAP_DEMO_PROTECTED_SERVICE_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a101)
#define BT_UUID_SAP_DEMO_PROTECTED_STATUS_VAL \
	BT_UUID_128_ENCODE(0x7a18e2d1, 0x3bd2, 0x4f31, 0x8c4b, 0xb6c5b8f7a102)

#define BT_UUID_SAP_DEMO_PROTECTED_SERVICE \
	BT_UUID_DECLARE_128(BT_UUID_SAP_DEMO_PROTECTED_SERVICE_VAL)
#define BT_UUID_SAP_DEMO_PROTECTED_STATUS \
	BT_UUID_DECLARE_128(BT_UUID_SAP_DEMO_PROTECTED_STATUS_VAL)

enum sap_demo_message_type {
	SAP_DEMO_MSG_TEXT = SAP_APP_MSG_TYPE_MIN,
	SAP_DEMO_MSG_BUTTON_STATE,
	SAP_DEMO_MSG_ROOT_STATUS_REQ,
	SAP_DEMO_MSG_ROOT_STATUS_RSP,
	SAP_DEMO_MSG_ROOT_SELECT_LEAF,
	SAP_DEMO_MSG_ROOT_SELECT_RSP,
	SAP_DEMO_MSG_ROOT_DFU_BEGIN,
	SAP_DEMO_MSG_ROOT_DFU_CHUNK,
	SAP_DEMO_MSG_ROOT_DFU_PROGRESS,
	SAP_DEMO_MSG_ROOT_DFU_FINISH,
	SAP_DEMO_MSG_ROOT_DFU_RESULT,
	SAP_DEMO_MSG_DFU_APPLY,
};

enum sap_demo_root_peer_flags {
	SAP_DEMO_ROOT_PEER_AUTHENTICATED = BIT(0),
	SAP_DEMO_ROOT_PEER_PROTECTED_READY = BIT(1),
	SAP_DEMO_ROOT_PEER_DFU_READY = BIT(2),
	SAP_DEMO_ROOT_PEER_SELECTED = BIT(3),
	SAP_DEMO_ROOT_PEER_LED_ASSIGNED = BIT(4),
};

enum sap_demo_root_status_code {
	SAP_DEMO_ROOT_STATUS_OK = 0,
	SAP_DEMO_ROOT_STATUS_INVALID = 1,
	SAP_DEMO_ROOT_STATUS_NO_PEER = 2,
	SAP_DEMO_ROOT_STATUS_BUSY = 3,
	SAP_DEMO_ROOT_STATUS_BAD_STATE = 4,
	SAP_DEMO_ROOT_STATUS_DFU_ERROR = 5,
};

struct sap_demo_root_status_record {
	uint8_t peer_id;
	uint8_t state;
	uint8_t flags;
	uint8_t led_index;
	uint8_t pattern_id;
	uint16_t dfu_chunk_limit_le;
} __packed;

struct sap_demo_root_status_response {
	uint8_t selected_peer_id;
	uint8_t peer_count;
	struct sap_demo_root_status_record records[];
} __packed;

struct sap_demo_root_select_leaf {
	uint8_t peer_id;
} __packed;

struct sap_demo_root_select_response {
	uint8_t status;
	uint8_t selected_peer_id;
} __packed;

struct sap_demo_root_dfu_begin {
	uint8_t peer_id;
	uint8_t image_num;
	uint8_t boot_hash_len;
	uint8_t reserved;
	uint32_t image_size_le;
	uint8_t upload_sha256[32];
	uint8_t boot_hash[64];
} __packed;

struct sap_demo_root_dfu_chunk {
	uint32_t offset_le;
	uint8_t data[];
} __packed;

struct sap_demo_root_dfu_progress {
	uint8_t status;
	uint8_t peer_id;
	uint8_t reserved0;
	uint8_t reserved1;
	uint32_t accepted_offset_le;
	uint32_t image_size_le;
} __packed;

struct sap_demo_root_dfu_finish {
	uint8_t peer_id;
	uint8_t permanent;
} __packed;

struct sap_demo_root_dfu_result {
	uint8_t status;
	uint8_t peer_id;
	uint8_t selected_peer_id;
	uint8_t reserved;
	uint32_t detail_le;
} __packed;

#endif /* SAP_DEMO_PROTOCOL_H__ */
